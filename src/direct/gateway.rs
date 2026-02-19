use std::{
    cell::{Cell, OnceCell},
    collections::HashMap,
    error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    net::{Ipv4Addr, UdpSocket},
    num::ParseIntError,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU32, Ordering},
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use aes::{
    Aes128,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7},
};
use md5::{Digest, Md5};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use crate::{
    device::{Device, InitSubscriber},
    utils::{BinaryToInt, BinaryToIntN},
};

pub struct Gateway {
    worker: Worker,
    response_senders: Arc<Mutex<HashMap<RequestId, Sender<io::Result<RawResponse>>>>>,
    message_id: AtomicU32,
    cipher_caches: Arc<RwLock<HashMap<String, CipherCache>>>,
}

pub enum Request {
    Ping {
        manager_id: String,
    },
    Message {
        timestamp: u32,
        method: String,
        params: Value,
    },
}

pub enum Response<T> {
    Ping { timestamp: u32 },
    Message(T),
}

pub trait DeviceQuerier: Send + Sync {
    fn query(&self, id: &str) -> Device;
}

struct Worker {
    handler: OnceCell<JoinHandle<()>>,
    store: Cell<Option<WorkerStore>>,
    sender: Option<Sender<SendParams>>,
}

struct WorkerStore {
    socket: UdpSocket,
    receiver: Receiver<SendParams>,
    device_querier: Arc<dyn DeviceQuerier>,
}

struct SendParams {
    id: RequestId,
    addr: Ipv4Addr,
    packet: Box<[u8]>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum RequestId {
    Ping(String),
    Message(u32),
}

enum RawResponse {
    Ping(Box<[u8]>),
    Message(Value),
}

struct CipherCache {
    key: [u8; 16],
    iv: [u8; 16],
}

const PREFIX: [u8; 2] = [0x21, 0x31];

impl Gateway {
    pub fn try_new(device_querier: Arc<dyn DeviceQuerier>) -> Result<Self, Error> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(Error::Init)?;
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("unexpected error on UdpSocket::set_read_timeout");

        let (sender, receiver) = mpsc::channel();

        Ok(Self {
            worker: Worker {
                handler: OnceCell::new(),
                store: Cell::new(Some(WorkerStore {
                    socket,
                    receiver,
                    device_querier,
                })),
                sender: Some(sender),
            },
            response_senders: Arc::new(Mutex::new(HashMap::new())),
            message_id: AtomicU32::new(1),
            cipher_caches: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn start(&self) -> Result<(), Error> {
        let handler = &self.worker.handler;
        if handler.get().is_some() {
            return Err(Error::ReceiverAlreadyStarted);
        }

        let WorkerStore {
            socket,
            receiver,
            device_querier,
        } = self
            .worker
            .store
            .take()
            .expect("unexpected worker store state");
        let response_senders = Arc::clone(&self.response_senders);
        let cipher_caches = Arc::clone(&self.cipher_caches);

        handler
            .set(thread::spawn(move || {
                let mut buf = [0; 32 * 1024];
                loop {
                    match receiver.try_recv() {
                        Ok(params) => {
                            if let Err(e) = socket.send_to(&params.packet, (params.addr, 54321))
                                && let Err(error) = response_senders
                                    .lock()
                                    .unwrap()
                                    .remove(&params.id)
                                    .expect("unexpected missing response sender")
                                    .send(Err(e))
                            {
                                debug!(?error, "receiver dropped before send error delivered");
                            }
                        }
                        Err(TryRecvError::Empty) => (),
                        Err(TryRecvError::Disconnected) => {
                            info!("channel closed, shutting down the worker");
                            return;
                        }
                    }

                    let buf = match socket.recv_from(&mut buf) {
                        Ok((len, _)) => &mut buf[..len],
                        Err(e)
                            if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                        {
                            continue;
                        }
                        Err(error) => {
                            error!(?error, "failed to receive the message");
                            continue;
                        }
                    };
                    if buf.len() < 32 || buf[..2] != PREFIX {
                        debug!("invalid packet header");
                        continue;
                    }

                    let device_id = buf.to_u64::<4>().to_string();

                    if buf.len() == 32 {
                        match response_senders
                            .lock()
                            .unwrap()
                            .remove(&RequestId::Ping(device_id))
                        {
                            Some(sender) => {
                                if let Err(error) =
                                    sender.send(Ok(RawResponse::Ping(Box::from(buf))))
                                {
                                    debug!(
                                        ?error,
                                        "receiver dropped before ping response delivered"
                                    );
                                }
                            }
                            None => debug!("no pending ping request, ignoring"),
                        }
                        continue;
                    }

                    let original_hash = *buf[16..32].as_array::<16>().unwrap();
                    let calculated_hash = {
                        let device = device_querier.query(&device_id);
                        buf[16..32].copy_from_slice(&device.token);
                        Md5::digest(&buf)
                    };
                    if calculated_hash.as_slice() != original_hash {
                        warn!(device_id, "integrity check failed");
                        continue;
                    }

                    let message = {
                        let cipher_caches = cipher_caches.read().unwrap();
                        let Some(CipherCache { key, iv }) = cipher_caches.get(&device_id) else {
                            warn!(device_id, "device uninitialized");
                            continue;
                        };
                        let message = match cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                            .expect("unexpected invalid cipher params")
                            .decrypt_padded_vec_mut::<Pkcs7>(&buf[32..])
                        {
                            Ok(message) => message,
                            Err(error) => {
                                warn!(device_id, ?error, "decryption failed");
                                continue;
                            }
                        };
                        match serde_json::from_slice::<Value>(&message) {
                            Ok(message) => message,
                            Err(error) => {
                                warn!(device_id, ?error, "invalid JSON payload");
                                continue;
                            }
                        }
                    };

                    let Some(id) = message
                        .get("id")
                        .and_then(|id| id.as_u64())
                        .map(|id| id as u32)
                    else {
                        warn!(device_id, "failed to parse the message id");
                        continue;
                    };
                    match response_senders
                        .lock()
                        .unwrap()
                        .remove(&RequestId::Message(id))
                    {
                        Some(sender) => {
                            if let Err(error) = sender.send(Ok(RawResponse::Message(message))) {
                                debug!(
                                    device_id,
                                    id,
                                    ?error,
                                    "receiver dropped before response delivered"
                                );
                            }
                        }
                        None => debug!(device_id, id, "no pending request, ignoring"),
                    }
                }
            }))
            .expect("unexpected worker handler state");
        Ok(())
    }

    pub fn send<T: DeserializeOwned>(
        &self,
        device: &Device,
        request: Request,
    ) -> Result<Response<T>, Error> {
        let id = match &request {
            Request::Ping { .. } => RequestId::Ping(device.id.clone()),
            Request::Message { .. } => RequestId::Message(
                self.message_id
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
                        Some(if x < u32::MAX { x + 1 } else { 1 })
                    })
                    .unwrap(),
            ),
        };

        let packet = match &request {
            Request::Ping { manager_id } => {
                let mut packet = [0; 32];
                packet[0..2].copy_from_slice(&PREFIX);
                packet[2..4].copy_from_slice(&32u16.to_be_bytes());
                packet[4..16].copy_from_slice(&[0xff; 12]);
                packet[16..20].copy_from_slice(b"MDID");
                packet[20..28].copy_from_slice(
                    &manager_id
                        .parse::<u64>()
                        .map_err(Error::Parse)?
                        .to_be_bytes(),
                );
                Box::from(packet)
            }
            Request::Message {
                timestamp,
                method,
                params,
            } => {
                let RequestId::Message(id) = id else {
                    unreachable!()
                };
                let payload =
                    serde_json::to_vec(&json!({ "id": id, "method": method, "params": params }))
                        .map_err(Error::Serialize)?;

                let cipher_caches = self.cipher_caches.read().unwrap();
                let CipherCache { key, iv } = cipher_caches
                    .get(&device.id)
                    .ok_or(Error::DeviceUninitialized)?;
                let mut payload = cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
                    .expect("unexpected invalid cipher params")
                    .encrypt_padded_vec_mut::<Pkcs7>(&payload);

                let len = 32 + payload.len();
                let mut packet = Vec::with_capacity(len);
                packet.resize(32, 0);
                packet[0..2].copy_from_slice(&PREFIX);
                packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                packet[4..12].copy_from_slice(
                    &device
                        .id
                        .parse::<u64>()
                        .map_err(Error::Parse)?
                        .to_be_bytes(),
                );
                packet[12..16].copy_from_slice(&timestamp.to_be_bytes());
                packet[16..32].copy_from_slice(&device.token);
                packet.append(&mut payload);

                let packet_hash = Md5::digest(&packet);
                packet[16..32].copy_from_slice(&packet_hash);

                packet.into_boxed_slice()
            }
        };

        let (tx, rx) = mpsc::channel();
        self.response_senders.lock().unwrap().insert(id.clone(), tx);
        self.worker
            .sender
            .as_ref()
            .ok_or(Error::ShuttingDown)?
            .send(SendParams {
                id,
                addr: device.address,
                packet,
            })
            .expect("unexpected channel closed");

        match rx
            .recv()
            .expect("unexpected channel closed")
            .map_err(Error::Send)?
        {
            RawResponse::Ping(raw) => Ok(Response::Ping {
                timestamp: raw.to_int::<12, 16>(),
            }),
            RawResponse::Message(message) => serde_json::from_value(message)
                .map(Response::Message)
                .map_err(Error::Deserialize),
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.worker.sender.take();
        if let Some(handler) = self.worker.handler.take() {
            handler.join().unwrap();
        }
    }
}

impl InitSubscriber for Gateway {
    fn handle(&self, device: &Device) {
        let mut cipher_caches = self.cipher_caches.write().unwrap();
        let key = Md5::digest(&device.token);
        let iv = Md5::new()
            .chain_update(&key)
            .chain_update(&device.token)
            .finalize();
        cipher_caches.insert(
            device.id.clone(),
            CipherCache {
                key: <[u8; 16]>::from(key),
                iv: <[u8; 16]>::from(iv),
            },
        );
    }
}

#[derive(Debug)]
pub enum Error {
    Init(std::io::Error),
    Parse(ParseIntError),
    Serialize(serde_json::Error),
    Deserialize(serde_json::Error),
    Send(io::Error),
    ReceiverAlreadyStarted,
    DeviceUninitialized,
    ShuttingDown,
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Init(e) => Some(e),
            Error::Parse(e) => Some(e),
            Error::Serialize(e) => Some(e),
            Error::Deserialize(e) => Some(e),
            Error::Send(e) => Some(e),
            Error::ReceiverAlreadyStarted | Error::DeviceUninitialized | Error::ShuttingDown => {
                None
            }
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Init(_) => write!(f, "failed to initialize"),
            Error::Parse(_) => write!(f, "failed to parse id"),
            Error::Serialize(_) => write!(f, "failed to serialize"),
            Error::Deserialize(_) => write!(f, "failed to deserialize"),
            Error::Send(_) => write!(f, "failed to send"),
            Error::ReceiverAlreadyStarted => write!(f, "receiver already started"),
            Error::DeviceUninitialized => write!(f, "device uninitialized"),
            Error::ShuttingDown => write!(f, "gateway is shutting down"),
        }
    }
}
