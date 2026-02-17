use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub address: Ipv4Addr,
    pub token: [u8; 16],
}

pub trait InitSubscriber {
    fn handle(&self, device: &Device);
}
