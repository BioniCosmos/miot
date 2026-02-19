use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Context;
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;

use crate::{cloud::session::Session, device::Device};

mod session;

pub struct Cloud {
    session: Session,
}

impl Cloud {
    pub fn new() -> Self {
        Self {
            session: Session::new(),
        }
    }

    pub async fn login(&mut self) -> anyhow::Result<()> {
        self.session.login().await
    }

    pub async fn get_devices(&self) -> anyhow::Result<Vec<Device>> {
        #[derive(Deserialize)]
        struct Response {
            list: Vec<DeviceInfo>,
        }

        #[derive(Deserialize)]
        struct DeviceInfo {
            did: String,
            localip: String,
            name: String,
            token: String,
        }

        self.session
            .request::<Response>(
                Method::GET,
                "/app/v2/home/device_list_page",
                &json!({"limit": 200, "get_split_device": true, "get_third_device": true}),
            )
            .await?
            .list
            .into_iter()
            .map(
                |DeviceInfo {
                     did,
                     localip,
                     name,
                     token,
                 }| {
                    let address = Ipv4Addr::from_str(&localip)?;
                    let token = *hex::decode(token)?.as_array().context("invalid token")?;
                    Ok(Device {
                        id: did,
                        name,
                        address,
                        token,
                    })
                },
            )
            .collect()
    }
}
