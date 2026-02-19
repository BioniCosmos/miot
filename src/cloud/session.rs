use std::{
    io::{BufRead, BufReader, Write},
    net::{Ipv6Addr, TcpListener},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Error, ensure};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use reqwest::{
    Client, Method, Url,
    header::{self},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tracing::trace;

pub(super) struct Session {
    client: Client,
    base_url: Url,
    credentials: Option<Credentials>,
}

// TODO: remove the hint after implementing the refresh mechanism
#[allow(unused)]
struct Credentials {
    access_token: String,
    refresh_token: String,
    expires_at: SystemTime,
}

#[derive(Deserialize)]
struct Response {
    code: i32,
    message: String,
    result: Value,
}

impl Session {
    const CLIENT_ID: &str = "2882303761520251711";
    const REDIRECT_URL: &str = "http://homeassistant.local:8123";

    pub(super) fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: Url::parse("https://ha.api.io.mi.com").expect("unexpected invalid base URL"),
            credentials: None,
        }
    }

    pub(super) async fn login(&mut self) -> anyhow::Result<()> {
        let code = self.get_auth_code()?;
        self.credentials = Some(self.get_token(&code).await?);
        Ok(())
    }

    fn get_auth_code(&self) -> anyhow::Result<String> {
        let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 8123))?;

        let mdns = ServiceDaemon::new()?;
        mdns.register(ServiceInfo::new(
            "_http._tcp.local.",
            "home-assistant",
            "homeassistant.local.",
            "127.0.0.1,::1",
            8123,
            None,
        )?)?;

        let mut sign_in_url = Url::parse("https://account.xiaomi.com/oauth2/authorize")?;
        sign_in_url.query_pairs_mut().extend_pairs([
            ("redirect_uri", Self::REDIRECT_URL),
            ("client_id", Self::CLIENT_ID),
            ("response_type", "code"),
            ("skip_confirm", "true"),
        ]);
        println!("Sign in to your Xiaomi account:\n{sign_in_url}");

        let (mut stream, _) = listener.accept()?;

        let mut buf = BufReader::new(&stream);

        let mut request_line = String::new();
        buf.read_line(&mut request_line)?;
        trace!(request_line, "receiving OAuth2 redirect request");

        for line in buf.lines() {
            if line?.is_empty() {
                break;
            }
        }

        let body = r#"
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>MIoT</title>
  </head>
  <body>
    <p>Sign in successful. You may close this tab.</p>
  </body>
</html>
    "#
        .trim();
        write!(stream, "HTTP/1.1 200 OK\r\n")?;
        write!(stream, "Content-Type: text/html; charset=utf-8\r\n")?;
        write!(stream, "Content-Length: {}\r\n", body.len())?;
        write!(stream, "\r\n")?;
        stream.write_all(body.as_bytes())?;

        let temp_url = Url::parse("http://localhost")?.join(
            request_line
                .split_ascii_whitespace()
                .nth(1)
                .context("could not find the authorization code")?,
        )?;
        trace!(?temp_url, "parsing the request line");
        temp_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .context("could not find the authorization code")
    }

    async fn get_token(&self, code: &str) -> anyhow::Result<Credentials> {
        let response = self
            .client
            .post(
                self.base_url
                    .join("/app/v2/ha/oauth/get_token")
                    .expect("unexpected joining path to base URL error"),
            )
            .form(&[(
                "data",
                json!({
                    "client_id": Self::CLIENT_ID,
                    "redirect_uri": Self::REDIRECT_URL,
                    "code": code
                })
                .to_string(),
            )])
            .send()
            .await?
            .json::<Response>()
            .await?;
        ensure!(
            response.code == 0,
            response
                .result
                .get("error_description")
                .and_then(|result| result.as_str())
                .context("failed to parse the error message")?
                .to_owned()
        );

        #[derive(Deserialize)]
        struct SuccessResult {
            access_token: String,
            refresh_token: String,
            expires_in: u64,
        }

        serde_json::from_value(response.result)
            .map(
                |SuccessResult {
                     access_token,
                     refresh_token,
                     expires_in,
                 }| Credentials {
                    access_token,
                    refresh_token,
                    expires_at: SystemTime::now() + Duration::from_secs(expires_in),
                },
            )
            .map_err(Error::from)
    }

    pub(super) async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        params: &(impl Serialize + ?Sized),
    ) -> anyhow::Result<T> {
        let mut url = self.base_url.clone();
        url.set_path(path);

        let res = self
            .client
            .request(method, url)
            .header(
                header::AUTHORIZATION,
                format!(
                    "Bearer{}",
                    self.credentials
                        .as_ref()
                        .context("session uninitialized")?
                        .access_token
                ),
            )
            .header("X-Client-AppId", Self::CLIENT_ID)
            .header("X-Client-BizId", "haapi")
            .json(params)
            .send()
            .await?
            .json::<Response>()
            .await?;
        ensure!(res.code == 0, res.message);
        serde_json::from_value(res.result).map_err(Error::from)
    }
}
