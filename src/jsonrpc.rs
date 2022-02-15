use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::json;

pub use reqwest;

const JSON_RPC_VERSION: &str = "2.0";

pub type Result<T> = std::result::Result<T, reqwest::Error>;

pub struct RpcClient {
    client: reqwest::blocking::Client,
    host: String,
}

impl RpcClient {
    pub fn new(host: String) -> Self {
        let client =
            tokio::task::block_in_place(move || reqwest::blocking::Client::builder().build())
                .expect("build client");

        Self { client, host }
    }

    pub fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let request_json = json!({
           "jsonrpc": JSON_RPC_VERSION,
           "id": 1,
           "method": method.to_string(),
           "params": params,
        })
        .to_string();

        let response = tokio::task::block_in_place(move || {
            self.client
                .post(&self.host)
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json")
                .body(request_json)
                .send()
        })?;

        let mut json = tokio::task::block_in_place(move || response.json::<serde_json::Value>())?;

        Ok(json["result"].take())
    }
}
