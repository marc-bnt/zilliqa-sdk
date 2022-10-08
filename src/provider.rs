use crate::core::{BalanceAndNonce, ContractValue, Transaction, TxBlock};
use crate::jsonrpc::{reqwest, RpcClient};
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProviderErrorSource {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::error::Error),
}

#[derive(Error, Debug)]
#[error("{source}")]
pub struct ProviderError {
    pub method: Option<String>,
    pub source: ProviderErrorSource,
}

impl ProviderError {
    pub fn new_with_method(source: ProviderErrorSource, method: String) -> Self {
        Self {
            method: Some(method),
            source,
        }
    }
}

impl From<reqwest::Error> for ProviderError {
    fn from(err: reqwest::Error) -> Self {
        Self {
            method: None,
            source: err.into(),
        }
    }
}

impl From<serde_json::error::Error> for ProviderError {
    fn from(err: serde_json::error::Error) -> Self {
        Self {
            method: None,
            source: err.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, ProviderError>;

pub struct Provider {
    rpc_client: RpcClient,
}

impl Provider {
    pub fn new(host: String) -> Self {
        Self {
            rpc_client: RpcClient::new(host),
        }
    }

    pub fn get_latest_tx_block(&self) -> Result<TxBlock> {
        self.call("GetLatestTxBlock", Value::Null)
    }

    pub fn get_transaction(&self, transaction_hash: &str) -> Result<Transaction> {
        self.call("GetTransaction", json!([transaction_hash.to_string()]))
    }

    pub fn get_transactions_for_tx_block(&self, tx_block_number: &str) -> Result<Vec<Vec<String>>> {
        self.call(
            "GetTransactionsForTxBlock",
            json!([tx_block_number.to_string()]),
        )
    }

    pub fn get_minimum_gas_price(&self) -> Result<String> {
        self.call("GetMinimumGasPrice", Value::Null)
    }

    pub fn get_smart_contract_init(&self, contract_address: &str) -> Result<Vec<ContractValue>> {
        self.call(
            "GetSmartContractInit",
            json!([contract_address.to_string()]),
        )
    }

    pub fn get_smart_contract_substate(
        &self,
        contract_address: &str,
        variable_name: &str,
        indices: &[&str],
    ) -> Result<Value> {
        self.call(
            "GetSmartContractSubState",
            json!([
                contract_address.to_string(),
                variable_name.to_string(),
                indices,
            ]),
        )
    }

    pub fn get_contract_address_from_transaction_id(&self, transaction_id: &str) -> Result<String> {
        self.call(
            "GetContractAddressFromTransactionID",
            json!([transaction_id.to_string()]),
        )
    }

    pub fn get_balance(&self, user_address: &str) -> Result<BalanceAndNonce> {
        self.call("GetBalance", json!([user_address.to_string()]))
    }

    fn call<T: serde::de::DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let response = self
            .rpc_client
            .call(method, params)
            .map_err(|err| ProviderError::new_with_method(err.into(), method.to_string()))?;

        serde_json::from_value(response.clone())
            .map_err(|err| ProviderError::new_with_method(err.into(), method.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_latest_tx_block() {
        let provider = Provider::new("https://dev-api.zilliqa.com".into());
        let result = provider.get_latest_tx_block().unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_get_transaction() {
        let provider = Provider::new("https://api.zilliqa.com".into());
        let result = provider
            .get_transaction("f79b9a88bbe15a0af47880b4fa8dc0d15e9d5a05c4e89c59b1fc2abc9785fcf8")
            .unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_get_transactions_for_tx_block() {
        let provider = Provider::new("https://dev-api.zilliqa.com".into());
        let result = provider.get_transactions_for_tx_block("1442201").unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_get_minimum_gas_price() {
        let provider = Provider::new("https://dev-api.zilliqa.com/".into());
        let result = provider.get_minimum_gas_price().unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_get_smart_contract_init() {
        let provider = Provider::new("https://api.zilliqa.com".into());
        let result = provider
            .get_smart_contract_init("9611c53BE6d1b32058b2747bdeCECed7e1216793")
            .unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_get_smart_contract_substate() {
        let provider = Provider::new("https://api.zilliqa.com".into());
        let result = provider
            .get_smart_contract_substate("9611c53BE6d1b32058b2747bdeCECed7e1216793", "admins", &[])
            .unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn get_contract_address_from_transaction_id() {
        let provider = Provider::new("https://dev-api.zilliqa.com".into());
        let result = provider
            .get_contract_address_from_transaction_id(
                "5283d3a37d90b960ff2e7c6b2a6e8b0f5e62ed74f63b268b1b9485aa08026551",
            )
            .unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_get_balance() {
        let provider = Provider::new("https://dev-api.zilliqa.com".into());
        let result = provider
            .get_balance("9bfec715a6bd658fcb62b0f8cc9bfa2ade71434a")
            .unwrap();
        println!("{:?}", result);
    }
}
