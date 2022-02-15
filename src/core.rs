use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct ContractValue {
    pub vname: String,
    pub r#type: String,
    pub value: Value,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionMessage {
    #[serde(rename = "_amount")]
    pub amount: String,
    #[serde(rename = "_recipient")]
    pub recipient: String,
    #[serde(rename = "_tag")]
    pub tag: String,
    pub params: Vec<ContractValue>,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionException {
    line: u32,
    message: String,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Transition {
    pub addr: String,
    pub depth: u32,
    pub msg: TransactionMessage,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionReceipt {
    pub accept: Option<bool>,
    pub cumulative_gas: String,
    pub epoch_num: String,
    pub success: bool,
    pub transitions: Option<Vec<Transition>>,
    pub errors: Option<HashMap<String, Vec<u32>>>,
    pub exceptions: Option<Vec<TransactionException>>,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(rename = "ID")]
    pub id: String,
    pub amount: String,
    pub code: Option<String>,
    pub data: Option<String>,
    pub gas_limit: String,
    pub gas_price: String,
    pub nonce: String,
    pub receipt: TransactionReceipt,
    pub sender_pub_key: String,
    pub signature: String,
    pub to_addr: String,
    pub version: String,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockHeader {
    pub block_num: String,
    #[serde(rename = "DSBlockNum")]
    pub ds_block_num: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub mb_info_hash: String,
    pub miner_pub_key: String,
    pub num_micro_blocks: u32,
    pub num_pages: u32,
    pub num_txns: u32,
    pub prev_block_hash: String,
    pub rewards: String,
    pub state_delta_hash: String,
    pub state_root_hash: String,
    pub timestamp: String,
    pub txn_fees: String,
    pub version: u32,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct MicroBlockInfo {
    pub micro_block_hash: String,
    pub micro_block_shard_id: u32,
    pub micro_block_txn_root_hash: String,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TxBlockBody {
    pub block_hash: String,
    pub header_sign: String,
    pub micro_block_infos: Vec<MicroBlockInfo>,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct TxBlock {
    pub body: TxBlockBody,
    pub header: TxBlockHeader,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct BalanceAndNonce {
    pub balance: String,
    pub nonce: u64,
}
