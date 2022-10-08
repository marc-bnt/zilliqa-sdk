use std::{collections::HashMap, rc::Rc};

use crate::keytools::get_address_from_private_key;

use super::account::Account;

pub struct Wallet {
    accounts: HashMap<String, Rc<Account>>,
    default_account: Option<Rc<Account>>,
}

impl Wallet {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            default_account: None,
        }
    }

    pub fn add_by_private_key(&mut self, private_key: &str) {
        let prik = hex::decode(private_key).unwrap();
        let account = Rc::new(Account::new(prik.clone()));
        let address = get_address_from_private_key(&prik).unwrap().to_uppercase();
        self.accounts.insert(address, account.clone());

        if self.default_account.is_none() {
            self.default_account = Some(account.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{core::Transaction, provider::Provider, util::pack};

    use super::*;

    #[test]
    fn test_payload() {
        let mut wallet = Wallet::new();
        wallet
            .add_by_private_key("e19d05c5452598e24caad4a0d85a49146f7be089515c905ae6a19e8a578a6930");
        let provider = Provider::new("https://dev-api.zilliqa.com/".into());

        let gas_price = provider.get_minimum_gas_price().unwrap();

        let tx = Transaction {
            version: pack(333, 1).to_string(),
            sender_pub_key: "0246E7178DC8253201101E18FD6F6EB9972451D121FC57AA2A06DD5C111E58DC6A"
                .into(),
            to_addr: "4BAF5faDA8e5Db92C3d3242618c5B47133AE003C".into(),
            amount: "10000000".into(),
            gas_price: gas_price,
            gas_limit: "50".into(),
            code: None,
            data: None,
            priority: false,
            id: None,
            nonce: None,
            receipt: None,
            signature: None,
        };

        todo!("{:?}", tx);
    }
}
