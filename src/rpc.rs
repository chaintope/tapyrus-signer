// Copyright (c) 2019 Chaintope Inc.

use log::Level::Trace;
use log::{log_enabled, trace};
use serde::Deserialize;
use std::collections::HashMap;
use tapyrus::{Address, PublicKey};

use crate::errors::Error;
use jsonrpc::Client;
use serde_json::value::RawValue;
use tapyrus::blockdata::block::{Block, XField};
use tapyrus::consensus::encode::{deserialize, serialize};

#[derive(Debug, Deserialize, Clone)]
pub struct GetBlockchainInfoResult {
    pub chain: String,
    pub blocks: u32,
    pub headers: u64,
    pub bestblockhash: String,
    pub mediantime: u64,
    pub initialblockdownload: bool,
    pub aggregate_pubkeys: Vec<HashMap<PublicKey, u32>>,
    pub max_block_sizes: Vec<HashMap<u32, u32>>,
}

pub struct Rpc {
    client: jsonrpc::client::Client,
}

pub trait TapyrusApi {
    /// Get or Create candidate block.
    fn getnewblock(&self, address: &Address) -> Result<Block, Error>;
    /// Get or Create candidate block with xfield change.
    fn getnewblockwithxfield(
        &self,
        address: &Address,
        required_age: &u32,
        xfield: &XField,
    ) -> Result<Block, Error>;
    /// Validate to candidateblock
    fn testproposedblock(&self, block: &Block) -> Result<bool, Error>;
    /// Broadcast new block include enough proof.
    fn submitblock(&self, block: &Block) -> Result<(), Error>;
    /// Get block chain info
    fn getblockchaininfo(&self) -> Result<GetBlockchainInfoResult, Error>;
}

impl Rpc {
    pub fn new(url: &str, user: Option<String>, pass: Option<String>) -> Self {
        // Check that if we have a password, we have a username; other way around is ok
        debug_assert!(pass.is_none() || user.is_some());
        Rpc {
            client: Client::simple_http(url, user, pass).unwrap(),
        }
    }

    fn call<T>(&self, name: &str, params: &[Box<RawValue>]) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let req = self.client.build_request(name, params);

        trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());

        match self.client.send_request(req) {
            Ok(resp) => {
                if log_enabled!(Trace) {
                    trace!(
                        "JSON-RPC response: {}: {}",
                        name,
                        serde_json::to_string(&resp).unwrap()
                    );
                }

                if let Err(jsonrpc::Error::Rpc(e)) = resp.clone().check_error() {
                    warn!("RPC Error: {:?}", e);
                    return Err(Error::InvalidRequest(e));
                }

                match resp.result::<T>() {
                    Ok(result) => Ok(result),
                    Err(e) => Err(Error::JsonRpc(e)),
                }
            }
            Err(e) => Err(Error::from(e)),
        }
    }

    pub fn test_connection(&self) -> Result<(), Error> {
        match self.getblockchaininfo() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn getnewblock_raw(&self, raw_args: &Vec<Box<RawValue>>) -> Result<Block, Error> {
        let resp = self.call::<String>("getnewblock", &raw_args);
        match resp {
            Ok(v) => {
                let raw_block = hex::decode(v).expect("Decoding block hex failed");
                deserialize(&raw_block).map_err(|_| Error::InvalidBlock)
            }
            Err(e) => Err(e),
        }
    }
}

fn to_rpc_string(xfield: &XField) -> String {
    match xfield {
        XField::None => String::new(),
        XField::AggregatePublicKey(pubkey) => {
            format!("{}:{}", xfield.field_type(), pubkey)
        }
        XField::MaxBlockSize(size) => format!("{}:{}", xfield.field_type(), size),
        XField::Unknown(_, _) => String::new(),
    }
}

impl TapyrusApi for Rpc {
    /// Call getnewblock rpc
    fn getnewblock(&self, address: &Address) -> Result<Block, Error> {
        let arg = serde_json::Value::from(address.to_string());
        let raw_args = vec![serde_json::value::to_raw_value(&arg).unwrap()];
        self.getnewblock_raw(&raw_args)
    }

    fn getnewblockwithxfield(
        &self,
        address: &Address,
        required_age: &u32,
        xfield: &XField,
    ) -> Result<Block, Error> {
        let args = vec![
            serde_json::Value::from(address.to_string()),
            serde_json::Value::from(*required_age),
            serde_json::Value::from(to_rpc_string(&xfield)),
        ];

        let raw_args: Vec<_> = args
            .into_iter()
            .map(|value| serde_json::value::to_raw_value(&value).unwrap())
            .collect();
        self.getnewblock_raw(&raw_args)
    }

    fn testproposedblock(&self, block: &Block) -> Result<bool, Error> {
        let block_hex = serde_json::value::to_raw_value(&hex::encode(serialize(block)))?;
        self.call::<bool>("testproposedblock", &[block_hex])
    }

    fn submitblock(&self, block: &Block) -> Result<(), Error> {
        let block_hex = serde_json::value::to_raw_value(&hex::encode(serialize(block)))?;
        self.call::<()>("submitblock", &[block_hex])
    }

    fn getblockchaininfo(&self) -> Result<GetBlockchainInfoResult, Error> {
        self.call::<GetBlockchainInfoResult>("getblockchaininfo", &[])
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::helper::keys::TEST_KEYS;
    use tapyrus::secp256k1::Secp256k1;

    pub fn get_rpc_client() -> Rpc {
        Rpc::new(
            "http://127.0.0.1:12381",
            Some("user".to_string()),
            Some("pass".to_string()),
        )
    }

    pub fn call_getnewblock() -> Result<Block, Error> {
        let rpc = get_rpc_client();

        let private_key = TEST_KEYS.key[4];
        let secp = Secp256k1::new();
        let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
        rpc.getnewblock(&address)
    }

    pub fn call_getnewblockwithxfield(xfield: XField) -> Result<Block, Error> {
        let rpc = get_rpc_client();

        let private_key = TEST_KEYS.key[4];
        let secp = Secp256k1::new();
        let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
        let required_age = 0;
        let xfield = xfield.clone();
        rpc.getnewblockwithxfield(&address, &required_age, &xfield)
    }

    use std::sync::{Arc, Mutex};

    pub type SafetyBlock = Arc<Mutex<Result<Block, AnyError>>>;
    pub struct MockRpc {
        pub return_block: SafetyBlock,
    }
    impl MockRpc {
        pub fn result(&self) -> Result<Block, Error> {
            let gard_block = self.return_block.try_lock().unwrap();
            let result = (*gard_block).as_ref();
            match result {
                Ok(b) => Ok(b.clone()),
                Err(error) => Err(self.create_error(error.to_string())),
            }
        }

        fn create_error(&self, message: String) -> Error {
            Error::JsonRpc(jsonrpc::error::Error::Rpc(jsonrpc::error::RpcError {
                code: 0,
                message,
                data: None,
            }))
        }
    }

    #[derive(Debug)]
    pub struct AnyError(pub String);

    impl core::fmt::Display for AnyError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl std::error::Error for AnyError {}

    pub fn safety(block: Block) -> SafetyBlock {
        Arc::new(Mutex::new(Ok(block)))
    }

    pub fn safety_error(error_msg: String) -> SafetyBlock {
        Arc::new(Mutex::new(Err(AnyError(error_msg))))
    }

    impl TapyrusApi for MockRpc {
        fn getnewblock(&self, _address: &Address) -> Result<Block, Error> {
            self.result()
        }

        fn getnewblockwithxfield(
            &self,
            _address: &Address,
            _required_age: &u32,
            _xfield_str: &XField,
        ) -> Result<Block, Error> {
            self.result()
        }

        fn testproposedblock(&self, _block: &Block) -> Result<bool, Error> {
            let _block = self.result()?;
            Ok(true)
        }

        fn submitblock(&self, _block: &Block) -> Result<(), Error> {
            let _block = self.result()?;
            Ok(())
        }

        fn getblockchaininfo(&self) -> Result<GetBlockchainInfoResult, Error> {
            Ok(GetBlockchainInfoResult {
                chain: "regtest".to_string(),
                blocks: 0,
                headers: 0,
                bestblockhash: "xxx".to_string(),
                mediantime: 0,
                initialblockdownload: false,
                aggregate_pubkeys: vec![],
                max_block_sizes: vec![],
            })
        }
    }

    /// TODO: use rpc mock. Now this test needs tapyrus node process.
    #[test]
    #[ignore]
    fn test_getnewblock() {
        let result = call_getnewblock();
        assert!(result.is_ok());

        let _value = result.unwrap();
    }

    #[test]
    #[ignore]
    fn test_testproposedblock() {
        let block = call_getnewblock().unwrap();
        let rpc = get_rpc_client();

        let result = rpc.testproposedblock(&block);

        assert!(result.is_ok());
    }
}
