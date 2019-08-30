// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use bitcoin::Address;
use log::Level::Trace;
use log::{log_enabled, trace};
use secp256k1::Signature;
use serde_json::Value;
use serde::{Deserialize, Serialize};

use crate::blockdata::Block;
use crate::errors::Error;

#[derive(Debug, Serialize, Deserialize)]
struct CombineBlockSigsResult {
    hex: String,
    warning: String,
    complete: bool,
}

#[derive(Debug, Deserialize)]
pub struct GetBlockchainInfoResult {
    chain: String,
    blocks: u64,
    headers: u64,
    bestblockhash: String,
    mediantime: u64,
    initialblockdownload: bool,
}

pub struct Rpc {
    client: jsonrpc::client::Client,
}

pub trait TapyrusApi {
    /// Get or Create candidate block.
    fn getnewblock(&self, address: &Address) -> Result<Block, Error>;
    /// Validate to candidateblock
    fn testproposedblock(&self, block: &Block) -> Result<(), Error>;
    /// Combine Signatures to candidate block.
    fn combineblocksigs(&self, block: &Block, signatures: &Vec<Signature>) -> Result<Block, Error>;
    /// Broadcast new block include enough proof.
    fn submitblock(&self, block: &Block) -> Result<(), Error>;
    /// Get block chain info
    fn getblockchaininfo(&self) -> Result<GetBlockchainInfoResult, Error>;
}

impl Rpc {
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Self {
        // Check that if we have a password, we have a username; other way around is ok
        debug_assert!(pass.is_none() || user.is_some());
        Rpc {
            client: jsonrpc::client::Client::new(url, user, pass),
        }
    }

    fn call(&self, name: &str, params: &[serde_json::Value]) -> Result<jsonrpc::Response, Error> {
        let req = self.client.build_request(name, params);

        trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());

        let resp = self.client.send_request(&req).map_err(Error::from);
        if log_enabled!(Trace) && resp.is_ok() {
            let resp = resp.as_ref().unwrap();
            trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
        }

        Ok(resp?)
    }

    pub fn test_connection(&self) -> Result<(), Error>{
        match self.getblockchaininfo() {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }
}

impl TapyrusApi for Rpc {
    /// Call getnewblock rpc
    fn getnewblock(&self, address: &Address) -> Result<Block, Error> {
        let args = [address.to_string().into()];
        let resp = self.call("getnewblock", &args);

        match resp {
            Ok(jsonrpc::Response { result: Some(serde_json::Value::String(v)), .. }) => {
                let raw_block = hex::decode(v).expect("Decoding block hex failed");
                Ok(Block::new(raw_block))
            }
            Ok(_) => Err(Error::InvalidRequest),
            Err(e) => Err(e),
        }
    }

    fn testproposedblock(&self, block: &Block) -> Result<(), Error> {
        let blockhex = serde_json::Value::from(block.hex());
        let acceptnonstdtxn = serde_json::Value::Bool(true);
        let args = [blockhex, acceptnonstdtxn];
        let resp = self.call("testproposedblock", &args);

        match resp {
            Ok(jsonrpc::Response { result: Some(serde_json::Value::Bool(true)), .. }) => Ok(()),
            Ok(_v) => Err(Error::InvalidRequest),
            Err(error) => Err(error),
        }
    }

    fn combineblocksigs(&self, block: &Block, signatures: &Vec<Signature>) -> Result<Block, Error> {
        let blockhex: Value = block.hex().into();
        let signatures: Value = signatures.iter().map(|sig| { hex::encode(sig.serialize_der()) }).collect();
        let args = [blockhex, signatures];
        let resp = self.call("combineblocksigs", &args);

        match resp?.result::<CombineBlockSigsResult>() {
            Ok(CombineBlockSigsResult { hex: v, .. }) => {
                let raw_block = hex::decode(v).expect("Decoding block hex failed");
                Ok(Block::new(raw_block))
            }
            Err(e) => Err(Error::JsonRpc(e)),
        }
    }

    fn submitblock(&self, block: &Block) -> Result<(), Error> {
        let blockhex: Value = block.hex().into();
        let args = [blockhex];
        let resp = self.call("submitblock", &args);

        match resp {
            Ok(jsonrpc::Response { result: None, .. }) => Ok(()),
            Ok(_) => Err(Error::InvalidRequest),
            Err(e) => Err(e),
        }
    }

    fn getblockchaininfo(&self) -> Result<GetBlockchainInfoResult, Error> {
        let resp = self.call("getblockchaininfo", &[]);
        match resp?.result::<GetBlockchainInfoResult>() {
            Ok(r) =>  Ok(r),
            Err(e) => Err(Error::JsonRpc(e)),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    use crate::test_helper::{TestKeys, get_block};
    use crate::sign::sign;

    pub fn get_rpc_client() -> Rpc {
        Rpc::new("http://127.0.0.1:12381".to_string(), Some("user".to_string()), Some("pass".to_string()))
    }

    pub fn call_getnewblock() -> Result<Block, Error> {
        let rpc = get_rpc_client();

        let private_key = TestKeys::new().key[0];
        let secp = Secp256k1::new();
        let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
        rpc.getnewblock(&address)
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
                Err(error) => Err(self.create_error(error.to_string()))
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

        fn testproposedblock(&self, _block: &Block) -> Result<(), Error> {
            let _block = self.result()?;
            Ok(())
        }

        fn combineblocksigs(&self, _block: &Block, _signatures: &Vec<Signature>) -> Result<Block, Error> {
            self.result()
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

    #[test]
    #[ignore]
    fn test_combineblocksigs() {
        let block = get_block(0);
        let block_hash = block.hash().unwrap();
        let keys = &TestKeys::new().key[..1]; // Just 1 signature
        let sigs: Vec<Signature> = keys.iter().map(|key| {
            sign(&key, &block_hash)
        }).collect();

        let rpc = get_rpc_client();
        let result = rpc.combineblocksigs(&block, &sigs);

        assert!(result.is_ok());
    }

    #[test]
    #[ignore]
    fn test_submitblock() {
        let rpc = get_rpc_client();

        let block = call_getnewblock().unwrap();
        let block_hash = block.hash().unwrap();
        let keys = &TestKeys::new().key[..1]; // Just 1 signature
        let sigs: Vec<Signature> = keys.iter().map(|key| {
            sign(&key, &block_hash)
        }).collect();

        let result = rpc.combineblocksigs(&block, &sigs);
        let completed_block = result.unwrap();
        let result = rpc.submitblock(&completed_block);
        assert!(result.is_ok());

        // when invalid block.(cannot connect on the tip)
        let block = get_block(0);
        assert!(rpc.submitblock(&block).is_err());
    }

    #[test]
    #[ignore]
    fn test_getblockchaininfo() {
        let rpc = get_rpc_client();
        let result = rpc.getblockchaininfo();
        println!("{:?}", result);
        assert!(result.is_ok());
    }
}