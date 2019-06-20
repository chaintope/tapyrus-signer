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
}

impl Rpc {
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Rpc {
        // Check that if we have a password, we have a username; other way around is ok
        debug_assert!(pass.is_none() || user.is_some());
        Rpc {
            client: jsonrpc::client::Client::new(url, user, pass),
        }
    }

    fn call(&self, name: &str, params: &[serde_json::Value]) -> Result<jsonrpc::Response, Error> {
        let req = self.client.build_request(name, params);

        if log_enabled!(Trace) {
            trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
        }

        let resp = self.client.send_request(&req).map_err(Error::from);

        if log_enabled!(Trace) && resp.is_ok() {
            let resp = resp.as_ref().unwrap();
            trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
        }

        Ok(resp?)
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

    pub struct MockRpc<'a> {
        pub return_block: Option<&'a Block>,
    }

    impl<'a> MockRpc<'a> {

        pub fn result(&self) -> Result<Block, Error> {
            match self.return_block {
                Some(b) => Ok(b.clone()),
                None => Err(Error::JsonRpc(jsonrpc::error::Error::Rpc(jsonrpc::error::RpcError {
                    code: 0,
                    message: "return_block is None.".to_string(),
                    data: None,
                })))
            }
        }
    }
    impl<'a> TapyrusApi for MockRpc<'a> {
        fn getnewblock(&self, _address: &Address) -> Result<Block, Error> {
            self.result()
        }

        fn testproposedblock(&self, _block: &Block) -> Result<(), Error> {
            Ok(())
        }

        fn combineblocksigs(&self, _block: &Block, _signatures: &Vec<Signature>) -> Result<Block, Error> {
            self.result()
        }

        fn submitblock(&self, _block: &Block) -> Result<(), Error> {
            Ok(())
        }
    }

    /// TODO: use rpc mock. Now this test needs tapyrus node process.
    #[test]
    fn test_getnewblock() {
        let result = call_getnewblock();
        assert!(result.is_ok());

        let _value = result.unwrap();
    }

    #[test]
    fn test_testproposedblock() {
        let block = call_getnewblock().unwrap();
        let rpc = get_rpc_client();

        let result = rpc.testproposedblock(&block);

        assert!(result.is_ok());
    }

    #[test]
    fn test_combineblocksigs() {
        let block = get_block();
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
        let block = get_block();
        assert!(rpc.submitblock(&block).is_err());
    }
}