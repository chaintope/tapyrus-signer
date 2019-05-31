use bitcoin::Address;
use log::Level::Trace;
use log::{log_enabled, trace};
use secp256k1::Signature;
use crate::blockdata::Block;
use crate::blockdata;
use crate::errors::Error;

pub struct Rpc {
    client: jsonrpc::client::Client,
}

impl Rpc {
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Rpc {
        // Check that if we have a password, we have a username; other way around is ok
        debug_assert!(pass.is_none() || user.is_some());

        Rpc {
            client: jsonrpc::client::Client::new(url, user, pass),
        }
    }

    /// Call getnewblock rpc
    pub fn getnewblock(&self, address: &Address) -> Result<Block, Error> {
        let args = [address.to_string().into()];
        let req = self.client.build_request("getnewblock", &args);
        if log_enabled!(Trace) {
            trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
        }

        let resp = self.client.send_request(&req).map_err(Error::from);
        if log_enabled!(Trace) && resp.is_ok() {
            let resp = resp.as_ref().unwrap();
            trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
        }

        match resp {
            Ok(jsonrpc::Response { result: Some(serde_json::Value::String(v)), .. }) => {
                let raw_block= hex::decode(v).expect("Decoding block hex failed");
                Ok(Block::new(raw_block))
            },
            Ok(_) => Err(Error::InvalidRequest),
            Err(e) => Err(e),
        }
    }

    pub fn testproposedblock(&self, block: &Block) -> Result<(), Error> {
        let blockhex = serde_json::Value::from(block.hex());
        let acceptnonstdtxn = serde_json::Value::Bool(true);
        let args = [blockhex, acceptnonstdtxn];
        let req = self.client.build_request("testproposedblock", &args);
        if log_enabled!(Trace) {
            trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
        }

        let resp = self.client.send_request(&req).map_err(Error::from);

        if log_enabled!(Trace) && resp.is_ok() {
            let resp = resp.as_ref().unwrap();
            trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
        }

        match resp {
            Ok(jsonrpc::Response { result: Some(serde_json::Value::Bool(true)), .. } ) => Ok(()),
            Ok(v) => Err(Error::InvalidRequest),
            Err(error) => Err(error),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::PrivateKey;
    use secp256k1::Secp256k1;
    use crate::test_helper::{TestKeys, get_block};
    use crate::sign::sign;

    fn get_rpc_client() -> Rpc {
        Rpc::new("http://127.0.0.1:12381".to_string(), Some("user".to_string()), Some("pass".to_string()))
    }

    fn call_getnewblock() -> Result<Block, Error> {
        let rpc = get_rpc_client();

        let private_key = TestKeys::new().key[0];
        let secp = Secp256k1::new();
        let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
        rpc.getnewblock(&address)
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

//        for x in TestKeys::new().key {
//            sign(&x, )
//
//        }
    }
}