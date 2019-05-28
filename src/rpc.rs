use bitcoin::Address;
use log::Level::Trace;
use log::{log_enabled, trace};

pub struct Rpc {
    client: jsonrpc::client::Client,
}

#[derive(Debug)]
pub enum Error {
    JsonRpc(jsonrpc::error::Error),
    Json(serde_json::error::Error),
    /// Errors cause sender side matter, like parameter was wrong.
    InvalidRequest,
}

impl From<jsonrpc::error::Error> for Error {
    fn from(e: jsonrpc::error::Error) -> Error {
        Error::JsonRpc(e)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Error {
        Error::Json(e)
    }
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
    pub fn getnewblock(&self, address: &Address) -> Result<serde_json::Value, Error> {
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

        if let Some(value) = resp?.result {
            Ok(value)
        } else {
            Err(Error::InvalidRequest)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::PrivateKey;
    use secp256k1::Secp256k1;

    #[test]
    fn test_getnewblock() {
        let rpc = Rpc::new("http://127.0.0.1:12381".to_string(), Some("user".to_string()), Some("pass".to_string()));

        let private_key = PrivateKey::from_wif("cVkWtN9SaP8ywfyG1AwwjsZ5orN6a2x5wTaW2gGWkUCJVEPorDeK").unwrap();
        let secp = Secp256k1::new();
        let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);

        let result = rpc.getnewblock(&address);
        assert!(result.is_ok());

        let value = result.unwrap();
        println!("{}", value);
    }
}