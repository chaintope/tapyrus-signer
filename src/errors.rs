#[derive(Debug)]
pub enum Error {
    JsonRpc(jsonrpc::error::Error),
    Json(serde_json::error::Error),
    InvalidLength(usize, usize),
    InvalidArgs(String),
    BitcoinConsensusEncodeError(bitcoin::consensus::encode::Error),
    /// Errors cause sender side matter, like parameter was wrong.
    InvalidRequest,
    DuplicatedMessage,
    InvalidSignature(secp256k1::Error),
    TimerAlreadyStarted,
}


impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
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

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::InvalidSignature(e)
    }
}
