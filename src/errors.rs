// Copyright (c) 2019 Chaintope Inc.

use redis::RedisError;

#[derive(Debug)]
pub enum Error {
    JsonRpc(jsonrpc::error::Error),
    Json(serde_json::error::Error),
    InvalidLength(usize, usize),
    InvalidArgs(String),
    BitcoinConsensusEncodeError(tapyrus::consensus::encode::Error),
    /// Errors cause sender side matter, like parameter was wrong.
    InvalidRequest(jsonrpc::error::RpcError),
    DuplicatedMessage,
    InvalidLocalSignature,
    InvalidAggregatedSignature,
    InvalidBlock,
    InvalidKey,
    InvalidNodeState,
    InvalidSS,
    InvalidSig,
    TimerAlreadyStarted,
    InvalidTomlFormat(toml::de::Error),
    ConfigFileIOError(std::io::Error),
    InvalidPublicKeyFormat(String),
    RedisError(RedisError),
    /// Errors for using incomplete block(like no proof block) as usual block.
    IncompleteBlock,
    /// Errors when the federation is invalid. This error has the block height of the federation gets started and message string.
    InvalidFederation(Option<u32>, &'static str),
    /// Error when the aggregated public key included the candidate block is invalid.
    InvalidAggregatedPublicKey,
    /// xField is not supported by signer.
    UnsupportedXField(String),
    UnauthorizedFederationChange(u32),
    XfieldFederationMismatch(Option<u32>, &'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

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

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Error {
        Error::InvalidTomlFormat(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::ConfigFileIOError(e)
    }
}

impl From<RedisError> for Error {
    fn from(e: RedisError) -> Error {
        Error::RedisError(e)
    }
}

impl From<tapyrus::consensus::encode::Error> for Error {
    fn from(e: tapyrus::consensus::encode::Error) -> Error {
        Error::BitcoinConsensusEncodeError(e)
    }
}
