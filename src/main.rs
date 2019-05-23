extern crate bitcoin;
extern crate secp256k1;
extern crate bitcoincore_rpc;
extern crate log;
extern crate serde;
extern crate serde_json;
extern crate bitcoin_hashes;

use bitcoin::{PrivateKey, Address};
use bitcoincore_rpc::{Auth, Client, RpcApi, Error, json};
use secp256k1::Secp256k1;
use log::Level::Trace;
use log::log_enabled;
use log::trace;
use serde::{Serialize, Deserialize};
use serde_json::Value;

use bitcoin_hashes::sha256d;

/// Models the result of "getblockchaininfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TapyrusGetBlockchainInfoResult {
    // TODO: Use Network from rust-bitcoin
    /// Current network name as defined in BIP70 (main, test, regtest)
    pub chain: String,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The hash of the currently best block
    pub bestblockhash: sha256d::Hash,
    /// Median time for the current best block
    pub mediantime: u64,
    /// Estimate of verification progress [0..1]
    pub verificationprogress: f64,
    /// Estimate of whether this node is in Initial Block Download mode
    pub initialblockdownload: bool,
    /// The estimated size of the block and undo files on disk
    pub size_on_disk: u64,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    /// Lowest-height complete block stored (only present if pruning is enabled)
    pub pruneheight: Option<u64>,
    /// Whether automatic pruning is enabled (only present if pruning is enabled)
    pub automatic_pruning: Option<bool>,
    /// The target size used by pruning (only present if automatic pruning is enabled)
    pub prune_target_size: Option<u64>,
    /// Status of softforks in progress
    pub softforks: Vec<json::Softfork>,
    // TODO: add a type?
    /// Status of BIP9 softforks in progress
    pub bip9_softforks: Value,
    /// Any network and blockchain warnings.
    pub warnings: String,
}

pub trait TapyrusRpcApi: RpcApi {
    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    fn tapyrus_get_blockchain_info(&self) -> bitcoincore_rpc::Result<TapyrusGetBlockchainInfoResult> {
        self.call("getblockchaininfo", &[])
    }
}

impl TapyrusRpcApi for Client {}

fn getblockchaininfo() -> Result<(), Error>{
    let private_key = PrivateKey::from_wif("L5PXRT9b9KSinEVzcm8pNZ42Bd4guarPsRS2vFp1FMYJEVFgM6Gr").unwrap();

    let secp = Secp256k1::new();
    let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
    println!("{}", address);


    let rpc = Client::new("http://127.0.0.1:12381".to_string(),Auth::UserPass("user".to_string(), "pass".to_string())).unwrap();
    println!("fugafuga1");

    if log_enabled!(Trace) {
        trace!("Trace hogehoge");
    }

    match rpc.tapyrus_get_blockchain_info() {
        Ok(a) => {
            println!("OK, {}", a.chain);
        },
        Err(e)=> {
            println!("Error: {}", e);
        }
    }

    println!("fugafuga2");
//    println!("hoge{}", blockchain_info.chain);

    let blockchain_info2 = rpc.get_blockchain_info()?;



//    println!("hoge{}", blockchain_info.chain);

    Ok(())
}

fn main() {
    getblockchaininfo();
}



