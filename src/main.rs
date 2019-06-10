extern crate bitcoin;
extern crate secp256k1;
extern crate log;
extern crate serde;
extern crate serde_json;
extern crate bitcoin_hashes;
extern crate jsonrpc;
extern crate hex;
extern crate byteorder;
extern crate base64;
extern crate redis;

mod blockdata;
mod rpc;
mod process_master_round;
mod sign;
mod test_helper;
mod errors;
mod net;


fn main() {
    process_master_round::process_master_round();
}



