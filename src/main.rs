extern crate bitcoin;
extern crate secp256k1;
extern crate log;
extern crate serde;
extern crate serde_json;
extern crate bitcoin_hashes;
extern crate jsonrpc;
extern crate hex;
extern crate byteorder;

mod rpc;
mod process_master_round;

fn main() {
    process_master_round::process_master_round();
}



