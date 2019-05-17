extern crate bitcoin;
extern crate secp256k1;

use bitcoin::{PrivateKey, Address};
use secp256k1::{self, Secp256k1};

fn main() {
    let private_key = PrivateKey::from_wif("L5PXRT9b9KSinEVzcm8pNZ42Bd4guarPsRS2vFp1FMYJEVFgM6Gr").unwrap();

    let secp = Secp256k1::new();
    let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
    println!("{}", address);

}



