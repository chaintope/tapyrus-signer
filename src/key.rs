use bitcoin::network::constants::Network;
use bitcoin::{PrivateKey, PublicKey};
use secp256k1::rand::thread_rng;
use secp256k1::Secp256k1;

pub fn generate_key_pair() -> (PrivateKey, PublicKey) {
    let s = Secp256k1::new();
    let mut rng = thread_rng();
    let private_key = bitcoin::PrivateKey {
        compressed: true,
        network: Network::Bitcoin,
        key: s.generate_keypair(&mut rng).0,
    };
    let public_key = PublicKey::from_private_key(&s, &private_key);
    (private_key, public_key)
}
