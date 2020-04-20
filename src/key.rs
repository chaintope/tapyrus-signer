use tapyrus::network::constants::Network;
use tapyrus::{PrivateKey, PublicKey};
use secp256k1::rand::thread_rng;
use tapyrus::secp256k1::Secp256k1;

pub fn generate_key_pair() -> (PrivateKey, PublicKey) {
    let s = Secp256k1::new();
    let mut rng = thread_rng();
    let private_key = tapyrus::PrivateKey {
        compressed: true,
        network: Network::Prod,
        key: s.generate_keypair(&mut rng).0,
    };
    let public_key = PublicKey::from_private_key(&s, &private_key);
    (private_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tapyrus::network::constants::Network;

    #[test]
    fn test_generate_key_pair() {
        let (private_key, public_key) = generate_key_pair();
        let s = Secp256k1::new();
        assert_eq!(private_key.network, Network::Prod);
        assert_eq!(private_key.public_key(&s), public_key);
    }
}
