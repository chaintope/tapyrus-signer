use bitcoin::{PrivateKey, PublicKey};

pub mod aggregate;
pub mod create_block_vss;
pub mod create_key;
pub mod create_node_vss;
pub mod traits;

pub fn index_of(private_key: &PrivateKey, public_keys: &Vec<PublicKey>) -> usize {
    let secp = secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_private_key(&secp, private_key);
    let pos = public_keys
        .iter()
        .position(|pk| pk == &public_key)
        .expect("private_key or public_keys is invalid.");
    pos + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{PrivateKey, PublicKey};
    use std::str::FromStr;

    #[test]
    fn test_index_of() {
        let private_key =
            PrivateKey::from_wif("KwUKaA3KgtRhCsioNWZQfC6Nd6vPNTXwgmqcStewZ3KdonmP3k43").unwrap();
        let public_keys = vec![
            "023092e0fad6f42a2f456f5a891d8ea868393ca4308fef0f29388a1c5687d5860e",
            "03abdc3e2d64fb3e9ceeaf7d0f272c14c36793dfb862018c34a6ac5dfe0c02860e",
            "03d10d42715a8c7e6c93fac9336bcb5b286e827e766594e4d166b4894b805236a7",
        ]
        .iter()
        .map(|key| PublicKey::from_str(key).unwrap())
        .collect();

        assert_eq!(index_of(&private_key, &public_keys), 2);
    }
}
