use crate::net::SignerID;
use bitcoin::{PrivateKey, PublicKey};
use std::str::FromStr;

pub struct TestKeys {
    pub key: [PrivateKey; 5],
}

lazy_static! {
    pub static ref TEST_KEYS: TestKeys = TestKeys::new();
}

impl TestKeys {
    pub fn new() -> TestKeys {
        // private keys for testing with WIF. These keys are sorted by compressed public key dictionary order.
        let key: [PrivateKey; 5] = [
            PrivateKey::from_wif("cV3NmyH9j6hihac1omKENYVUaa7UFAyvSj7A7GMrp5WYgfv3W5fN").unwrap(),
            PrivateKey::from_wif("cN3Q5mTU58xFTp2zuWcPpKVWSpFu1eaeExoRnWEt4aYugs8Uo4aw").unwrap(),
            PrivateKey::from_wif("cTRkG8i8PP7imvryqQwcYm787WHRdMmUqBvi1Z456gHvVoKnJ9TK").unwrap(),
            PrivateKey::from_wif("cTJoBBwQbcY3Y789SxNMy9d4EJovpMBrf4RBbizuJXFokQCAxyqq").unwrap(),
            PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap(),
        ];

        TestKeys { key }
    }

    /// Returns public keys sorted by compressed public key order.
    pub fn pubkeys(&self) -> Vec<PublicKey> {
        let secp = secp256k1::Secp256k1::new();
        self.key
            .iter()
            .map(|k| PublicKey::from_private_key(&secp, k))
            .collect()
    }

    pub fn aggregated(&self) -> PublicKey {
        PublicKey::from_str("030d856ac9f5871c3785a2d76e3a5d9eca6fcce70f4de63339671dfb9d1f33edb0")
            .unwrap()
    }

    pub fn signer_id(&self) -> SignerID {
        SignerID::new(self.pubkeys()[4])
    }

    pub fn signer_ids(&self) -> Vec<SignerID> {
        self.pubkeys().iter().map(|&pk| SignerID::new(pk)).collect()
    }
}
