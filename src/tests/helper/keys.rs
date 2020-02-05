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
        // corresponding public keys are:
        // 03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc
        // 02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900
        // 02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e

        // command example for 3 of 5 signer node network, using same public and private keys at test.
        // ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 --privatekey=cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA -t 3 --rpcport=12381 --rpcuser=user --rpcpass=pass
        // ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 --privatekey=cTRkG8i8PP7imvryqQwcYm787WHRdMmUqBvi1Z456gHvVoKnJ9TK -t 3 --rpcport=12381 --rpcuser=user --rpcpass=pass
        // ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 --privatekey=cN3Q5mTU58xFTp2zuWcPpKVWSpFu1eaeExoRnWEt4aYugs8Uo4aw -t 3 --rpcport=12381 --rpcuser=user --rpcpass=pass
        // ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 --privatekey=cTJoBBwQbcY3Y789SxNMy9d4EJovpMBrf4RBbizuJXFokQCAxyqq -t 3 --rpcport=12381 --rpcuser=user --rpcpass=pass
        // ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 --privatekey=cV3NmyH9j6hihac1omKENYVUaa7UFAyvSj7A7GMrp5WYgfv3W5fN -t 3 --rpcport=12381 --rpcuser=user --rpcpass=pass

        // TestKeys Array index and publickey dictionary order mapping is below
        // array index -> ordered index
        //      0      ->     4
        //      1      ->     0
        //      2      ->     3
        //      3      ->     2
        //      4      ->     1
        let key: [PrivateKey; 5] = [
            PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap(),
            PrivateKey::from_wif("cTRkG8i8PP7imvryqQwcYm787WHRdMmUqBvi1Z456gHvVoKnJ9TK").unwrap(),
            PrivateKey::from_wif("cN3Q5mTU58xFTp2zuWcPpKVWSpFu1eaeExoRnWEt4aYugs8Uo4aw").unwrap(),
            PrivateKey::from_wif("cTJoBBwQbcY3Y789SxNMy9d4EJovpMBrf4RBbizuJXFokQCAxyqq").unwrap(),
            PrivateKey::from_wif("cV3NmyH9j6hihac1omKENYVUaa7UFAyvSj7A7GMrp5WYgfv3W5fN").unwrap(),
        ];

        TestKeys { key }
    }

    pub fn pubkeys(&self) -> Vec<PublicKey> {
        vec![
            PublicKey::from_str(
                "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc",
            )
            .unwrap(),
            PublicKey::from_str(
                "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900",
            )
            .unwrap(),
            PublicKey::from_str(
                "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e",
            )
            .unwrap(),
            PublicKey::from_str(
                "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c",
            )
            .unwrap(),
            PublicKey::from_str(
                "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
            )
            .unwrap(),
        ]
    }
    pub fn signer_id(&self) -> SignerID {
        SignerID::new(self.pubkeys()[0])
    }
}
