// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::blockdata::Block;
use crate::net::{BlockGenerationRoundMessageType, Message, MessageType, SignerID};
use bitcoin::{PrivateKey, PublicKey};
use std::str::FromStr;

pub fn enable_log(log_level: Option<log::Level>) {
    if let Some(level) = log_level {
        std::env::set_var("RUST_LOG", level.to_string());
    } else {
        std::env::set_var("RUST_LOG", "TRACE");
    }

    let _ = env_logger::builder().is_test(true).try_init();
}

pub fn create_message() -> Message {
    let signer_id = SignerID::new(TestKeys::new().pubkeys()[0]);
    Message {
        message_type: MessageType::BlockGenerationRoundMessages(
            BlockGenerationRoundMessageType::Roundfailure,
        ),
        sender_id: signer_id,
        receiver_id: None,
    }
}

pub fn get_block(index: u8) -> Block {
    let bytes: Vec<u8> = match index {
        0 => vec![
            0, 0, 0, 32, 77, 228, 137, 121, 91, 31, 137, 198, 243, 119, 113, 157, 141, 178, 102,
            20, 70, 231, 35, 162, 74, 119, 24, 168, 174, 160, 175, 210, 32, 50, 130, 188, 150, 67,
            146, 147, 210, 142, 105, 133, 119, 45, 47, 25, 75, 133, 112, 7, 79, 233, 69, 167, 215,
            96, 132, 19, 158, 148, 208, 190, 32, 64, 71, 79, 96, 189, 255, 240, 47, 231, 6, 230,
            177, 165, 201, 103, 20, 170, 124, 253, 51, 113, 94, 190, 113, 177, 76, 137, 120, 230,
            165, 107, 85, 240, 52, 212, 5, 180, 11, 93, 0, 1, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            0, 0, 3, 81, 1, 1, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 25, 118, 169, 20,
            207, 18, 219, 192, 75, 176, 222, 111, 182, 168, 122, 90, 235, 75, 46, 116, 201, 112, 6,
            178, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28,
            63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121,
            153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        1 => vec![
            0, 0, 0, 32, 125, 4, 68, 194, 18, 166, 21, 58, 24, 227, 192, 57, 180, 106, 161, 164,
            58, 121, 201, 176, 104, 60, 253, 128, 132, 142, 93, 198, 8, 102, 167, 156, 76, 187,
            149, 219, 233, 225, 40, 174, 239, 186, 110, 126, 114, 158, 187, 133, 180, 115, 192,
            174, 15, 52, 120, 17, 197, 223, 9, 18, 11, 111, 128, 226, 116, 203, 147, 145, 238, 46,
            204, 30, 42, 229, 70, 9, 69, 230, 127, 105, 106, 119, 146, 166, 27, 106, 192, 105, 200,
            12, 76, 61, 91, 129, 237, 0, 150, 182, 11, 93, 0, 1, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            0, 0, 0, 3, 82, 1, 1, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 25, 118, 169,
            20, 207, 18, 219, 192, 75, 176, 222, 111, 182, 168, 122, 90, 235, 75, 46, 116, 201,
            112, 6, 178, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226,
            246, 28, 63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137,
            121, 153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        2 => vec![
            0, 0, 0, 32, 246, 215, 42, 109, 124, 164, 225, 28, 168, 113, 148, 148, 129, 243, 236,
            218, 221, 159, 118, 15, 181, 122, 9, 91, 41, 51, 141, 85, 99, 62, 207, 15, 250, 180,
            118, 123, 237, 71, 125, 210, 251, 205, 126, 224, 44, 194, 68, 222, 67, 193, 39, 103,
            35, 152, 193, 254, 92, 31, 49, 175, 51, 242, 97, 3, 255, 168, 205, 236, 137, 76, 249,
            184, 71, 243, 0, 179, 67, 82, 232, 35, 12, 63, 53, 228, 59, 106, 81, 230, 100, 136,
            100, 29, 156, 198, 150, 131, 193, 182, 11, 93, 0, 1, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
            0, 0, 0, 3, 83, 1, 1, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 25, 118, 169,
            20, 207, 18, 219, 192, 75, 176, 222, 111, 182, 168, 122, 90, 235, 75, 46, 116, 201,
            112, 6, 178, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226,
            246, 28, 63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137,
            121, 153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        3 => vec![
            0, 0, 0, 32, 89, 172, 150, 189, 5, 79, 214, 69, 204, 103, 197, 170, 46, 142, 57, 28,
            26, 235, 183, 204, 9, 99, 56, 208, 171, 137, 83, 170, 182, 107, 37, 124, 129, 135, 106,
            88, 231, 157, 73, 44, 201, 62, 243, 225, 165, 26, 140, 133, 175, 75, 60, 52, 135, 76,
            193, 192, 4, 193, 41, 168, 243, 73, 241, 14, 127, 162, 167, 40, 6, 35, 189, 255, 133,
            131, 145, 20, 84, 74, 66, 123, 86, 155, 212, 121, 122, 107, 108, 149, 234, 119, 182,
            13, 247, 238, 44, 147, 13, 183, 11, 93, 0, 1, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
            3, 84, 1, 1, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 25, 118, 169, 20, 207,
            18, 219, 192, 75, 176, 222, 111, 182, 168, 122, 90, 235, 75, 46, 116, 201, 112, 6, 178,
            136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63,
            113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153,
            98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        _n => vec![
            0, 0, 0, 32, 64, 225, 51, 188, 105, 152, 192, 107, 30, 88, 253, 28, 117, 144, 193, 138,
            139, 149, 194, 211, 250, 75, 187, 26, 37, 222, 172, 247, 150, 233, 174, 172, 100, 84,
            80, 24, 197, 40, 209, 62, 227, 188, 176, 133, 95, 89, 160, 167, 222, 64, 118, 121, 193,
            177, 129, 192, 10, 209, 119, 174, 41, 159, 21, 158, 35, 235, 73, 61, 165, 97, 63, 165,
            10, 24, 91, 246, 118, 29, 203, 203, 89, 81, 207, 37, 237, 97, 20, 19, 243, 77, 107,
            148, 152, 95, 20, 45, 42, 183, 11, 93, 0, 1, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0,
            3, 85, 1, 1, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 25, 118, 169, 20, 207,
            18, 219, 192, 75, 176, 222, 111, 182, 168, 122, 90, 235, 75, 46, 116, 201, 112, 6, 178,
            136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63,
            113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153,
            98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    };
    Block::new(bytes)
}

pub struct TestKeys {
    pub key: [PrivateKey; 5],
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
