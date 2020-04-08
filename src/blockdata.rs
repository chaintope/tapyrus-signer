// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::serialize::HexStrVisitor;
use bitcoin::PublicKey;
use bitcoin_hashes::{sha256d, Hash};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;

pub mod hash {
    use crate::errors::Error;
    use crate::serialize::HexStrVisitor;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt::Debug;

    /// This is hash value container struct.
    /// This struct assumes porting value from sha256d::Hash.
    #[derive(PartialEq, Clone, Copy)]
    pub struct SHA256Hash([u8; 32]);

    impl SHA256Hash {
        const LEN: usize = 32;

        pub fn from_slice(sl: &[u8]) -> Result<SHA256Hash, Error> {
            if sl.len() != Self::LEN {
                Err(Error::InvalidLength(Self::LEN, sl.len()))
            } else {
                let mut ret = [0; 32];
                ret.copy_from_slice(sl);
                Ok(SHA256Hash(ret))
            }
        }

        pub fn into_inner(self) -> [u8; 32] {
            self.0
        }
        pub fn borrow_inner(&self) -> &[u8; 32] {
            &self.0
        }
    }

    impl Debug for SHA256Hash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Change byteorder to Big Endian
            let mut rev = self.0.clone();
            rev.reverse();

            let h = hex::encode(rev);
            write!(f, "Hash({})", h)
        }
    }

    impl Serialize for SHA256Hash {
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
        {
            let hex = hex::encode(&self.into_inner()[..]);
            serializer.serialize_str(&hex)
        }
    }

    impl<'de> Deserialize<'de> for SHA256Hash {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let vec = deserializer.deserialize_str(HexStrVisitor::with_size(32))?;
            Ok(SHA256Hash::from_slice(&vec[..]).unwrap())
        }
    }
}

#[derive(PartialEq, Clone)]
pub struct Block(Vec<u8>);

impl Block {
    const AGG_PUBKEY_POSITION: usize = 105;

    pub fn new(data: Vec<u8>) -> Block {
        Block(data)
    }

    /// Length of block header without proof is 105 + len bytes.
    /// Version: 4
    /// hasPrevBlock: 32
    /// hashMerkleRoot: 32
    /// hashImMerkleRoot: 32
    /// time: 4
    /// length of aggPubkey (len): 1
    /// aggPubkey: len
    pub fn get_header_without_proof(&self) -> &[u8] {
        let position = Self::AGG_PUBKEY_POSITION + self.get_aggregated_public_key_length();
        &self.0[..position]
    }

    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Returns hash for signing. This hash value doesn't include proof field. Actual block hash
    /// includes proof data.
    pub fn sighash(&self) -> hash::SHA256Hash {
        let header = self.get_header_without_proof();
        let hash = sha256d::Hash::hash(header).into_inner();
        hash::SHA256Hash::from_slice(&hash)
            .expect("couldn't convert to blockdata::hash::Hash from sha256d::hash")
    }

    /// Returns block hash
    pub fn hash(&self) -> hash::SHA256Hash {
        let header = if self.0[Self::AGG_PUBKEY_POSITION] == 0 {
            &self.0[..(Self::AGG_PUBKEY_POSITION + 1)] // length byte
        } else {
            &self.0[..(Self::AGG_PUBKEY_POSITION + 65)] // length byte + signature(64 bytes)
        };

        let hash = sha256d::Hash::hash(header).into_inner();
        hash::SHA256Hash::from_slice(&hash)
            .expect("couldn't convert to blockdata::hash::Hash from sha256d::hash")
    }

    pub fn payload(&self) -> &[u8] {
        &self.0
    }

    pub fn add_proof(&self, proof: Vec<u8>) -> Block {
        let position = Self::AGG_PUBKEY_POSITION + self.get_aggregated_public_key_length();
        let (header, txs) = self.payload().split_at(position);
        let new_payload = [header, &proof[..], &txs[1..]].concat();
        Block(new_payload)
    }

    pub fn add_aggregated_public_key(&self, aggregated_public_key: PublicKey) -> Block {
        let (header, rest) = self.payload().split_at(Self::AGG_PUBKEY_POSITION - 1);
        let bytes = aggregated_public_key.to_bytes();
        let new_payload = [header, &[bytes.len() as u8], &bytes[..], &rest[1..]].concat();
        Block(new_payload)
    }

    /// the length of aggregated public key.
    /// return 0 if key is not set in block.
    /// return 33 if otherwise.
    fn get_aggregated_public_key_length(&self) -> usize {
        self.0[Self::AGG_PUBKEY_POSITION - 1] as usize
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = hex::encode(&self.0);
        write!(f, "Block({})", h)
    }
}

impl Serialize for Block {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let hex = self.hex();
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = deserializer.deserialize_str(HexStrVisitor::new())?;
        Ok(Block::new(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TEST_BLOCK: &str = "010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d00403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc01010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000";
    const TEST_BLOCK2: &str = "010000000000000000000000000000000000000000000000000000000000000000000000e7c526d0125538b13a50b06465fb8b72120be13fb1142e93aba2aabb2a4f369826c18219f76e4d0ebddbaa9b744837c2ac65b347673695a23c3cc1a2be4141e1427d735e21025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc0101000000010000000000000000000000000000000000000000000000000000000000000000000000002221025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3ffffffff0100f2052a010000001976a914834e0737cdb9008db614cd95ec98824e952e3dc588ac00000000";
    const TEST_BLOCK_WITH_PUBKEY: &str = "010000000000000000000000000000000000000000000000000000000000000000000000e7c526d0125538b13a50b06465fb8b72120be13fb1142e93aba2aabb2a4f369826c18219f76e4d0ebddbaa9b744837c2ac65b347673695a23c3cc1a2be4141e1427d735e21025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3000101000000010000000000000000000000000000000000000000000000000000000000000000000000002221025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3ffffffff0100f2052a010000001976a914834e0737cdb9008db614cd95ec98824e952e3dc588ac00000000";
    const TEST_BLOCK_WITHOUT_PUBKEY: &str = "010000000000000000000000000000000000000000000000000000000000000000000000e7c526d0125538b13a50b06465fb8b72120be13fb1142e93aba2aabb2a4f369826c18219f76e4d0ebddbaa9b744837c2ac65b347673695a23c3cc1a2be4141e1427d735e00000101000000010000000000000000000000000000000000000000000000000000000000000000000000002221025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3ffffffff0100f2052a010000001976a914834e0737cdb9008db614cd95ec98824e952e3dc588ac00000000";
    const TEST_BLOCK_WITHOUT_PROOF: &str = "010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d000001010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000";

    fn test_block() -> Block {
        let raw_block = hex::decode(TEST_BLOCK).unwrap();
        Block(raw_block)
    }

    fn test_block2() -> Block {
        let raw_block = hex::decode(TEST_BLOCK2).unwrap();
        Block(raw_block)
    }

    fn test_block_with_pubkey() -> Block {
        let raw_block = hex::decode(TEST_BLOCK_WITH_PUBKEY).unwrap();
        Block(raw_block)
    }

    fn test_block_without_pubkey() -> Block {
        let raw_block = hex::decode(TEST_BLOCK_WITHOUT_PUBKEY).unwrap();
        Block(raw_block)
    }

    fn test_block_without_proof() -> Block {
        let raw_block = hex::decode(TEST_BLOCK_WITHOUT_PROOF).unwrap();
        Block(raw_block)
    }

    #[test]
    fn test_get_header_without_proof() {
        let block = test_block();

        let hex_expect = "010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d00";
        let raw_expect = hex::decode(hex_expect).unwrap();

        assert_eq!(block.get_header_without_proof(), &raw_expect[..]);

        let block = test_block_with_pubkey();
        let hex_expect = "010000000000000000000000000000000000000000000000000000000000000000000000e7c526d0125538b13a50b06465fb8b72120be13fb1142e93aba2aabb2a4f369826c18219f76e4d0ebddbaa9b744837c2ac65b347673695a23c3cc1a2be4141e1427d735e21025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3";
        let raw_expect = hex::decode(hex_expect).unwrap();

        assert_eq!(block.get_header_without_proof(), &raw_expect[..]);
    }

    #[test]
    fn test_add_proof() {
        let block = test_block_without_proof();
        let sig_hex = "403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc";

        assert_eq!(block.add_proof(hex::decode(sig_hex).unwrap()), test_block());

        let block = test_block_with_pubkey();
        assert_eq!(
            block.add_proof(hex::decode(sig_hex).unwrap()),
            test_block2()
        );
    }

    #[test]
    fn test_add_aggregated_public_key() {
        let public_key = PublicKey::from_str(
            "025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3",
        )
        .unwrap();
        let block = test_block_without_pubkey().add_aggregated_public_key(public_key);
        assert_eq!(block, test_block_with_pubkey());
    }

    #[test]
    fn test_hash() {
        let block = test_block();
        let hash = block.hash();

        assert_eq!(
            format!("{:?}", hash),
            "Hash(86dbdec1ab22f4d43ef164ea5198bf6d4d96ea6ef97ca2dea97a40657af6d789)"
        );

        let json = serde_json::to_string(&hash).unwrap();
        let deserialize_hash: hash::SHA256Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialize_hash, hash);
    }

    #[test]
    fn test_block_hash_debug_fmt() {
        let block = test_block();
        let hash = block.sighash();

        assert_eq!(
            format!("{:?}", hash),
            "Hash(3d856f50e0718f72bab6516c1ab020ce3390ebc97490b6d2bad4054dc7a40a93)"
        );
    }

    #[test]
    fn test_block_debug_fmt() {
        let block = test_block();

        assert_eq!(format!("{:?}", block), format!("Block({})", TEST_BLOCK));
    }

    #[test]
    fn test_block_serialize() {
        let block = test_block();

        let json = serde_json::to_string(&block).unwrap();
        let deserialize_block: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialize_block, block);
    }
}
