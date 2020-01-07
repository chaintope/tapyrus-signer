// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::errors::Error;
use bitcoin_hashes::{sha256d, Hash};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, PartialEq)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    const LEN: usize = 32;

    pub fn from_slice(sl: &[u8]) -> Result<BlockHash, Error> {
        if sl.len() != Self::LEN {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(BlockHash(ret))
        }
    }

    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
    pub fn borrow_inner(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Change byteorder to Big Endian
        let mut rev = self.0.clone();
        rev.reverse();

        let h = hex::encode(rev);
        write!(f, "BlockHash({})", h)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct Block(Vec<u8>);

impl Block {
    const PROOF_POSISION: usize = 105;

    pub fn new(data: Vec<u8>) -> Block {
        Block(data)
    }

    /// Length of block header without proof is 105 bytes.
    /// Version: 4
    /// hasPrevBlock: 32
    /// hashMerkleRoot: 32
    /// hashImMerkleRoot: 32
    /// time: 4
    /// length of aggPubkey: 1
    pub fn get_header_without_proof(&self) -> &[u8] {
        &self.0[..Self::PROOF_POSISION]
    }

    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Returns hash for signing. This hash value doesn't include proof field. Actual block hash
    /// includes proof data.
    pub fn hash_for_sign(&self) -> Result<BlockHash, Error> {
        let header = self.get_header_without_proof();
        let hash = sha256d::Hash::hash(header).into_inner();
        Ok(BlockHash::from_slice(&hash)?)
    }

    pub fn payload(&self) -> &[u8] {
        &self.0
    }
    pub fn add_proof(&self, proof: Vec<u8>) -> Block {
        let (header, txs) = self.payload().split_at(Self::PROOF_POSISION);
        let new_payload = [header, &proof[..], &txs[1..]].concat();
        Block(new_payload)
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = hex::encode(&self.0);
        write!(f, "Block({})", h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BLOCK: &str = "010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d00403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc01010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000";

    fn test_block() -> Block {
        let raw_block = hex::decode(TEST_BLOCK).unwrap();
        Block(raw_block)
    }

    #[test]
    fn test_get_header_without_proof() {
        let block = test_block();

        let hex_expect = "010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d00";
        let raw_expect = hex::decode(hex_expect).unwrap();

        assert_eq!(block.get_header_without_proof(), &raw_expect[..]);
    }

    #[test]
    fn test_add_proof() {
        let hex_block = "010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d000001010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000";
        let raw_block = hex::decode(hex_block).unwrap();
        let block = Block(raw_block);

        let sig_hex = "403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc";

        let hex_expect = "010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d00403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc01010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000";
        let raw_expect = hex::decode(hex_expect).unwrap();
        let expect = Block(raw_expect);

        assert_eq!(block.add_proof(hex::decode(sig_hex).unwrap()), expect);
    }

    #[test]
    fn test_block_hash_debug_fmt() {
        let block = test_block();
        let hash = block.hash_for_sign().unwrap();

        assert_eq!(
            format!("{:?}", hash),
            "BlockHash(3d856f50e0718f72bab6516c1ab020ce3390ebc97490b6d2bad4054dc7a40a93)"
        );
    }

    #[test]
    fn test_block_debug_fmt() {
        let block = test_block();

        assert_eq!(format!("{:?}", block), format!("Block({})", TEST_BLOCK));
    }
}
