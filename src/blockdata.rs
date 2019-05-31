use bitcoin_hashes::{sha256d, Hash};
use crate::errors::Error;

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

    pub fn into_inner(self) -> [u8; 32] { self.0 }
    pub fn borrow_inner(&self) -> &[u8; 32] { &self.0 }
}

pub struct Block(Vec<u8>);

impl Block {
    pub fn new(data: Vec<u8>) -> Block {
        Block(data)
    }
    /// Length of block header without proof is 104 bytes.
    pub fn get_header_without_proof(&self) -> &[u8] { &self.0[..104] }

    pub fn hex(&self) -> String { hex::encode(&self.0) }

    pub fn hash(&self) -> Result<BlockHash, Error> {
        let header = self.get_header_without_proof();
        let mut hash = sha256d::Hash::hash(header).into_inner();
        Ok(BlockHash::from_slice(&hash)?)
    }
}