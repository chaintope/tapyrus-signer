use crate::blockdata::Block;
use crate::net::SignerID;
use crate::signer_node::{BidirectionalSharedSecretMap, NodeState};
use crate::tests::helper::blocks::get_block;
use curv::{FE, GE};
use std::collections::BTreeMap;

pub trait Builder {
    fn new() -> Self;
    fn build(&self) -> NodeState;
}

pub struct Master {
    block_key: Option<FE>,
    shared_block_secrets: BidirectionalSharedSecretMap,
    block_shared_keys: Option<(bool, FE, GE)>,
    candidate_block: Block,
    signatures: BTreeMap<SignerID, (FE, FE)>,
    round_is_done: bool,
}

impl Builder for Master {
    fn new() -> Self {
        Self {
            block_key: None,
            shared_block_secrets: BidirectionalSharedSecretMap::new(),
            block_shared_keys: None,
            candidate_block: get_block(0),
            signatures: BTreeMap::new(),
            round_is_done: false,
        }
    }

    fn build(&self) -> NodeState {
        NodeState::Master {
            block_key: self.block_key.clone(),
            shared_block_secrets: self.shared_block_secrets.clone(),
            block_shared_keys: self.block_shared_keys.clone(),
            candidate_block: self.candidate_block.clone(),
            signatures: self.signatures.clone(),
            round_is_done: self.round_is_done,
        }
    }
}

impl Master {
    pub fn block_key(&mut self, block_key: Option<FE>) -> &mut Self {
        self.block_key = block_key;
        self
    }

    pub fn shared_block_secrets(
        &mut self,
        shared_block_secrets: BidirectionalSharedSecretMap,
    ) -> &mut Self {
        self.shared_block_secrets = shared_block_secrets;
        self
    }

    pub fn block_shared_keys(&mut self, block_shared_keys: Option<(bool, FE, GE)>) -> &mut Self {
        self.block_shared_keys = block_shared_keys;
        self
    }

    pub fn candidate_block(&mut self, candidate_block: Block) -> &mut Self {
        self.candidate_block = candidate_block;
        self
    }

    pub fn signatures(&mut self, signatures: BTreeMap<SignerID, (FE, FE)>) -> &mut Self {
        self.signatures = signatures;
        self
    }

    pub fn round_is_done(&mut self, round_is_done: bool) -> &mut Self {
        self.round_is_done = round_is_done;
        self
    }
}

pub struct Member {
    block_key: Option<FE>,
    shared_block_secrets: BidirectionalSharedSecretMap,
    block_shared_keys: Option<(bool, FE, GE)>,
    candidate_block: Option<Block>,
    master_index: usize,
}

impl Builder for Member {
    fn new() -> Self {
        Self {
            block_key: None,
            shared_block_secrets: BidirectionalSharedSecretMap::new(),
            block_shared_keys: None,
            candidate_block: None,
            master_index: 0,
        }
    }

    fn build(&self) -> NodeState {
        NodeState::Member {
            block_key: self.block_key.clone(),
            shared_block_secrets: self.shared_block_secrets.clone(),
            block_shared_keys: self.block_shared_keys.clone(),
            candidate_block: self.candidate_block.clone(),
            master_index: self.master_index,
        }
    }
}

impl Member {
    pub fn block_key(&mut self, block_key: Option<FE>) -> &mut Self {
        self.block_key = block_key;
        self
    }

    pub fn shared_block_secrets(
        &mut self,
        shared_block_secrets: BidirectionalSharedSecretMap,
    ) -> &mut Self {
        self.shared_block_secrets = shared_block_secrets;
        self
    }

    pub fn block_shared_keys(&mut self, block_shared_keys: Option<(bool, FE, GE)>) -> &mut Self {
        self.block_shared_keys = block_shared_keys;
        self
    }

    pub fn candidate_block(&mut self, candidate_block: Option<Block>) -> &mut Self {
        self.candidate_block = candidate_block;
        self
    }

    pub fn master_index(&mut self, master_index: usize) -> &mut Self {
        self.master_index = master_index;
        self
    }
}
