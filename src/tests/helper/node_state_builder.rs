use crate::signer_node::node_state::builder::{Master, Member};
use crate::signer_node::BidirectionalSharedSecretMap;
use crate::tests::helper::blocks::get_block;
use std::collections::{BTreeMap, HashSet};

pub trait BuilderForTest {
    fn for_test() -> Self;
}

impl BuilderForTest for Master {
    fn for_test() -> Self {
        Self::new(
            None,
            BidirectionalSharedSecretMap::new(),
            None,
            Some(get_block(0)),
            BTreeMap::new(),
            HashSet::new(),
            false,
        )
    }
}

impl BuilderForTest for Member {
    fn for_test() -> Self {
        Self::new(
            None,
            BidirectionalSharedSecretMap::new(),
            None,
            None,
            HashSet::new(),
            0,
        )
    }
}
