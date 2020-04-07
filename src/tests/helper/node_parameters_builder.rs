use crate::crypto::vss::Vss;
use crate::federation::Federations;
use crate::signer_node::NodeParameters;
use crate::tests::helper::address;
use crate::tests::helper::keys::TEST_KEYS;
use crate::tests::helper::node_vss::node_vss;
use crate::tests::helper::rpc::MockRpc;
use bitcoin::{Address, PublicKey};

pub struct NodeParametersBuilder {
    pubkey_list: Vec<PublicKey>,
    threshold: u8,
    rpc: Option<MockRpc>,
    address: Address,
    round_duration: u64,
    skip_waiting_ibd: bool,
    public_key: PublicKey,
    node_vss: Vec<Vss>,
    federations: Federations,
}

impl NodeParametersBuilder {
    /// Returns instance with default value for test.(it not same with production default)
    pub fn new() -> Self {
        Self {
            pubkey_list: TEST_KEYS.pubkeys(),
            threshold: 3,
            rpc: None,
            address: address(&TEST_KEYS.key[0]),
            round_duration: 0,
            skip_waiting_ibd: true,
            public_key: TEST_KEYS.pubkeys()[2],
            node_vss: node_vss(0),
            federations: Federations::new(vec![]),
        }
    }

    pub fn build(&mut self) -> NodeParameters<MockRpc> {
        NodeParameters::new(
            self.address.clone(),
            self.pubkey_list.clone(),
            self.threshold,
            self.public_key,
            self.node_vss.clone(),
            self.rpc.take().unwrap_or(MockRpc::new()),
            self.round_duration,
            self.skip_waiting_ibd,
            self.federations.clone(),
        )
    }

    pub fn pubkey_list(&mut self, pubkey_list: Vec<PublicKey>) -> &mut Self {
        self.pubkey_list = pubkey_list;
        self
    }

    pub fn threshold(&mut self, threshold: u8) -> &mut Self {
        self.threshold = threshold;
        self
    }

    pub fn public_key(&mut self, public_key: PublicKey) -> &mut Self {
        self.public_key = public_key;
        self
    }

    pub fn node_vss(&mut self, node_vss: Vec<Vss>) -> &mut Self {
        self.node_vss = node_vss;
        self
    }

    pub fn rpc(&mut self, rpc: MockRpc) -> &mut Self {
        self.rpc = Some(rpc);
        self
    }

    pub fn address(&mut self, address: Address) -> &mut Self {
        self.address = address;
        self
    }

    pub fn round_duration(&mut self, round_duration: u64) -> &mut Self {
        self.round_duration = round_duration;
        self
    }

    pub fn skip_waiting_ibd(&mut self, skip_waiting_ibd: bool) -> &mut Self {
        self.skip_waiting_ibd = skip_waiting_ibd;
        self
    }
}
