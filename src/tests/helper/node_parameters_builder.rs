use crate::signer_node::NodeParameters;
use crate::tests::helper::address;
use crate::tests::helper::keys::TEST_KEYS;
use crate::tests::helper::rpc::MockRpc;
use bitcoin::{Address, PrivateKey, PublicKey};

pub struct NodeParametersBuilder {
    pubkey_list: Vec<PublicKey>,
    threshold: u8,
    private_key: PrivateKey,
    rpc: Option<MockRpc>,
    address: Address,
    round_duration: u64,
    skip_waiting_ibd: bool,
}

impl NodeParametersBuilder {
    /// Returns instance with default value for test.(it not same with production default)
    pub fn new() -> Self {
        Self {
            pubkey_list: TEST_KEYS.pubkeys(),
            threshold: 3,
            private_key: TEST_KEYS.key[0],
            rpc: None,
            address: address(&TEST_KEYS.key[0]),
            round_duration: 0,
            skip_waiting_ibd: true,
        }
    }

    pub fn build(&mut self) -> NodeParameters<MockRpc> {
        NodeParameters::new(
            self.address.clone(),
            self.pubkey_list.clone(),
            self.private_key,
            self.threshold,
            self.rpc.take().unwrap_or(MockRpc::new()),
            self.round_duration,
            self.skip_waiting_ibd,
        )
    }

    pub fn pubkey_list(&mut self, pubkey_list: Vec<PublicKey>) -> &mut Self {
        self.pubkey_list = pubkey_list;
        self
    }

    pub fn private_key(&mut self, private_key: PrivateKey) -> &mut Self {
        self.private_key = private_key;
        self
    }

    pub fn threshold(&mut self, threshold: u8) -> &mut Self {
        self.threshold = threshold;
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
