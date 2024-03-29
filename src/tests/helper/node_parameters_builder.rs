use crate::federation::{Federation, Federations};
use crate::signer_node::NodeParameters;
use crate::tests::helper::address;
use crate::tests::helper::keys::TEST_KEYS;
use crate::tests::helper::node_vss::node_vss;
use crate::tests::helper::rpc::MockRpc;
use tapyrus::blockdata::block::XField;
use tapyrus::{Address, PublicKey};

pub struct NodeParametersBuilder {
    rpc: Option<MockRpc>,
    address: Address,
    round_duration: u64,
    round_limit: u64,
    skip_waiting_ibd: bool,
    public_key: PublicKey,
    federations: Federations,
}

impl NodeParametersBuilder {
    /// Returns instance with default value for test.(it not same with production default)
    pub fn new() -> Self {
        Self {
            rpc: None,
            address: address(&TEST_KEYS.key[4]),
            round_duration: 0,
            round_limit: 15,
            skip_waiting_ibd: true,
            public_key: TEST_KEYS.pubkeys()[4],
            federations: Federations::new(vec![Federation::new(
                TEST_KEYS.pubkeys()[1],
                0,
                Some(2),
                Some(node_vss(0)),
                XField::AggregatePublicKey(TEST_KEYS.aggregated()),
                None,
                None,
            )]),
        }
    }

    pub fn build(&mut self) -> NodeParameters<MockRpc> {
        NodeParameters::new(
            self.address.clone(),
            self.public_key,
            self.rpc.take().unwrap_or(MockRpc::new()),
            self.round_duration,
            self.round_limit,
            self.skip_waiting_ibd,
            self.federations.clone(),
        )
    }

    pub fn public_key(&mut self, public_key: PublicKey) -> &mut Self {
        self.public_key = public_key;
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

    pub fn round_limit(&mut self, round_limit: u64) -> &mut Self {
        self.round_limit = round_limit;
        self
    }

    pub fn skip_waiting_ibd(&mut self, skip_waiting_ibd: bool) -> &mut Self {
        self.skip_waiting_ibd = skip_waiting_ibd;
        self
    }

    pub fn federations(&mut self, federations: Federations) -> &mut Self {
        self.federations = federations;
        self
    }
}
