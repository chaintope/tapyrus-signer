// Copyright (c) 2019 Chaintope Inc.

mod message_processor;
pub mod node_parameters;
pub mod node_state;
pub mod utils;

use crate::federation::Federation;
pub use crate::signer_node::node_parameters::NodeParameters;
pub use crate::signer_node::node_state::NodeState;

use crate::errors::Error;
use crate::net::{ConnectionManager, ConnectionManagerError, Message, MessageType, SignerID};
use crate::rpc::{GetBlockchainInfoResult, TapyrusApi};
use crate::signer_node::message_processor::create_block_vss;
use crate::signer_node::message_processor::process_blockparticipants;
use crate::signer_node::message_processor::process_blocksig;
use crate::signer_node::message_processor::process_blockvss;
use crate::signer_node::message_processor::process_candidateblock;
use crate::signer_node::message_processor::process_completedblock;
use crate::signer_node::node_state::builder::{Builder, Master, Member};
use crate::timer::RoundTimeOutObserver;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;
use redis::ControlFlow;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::time::Duration;
use tapyrus::blockdata::block::Block;
use tapyrus::blockdata::block::XField;
use tapyrus::PublicKey;

/// Round interval.
pub static ROUND_INTERVAL_DEFAULT_SECS: u64 = 60;
/// Round time limit delta. Round timeout timer should be little longer than `ROUND_INTERVAL_DEFAULT_SECS`.
pub static ROUND_LIMIT_DEFAULT_SECS: u64 = 15;

pub struct SignerNode<T: TapyrusApi, C: ConnectionManager> {
    connection_manager: C,
    params: NodeParameters<T>,
    current_state: NodeState,
    stop_signal: Option<Receiver<u32>>,
    /// ## Round Limit Timer
    /// If the round duration is over, notify it and go through next round.
    /// The round limit consists from round_interval and round_limit.
    ///
    /// Round timer must follow below rules.
    /// * The timer is started on rounds start only.
    /// * New round is started on only receiving completedblock message
    ///   or previous round is timeout.
    round_limit_timer: RoundTimeOutObserver,

    /// ## Round Interval Timer
    /// The timer will be started when the node starts a round as a Master.
    /// If the timer was up, the node starts round communication with getting a block and sending
    /// candidateblock message.
    round_interval_timer: RoundTimeOutObserver,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SharedSecret {
    pub vss: VerifiableSS,
    pub secret_share: FE,
}

pub type SharedSecretMap = BTreeMap<SignerID, SharedSecret>;

pub type BidirectionalSharedSecretMap = BTreeMap<SignerID, (SharedSecret, SharedSecret)>;

pub trait ToVerifiableSS {
    fn to_vss(&self) -> Vec<VerifiableSS>;
}

impl ToVerifiableSS for SharedSecretMap {
    fn to_vss(&self) -> Vec<VerifiableSS> {
        self.values().map(|i| i.vss.clone()).collect()
    }
}

pub trait ToSharedSecretMap {
    fn for_negative(&self) -> SharedSecretMap;
    fn for_positive(&self) -> SharedSecretMap;
}

impl ToSharedSecretMap for BidirectionalSharedSecretMap {
    fn for_positive(&self) -> SharedSecretMap {
        let mut map = SharedSecretMap::new();
        for (key, value) in self.iter() {
            map.insert(*key, value.0.clone());
        }
        map
    }
    fn for_negative(&self) -> SharedSecretMap {
        let mut map = SharedSecretMap::new();
        for (key, value) in self.iter() {
            map.insert(*key, value.1.clone());
        }
        map
    }
}
pub trait ToShares {
    fn to_shares(&self) -> Vec<FE>;
}

impl ToShares for SharedSecretMap {
    fn to_shares(&self) -> Vec<FE> {
        self.values().map(|i| i.secret_share).collect()
    }
}

static INITIAL_MASTER_INDEX: usize = 0;

impl<T: TapyrusApi, C: ConnectionManager> SignerNode<T, C> {
    pub fn new(connection_manager: C, params: NodeParameters<T>) -> Self
    where
        Self: Sized,
    {
        let timer_limit = params.round_duration + params.round_limit;
        let round_interval = params.round_duration;
        SignerNode {
            connection_manager,
            params,
            current_state: NodeState::Joining,
            stop_signal: None,
            round_limit_timer: RoundTimeOutObserver::new("round_limit_timer", timer_limit),
            round_interval_timer: RoundTimeOutObserver::new("round_interval_timer", round_interval),
        }
    }

    pub fn stop_handler(&mut self, receiver: Receiver<u32>) {
        self.stop_signal = Some(receiver);
    }

    pub fn start(&mut self) {
        if !self.params.skip_waiting_ibd {
            self.wait_for_ibd_finish(std::time::Duration::from_secs(10));
        } else {
            log::info!("Skip waiting for ibd finish.")
        }

        loop {
            match self.connection_manager.test_connection() {
                Ok(_) => {
                    log::debug!("Connection is established.");
                }
                Err(e) => {
                    log::debug!("Can't establish redis connection: {:?}", e);
                    std::thread::sleep(Duration::from_millis(5000));
                    continue;
                }
            }

            let (sender, receiver): (Sender<Message>, Receiver<Message>) = channel();
            let closure = move |message: Message| match sender.send(message) {
                Ok(_) => ControlFlow::Continue,
                Err(error) => {
                    log::warn!("Happened error!: {:?}", error);
                    ControlFlow::Break(())
                }
            };

            let id = self.params.signer_id;
            let handler = self.connection_manager.start(closure, id);

            // Start First Round
            log::info!("Start block creation rounds.");
            self.start_next_round();

            loop {
                match self.handle_signal() {
                    Some(()) => return,
                    None => {}
                }

                self.handle_round_interval_timer();

                // After process when received message. Get message from receiver,
                // then change that state in main thread side.
                self.handle_message(&receiver);

                self.handle_timer();

                match self.handle_connection_error() {
                    Some(_) => break,
                    None => {}
                }

                // Wait for next loop 300 ms.
                std::thread::sleep(Duration::from_millis(300));
            }
            log::info!("Wait for join thread {:?}", handler.thread().id());
            if let Err(e) = handler.join() {
                log::warn!("Failed to join thread {:?}", e);
            }
        }
    }

    /// Check if the node receives signal.
    /// if any signal, stop the round timer.
    fn handle_signal(&mut self) -> Option<()> {
        match &self.stop_signal {
            Some(ref r) => match r.try_recv() {
                Ok(_) => {
                    log::warn!("Stop by Terminate Signal.");
                    self.round_limit_timer.stop();
                    Some(())
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Stop signal is empty. Continue to run. Do nothing.
                    None
                }
                Err(_) => Some(()),
            },
            None => {
                // Stop signal receiver is not set. Do nothing.
                None
            }
        }
    }

    /// Check if the node recieves a new message from other nodes.
    /// if received, process the received message.
    fn handle_message(&mut self, receiver: &Receiver<Message>) {
        // Receiving message.
        match receiver.try_recv() {
            Ok(Message {
                message_type,
                sender_id,
                ..
            }) => {
                log::debug!(
                    "Got {} message from {:?}. MessageType: {:?}",
                    message_type,
                    sender_id,
                    message_type
                );

                let next = self.process_round_message(&sender_id, message_type);
                self.current_state = next;

                if let NodeState::RoundComplete { .. } = &self.current_state {
                    self.start_next_round()
                }

                log::debug!("Current state updated as {:?}", self.current_state);
            }
            Err(TryRecvError::Empty) => {
                // No new messages. Do nothing.
            }
            Err(e) => {
                log::warn!("Can't receive message: {:?}", e);
            }
        }
    }

    /// Check if round timer elapsed
    /// if elapsed, the node start new round.
    fn handle_timer(&mut self) {
        // Checking whether the time limit of a round exceeds.
        match self.round_limit_timer.receiver.try_recv() {
            Ok(_) => {
                // Round duration is timeout. Starting next round.
                self.start_next_round();
                log::debug!("Current state updated as {:?}", self.current_state);
            }
            Err(TryRecvError::Empty) => {
                // Still waiting round duration interval. Do nothing.
            }
            Err(e) => log::warn!("Round timer generates an error: {:?}", e),
        }
    }

    /// Check if round interval timer elapsed
    /// If elapsed, the node start round communication.
    fn handle_round_interval_timer(&mut self) {
        // Checking whether the time limit of a round exceeds.
        match self.round_interval_timer.receiver.try_recv() {
            Ok(_) => {
                // Round interval is timeout.
                if let NodeState::Master { block_height, .. } = self.current_state {
                    self.current_state = self.start_round_communication(block_height);
                    log::debug!("Current state updated as {:?}", self.current_state);
                }
            }
            Err(TryRecvError::Empty) => {
                // Still waiting round interval. Do nothing.
            }
            Err(e) => log::warn!("Round interval timer generates an error: {:?}", e),
        }
    }

    /// Check connection to redis server.
    fn handle_connection_error(&mut self) -> Option<ConnectionManagerError<C::ERROR>> {
        // Checking network connection error
        match self.connection_manager.take_error() {
            Ok(e) => {
                log::error!("Connection Manager Error {:?}", e);
                Some(e)
            }
            Err(TryRecvError::Empty) => {
                // No errors.
                None
            }
            Err(e) => {
                log::warn!("Connection manager can't send error: {:?}", e);
                None
            }
        }
    }
    /// Signer Node waits for connected Tapyrus Core Node complete IBD(Initial Block Download).
    fn wait_for_ibd_finish(&self, interval: Duration) {
        log::info!("Waiting finish Initial Block Download ...");
        log::info!("If you start right away, you can set `--skip-waiting-ibd` option. ");

        loop {
            match self
                .params
                .rpc
                .getblockchaininfo()
                .expect("RPC connection failed")
            {
                GetBlockchainInfoResult {
                    initialblockdownload: false,
                    ..
                } => {
                    break;
                }
                GetBlockchainInfoResult {
                    initialblockdownload: true,
                    blocks: height,
                    bestblockhash: hash,
                    ..
                } => {
                    log::info!("Waiting for finish Initial Block Download. Current block height: {}, current best hash: {}", height, hash);
                }
            }
            std::thread::sleep(interval);
        }
    }

    fn start_new_round(&mut self, block_height: u32) -> NodeState {
        self.round_interval_timer.restart().unwrap();
        Master::default().block_height(block_height).build()
    }

    /// A master node of the round starts a round communication with sending candidateblock message.
    pub fn start_round_communication(&mut self, block_height: u32) -> NodeState {
        let pending_federation_change = self
            .params
            .get_federation_change_for_block_height(block_height + 1); // block_height + 1 so that xfield expected in the next block is added in this block.

        let block = match pending_federation_change {
            Some(x) => match self.params.rpc.getnewblockwithxfield(
                &self.params.address,
                &0,
                &x.clone().xfield(),
            ) {
                Ok(block) => block,
                Err(e) => {
                    log::error!("RPC getnewblockwithxfield failed. reason={:?}", e);
                    return Master::default().block_height(block_height).build();
                }
            },
            None => match self.params.rpc.getnewblock(&self.params.address) {
                Ok(block) => block,
                Err(e) => {
                    log::error!("RPC getnewblock failed. reason={:?}", e);
                    return Master::default().block_height(block_height).build();
                }
            },
        };

        match self.verify_block(&block) {
            Ok(_) => {} // If the block is valid, continue with the rest of your code
            Err(e) => {
                log::error!("Invalid block. reason={:?}", e);
                return Master::default().block_height(block_height).build();
            }
        };

        //let block = self.add_aggregated_public_key_if_needed(block_height, block);
        log::info!(
            "Broadcast candidate block. block hash for signing: {:?}",
            block.header.signature_hash()
        );
        self.connection_manager.broadcast_message(Message {
            message_type: MessageType::Candidateblock(block.clone()),
            sender_id: self.params.signer_id,
            receiver_id: None,
        });

        let (keys, shared_secret_for_positive, shared_secret_for_negative) = create_block_vss(
            block.clone(),
            &self.params,
            &self.connection_manager,
            block_height,
        );

        Master::default()
            .candidate_block(Some(block))
            .block_key(Some(keys.u_i))
            .insert_shared_block_secrets(
                self.params.signer_id.clone(),
                shared_secret_for_positive,
                shared_secret_for_negative,
            )
            .block_height(block_height)
            .build()
    }

    /// Returns true if the signer passed as an argument is a member of current federation.
    fn is_federation_member(&self, signer_id: &SignerID) -> bool {
        let block_height = self.current_state.block_height();
        let federation = self.params.get_federation_by_block_height(block_height);
        federation.signers().contains(signer_id)
    }

    pub fn process_round_message(
        &mut self,
        sender_id: &SignerID,
        message: MessageType,
    ) -> NodeState {
        if let NodeState::Idling { .. } = &self.current_state {
            return self.current_state.clone();
        }

        // Check the node, which sent the message is a member of the current federation.
        if !self.is_federation_member(sender_id) {
            return self.current_state.clone();
        }

        match message {
            MessageType::Candidateblock(block) => process_candidateblock(
                &sender_id,
                &block,
                &self.current_state,
                &self.connection_manager,
                &self.params,
            ),
            MessageType::Completedblock(block) => {
                process_completedblock(&sender_id, &block, &self.current_state, &self.params)
            }
            MessageType::Blockvss(
                blockhash,
                vss_for_positive,
                secret_share_for_positive,
                vss_for_negative,
                secret_share_for_negative,
            ) => process_blockvss(
                &sender_id,
                blockhash,
                vss_for_positive,
                secret_share_for_positive,
                vss_for_negative,
                secret_share_for_negative,
                &self.current_state,
                &self.connection_manager,
                &self.params,
            ),
            MessageType::Blockparticipants(blockhash, participants) => process_blockparticipants(
                &sender_id,
                blockhash,
                participants,
                &self.current_state,
                &self.connection_manager,
                &self.params,
            ),
            MessageType::Blocksig(blockhash, gamma_i, e) => process_blocksig(
                &sender_id,
                blockhash,
                gamma_i,
                e,
                &self.current_state,
                &self.connection_manager,
                &self.params,
            ),
        }
    }

    /// Start next round.
    /// decide master of next round according to Round-robin.
    fn start_next_round(&mut self) {
        self.round_limit_timer.restart().unwrap();

        // Get a block height at next of the tip block.
        let (block_height, block_hash, aggregatedpubkeys, maxblocksizes) =
            match self.params.rpc.getblockchaininfo() {
                Ok(GetBlockchainInfoResult {
                    blocks: block_height,
                    bestblockhash: block_hash,
                    aggregate_pubkeys: aggregatedpubkeys,
                    max_block_sizes: maxblocksizes,
                    ..
                }) => (
                    block_height + 1,
                    block_hash,
                    aggregatedpubkeys,
                    maxblocksizes,
                ),
                _ => (
                    match self.current_state {
                        NodeState::Idling { block_height } => block_height + 1,
                        NodeState::RoundComplete { block_height, .. } => block_height + 1,
                        // The case, which the node state is Member or Master, means that previous round
                        // was failure. If it was success, the state should be RoundComplete. So, the block
                        // height is not incremented here.
                        NodeState::Member { block_height, .. } => block_height,
                        NodeState::Master { block_height, .. } => block_height,
                        NodeState::Joining => {
                            panic!("Couldn't start the node because of an RPC connection error.")
                        }
                    },
                    "".to_string(),
                    vec![],
                    vec![],
                ),
            };

        // we get the expected federation at block_height  for logging
        let expected_xfield_change = self
            .params
            .get_federation_change_for_block_height(block_height);

        if expected_xfield_change.is_some() {
            log_xfield_from_blockchaininfo(
                expected_xfield_change.unwrap(),
                aggregatedpubkeys,
                maxblocksizes,
                block_hash,
                block_height,
            );
        }

        let federation = self.params.get_federation_by_block_height(block_height);
        if !federation.is_member() {
            log::info!(
                "Start next round: self_index=None, master_index=None. Idling because the node is not a member of the current federation when the block height is {}.",
                block_height,
            );
            self.current_state = NodeState::Idling { block_height };
            return;
        }

        let next_master_index = next_master_index(&self.current_state, &self.params, block_height);

        log::info!(
            "Start next round: target_block_height={}, self_index={}, master_index={}",
            block_height,
            self.params.self_node_index(block_height),
            next_master_index,
        );

        if self.params.self_node_index(block_height) == next_master_index {
            self.current_state = self.start_new_round(block_height);
        } else {
            self.current_state = Member::default()
                .master_index(next_master_index)
                .block_height(block_height)
                .build();
        }
    }

    fn verify_block(&self, block: &Block) -> Result<(), Error> {
        // master node accepts the block that has xfield change matching its federation.toml
        let block_height = self.current_state.block_height();
        let xfield = block.header.xfield.clone();
        let expected_federation = self
            .params
            .get_federation_change_for_block_height(block_height + 1);

        Federation::match_xfield_with_federation(block_height, xfield, expected_federation)
    }
}

fn log_xfield_from_blockchaininfo(
    expected_xfield_change: &Federation,
    aggregatedpubkeys: Vec<HashMap<PublicKey, u32>>,
    maxblocksizes: Vec<HashMap<u32, u32>>,
    block_hash: String,
    block_height: u32,
) {
    let xfield_aggregatepubkey = aggregatedpubkeys
        .iter()
        .flat_map(|map| map.iter())
        .find(|&(_, &height)| height == block_height)
        .map(|(&data, _)| data);

    let xfield_maxblocksize = maxblocksizes
        .iter()
        .flat_map(|map| map.iter())
        .find(|&(_, &height)| height == block_height)
        .map(|(&data, _)| data);

    match expected_xfield_change.xfield() {
        XField::None => {
            if xfield_maxblocksize.is_some() || xfield_aggregatepubkey.is_some() {
                log::warn!("Xfield was not expected in block {} at height {} according to federations.toml.", block_hash, block_height);
            }
        }
        XField::Unknown(_, _) => {
            log::warn!(
                "Unknown Xfield at height {} in federations.toml.",
                block_height
            );
        }
        XField::AggregatePublicKey(key) => {
            if xfield_aggregatepubkey.is_some() && *key == xfield_aggregatepubkey.unwrap() {
                log::info!(
                    "Xfield Aggregated pubkey was set in block {} at height {} as expected.",
                    block_hash,
                    block_height
                )
            } else {
                log::warn!(
                    "Xfield Aggregated pubkey was set in block {} at height {} was NOT expected.",
                    block_hash,
                    block_height
                )
            }
        }
        XField::MaxBlockSize(size) => {
            if xfield_maxblocksize.is_some() && *size == xfield_maxblocksize.unwrap() {
                log::info!(
                    "Xfield Max block size was set in block {} at height {} as expected.",
                    block_hash,
                    block_height
                )
            } else {
                log::warn!(
                    "Xfield Max block size was set in block {} at height {} was NOT expected.",
                    block_hash,
                    block_height
                )
            }
        }
    }
}

pub fn master_index<T>(state: &NodeState, params: &NodeParameters<T>) -> Option<usize>
where
    T: TapyrusApi,
{
    match state {
        NodeState::Master { .. } => Some(params.self_node_index(state.block_height())),
        NodeState::Member { master_index, .. } => Some(*master_index),
        NodeState::RoundComplete { master_index, .. } => Some(*master_index),
        _ => None,
    }
}

/// Returns master index of next round. If the node is not a member in the federation of the next
/// round, it raises a panic. So you should check it before calling this function.
/// This function is called when the next round about to start.
///
/// # Arguments
///
/// * `state` - A node state of the previous round.
/// * `params` - Node Parameters
/// * `target_block_height` - A target block height at a round, which about to start.
fn next_master_index<T>(
    state: &NodeState,
    params: &NodeParameters<T>,
    target_block_height: u32,
) -> usize
where
    T: TapyrusApi,
{
    let next_index = match state {
        NodeState::Joining => return INITIAL_MASTER_INDEX,
        NodeState::Idling { .. } => return INITIAL_MASTER_INDEX,
        NodeState::Master { .. } => params.self_node_index(state.block_height()) + 1,
        NodeState::Member { master_index, .. } => master_index + 1,
        NodeState::RoundComplete { master_index, .. } => master_index + 1,
    };

    next_index % params.pubkey_list(target_block_height).len()
}

pub fn is_master<T>(sender_id: &SignerID, state: &NodeState, params: &NodeParameters<T>) -> bool
where
    T: TapyrusApi,
{
    match state {
        NodeState::Master { .. } => params.signer_id == *sender_id,
        NodeState::Member {
            master_index,
            block_height,
            ..
        } => {
            let master_id = params.pubkey_list(*block_height)[*master_index];
            master_id == sender_id.pubkey
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::errors;
    use crate::federation::{Federation, Federations};
    use crate::net::{ConnectionManager, ConnectionManagerError, Message, SignerID};
    use crate::rpc::tests::{safety, MockRpc};
    use crate::rpc::TapyrusApi;
    use crate::signer_node::{
        master_index, BidirectionalSharedSecretMap, NodeParameters, NodeState, SignerNode,
    };
    use crate::tests::helper::blocks::get_block;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::node_vss::node_vss;
    use crate::tests::helper::{address, enable_log};
    use redis::ControlFlow;
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::Arc;
    use std::thread;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use tapyrus::blockdata::block::{Block, XField};
    use tapyrus::consensus::encode::deserialize;
    use tapyrus::PublicKey;

    pub type SpyMethod = Box<dyn Fn(Arc<Message>) -> () + Send + 'static>;

    /// ConnectionManager for testing.
    pub struct TestConnectionManager {
        /// This is count of messages. TestConnectionManager waits for receiving the number of message.
        pub receive_count: u32,
        /// sender of message
        pub sender: Sender<Message>,
        /// receiver of message
        pub receiver: Receiver<Message>,
        /// A function which is called when the node try to broadcast messages.
        pub broadcast_assert: SpyMethod,
    }

    impl TestConnectionManager {
        pub fn new(receive_count: u32, broadcast_assert: SpyMethod) -> Self {
            let (sender, receiver): (Sender<Message>, Receiver<Message>) = channel();
            TestConnectionManager {
                receive_count,
                sender,
                receiver,
                broadcast_assert,
            }
        }
    }

    impl ConnectionManager for TestConnectionManager {
        type ERROR = crate::errors::Error;
        fn broadcast_message(&self, message: Message) {
            let rc_message = Arc::new(message);
            (self.broadcast_assert)(rc_message.clone());
        }

        fn send_message(&self, message: Message) {
            let rc_message = Arc::new(message);
            (self.broadcast_assert)(rc_message.clone());
        }

        fn start(
            &self,
            mut message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static,
            _id: SignerID,
        ) -> JoinHandle<()> {
            for _count in 0..self.receive_count {
                match self.receiver.recv() {
                    Ok(message) => {
                        log::debug!("Test message receiving!! {:?}", message.message_type);
                        message_processor(message);
                    }
                    Err(e) => log::warn!("happend receiver error: {:?}", e),
                }
            }
            thread::Builder::new()
                .name("TestConnectionManager start Thread".to_string())
                .spawn(|| {
                    thread::sleep(Duration::from_millis(300));
                })
                .unwrap()
        }

        fn test_connection(&self) -> Result<(), errors::Error> {
            Ok(())
        }

        fn take_error(
            &mut self,
        ) -> Result<ConnectionManagerError<Self::ERROR>, std::sync::mpsc::TryRecvError> {
            let (_, r) = channel();
            r.try_recv()
        }
    }

    fn create_node<T: TapyrusApi>(
        current_state: NodeState,
        rpc: T,
        federations: Option<Federations>,
    ) -> SignerNode<T, TestConnectionManager> {
        let closure: SpyMethod = Box::new(move |_message: Arc<Message>| {});
        let (node, _) =
            create_node_with_closure_and_publish_count(current_state, rpc, closure, 1, federations);
        node
    }

    fn create_node_with_closure_and_publish_count<T: TapyrusApi>(
        current_state: NodeState,
        rpc: T,
        spy: SpyMethod,
        publish_count: u32,
        federations: Option<Federations>,
    ) -> (SignerNode<T, TestConnectionManager>, Sender<Message>) {
        let pubkey_list = TEST_KEYS.pubkeys();
        let threshold = Some(3);
        let private_key = TEST_KEYS.key[4];
        let to_address = address(&private_key);
        let public_key = pubkey_list[4].clone();
        let aggregated_public_key = TEST_KEYS.aggregated();
        let federations = federations.unwrap_or(Federations::new(vec![Federation::new(
            public_key,
            0,
            threshold,
            Some(node_vss(0)),
            XField::AggregatePublicKey(aggregated_public_key),
            None,
            None,
        )]));

        let mut params = NodeParameters::new(to_address, public_key, rpc, 0, 10, true, federations);
        params.round_duration = 0;
        let con = TestConnectionManager::new(publish_count, spy);
        let broadcaster = con.sender.clone();
        let mut node = SignerNode::new(con, params);
        node.current_state = current_state;
        (node, broadcaster)
    }

    fn get_invalid_block() -> Block {
        const TEST_BLOCK_WITH_UNKNOWN_XFIELD: &str = "010000000000000000000000000000000000000000000000000000000000000000000000e7c526d0125538b13a50b06465fb8b72120be13fb1142e93aba2aabb2a4f369826c18219f76e4d0ebddbaa9b744837c2ac65b347673695a23c3cc1a2be4141e1427d735efffd2602ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000101000000010000000000000000000000000000000000000000000000000000000000000000000000002221025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3ffffffff0100f2052a010000001976a914834e0737cdb9008db614cd95ec98824e952e3dc588ac00000000";
        let raw_block = hex::decode(TEST_BLOCK_WITH_UNKNOWN_XFIELD).unwrap();
        deserialize(&raw_block).unwrap()
    }

    #[test]
    fn test_is_federation_member() {
        let public_key = TEST_KEYS.pubkeys()[4];
        let arc_block = safety(get_block(0));
        let rpc = MockRpc {
            return_block: arc_block.clone(),
        };
        let node = create_node(
            NodeState::Member {
                block_key: None,
                block_shared_keys: None,
                shared_block_secrets: BidirectionalSharedSecretMap::new(),
                candidate_block: None,
                participants: HashSet::new(),
                master_index: 0,
                block_height: 0,
            },
            rpc,
            None,
        );
        let result = node.is_federation_member(&SignerID::new(public_key));
        assert!(result);

        // This signer is not member of the federation.
        let public_key = PublicKey::from_str(
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
        )
        .unwrap();
        let result = node.is_federation_member(&SignerID::new(public_key));
        assert!(!result);
    }

    #[test]
    fn test_timeout_roundrobin() {
        enable_log(None);
        let closure: SpyMethod = Box::new(move |_message: Arc<Message>| {});
        let initial_state = NodeState::Joining;
        let arc_block = safety(get_block(0));
        let rpc = MockRpc {
            return_block: arc_block.clone(),
        };
        let (mut node, _broadcaster) =
            create_node_with_closure_and_publish_count(initial_state, rpc, closure, 0, None);

        let (stop_signal, stop_handler): (Sender<u32>, Receiver<u32>) = channel();
        node.stop_handler(stop_handler);

        let ss = stop_signal.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(16)); // 16s = 1 round (15s) + 1s
            ss.send(1).unwrap();
        });
        node.start();

        assert_eq!(master_index(&node.current_state, &node.params).unwrap(), 1);
    }

    #[test]
    fn test_start_next_round() {
        let arc_block = safety(get_block(0));
        let rpc = MockRpc {
            return_block: arc_block.clone(),
        };
        let mut node = create_node(
            NodeState::Member {
                block_key: None,
                block_shared_keys: None,
                shared_block_secrets: BidirectionalSharedSecretMap::new(),
                candidate_block: None,
                participants: HashSet::new(),
                master_index: 0,
                block_height: 0,
            },
            rpc,
            None,
        );

        assert_eq!(master_index(&node.current_state, &node.params).unwrap(), 0);

        node.start_next_round();
        assert_eq!(master_index(&node.current_state, &node.params).unwrap(), 1);

        // When the state is Joining, next round should be started as first round, so that,
        // the master index is 0.
        node.current_state = NodeState::Joining;
        node.start_next_round();
        assert_eq!(master_index(&node.current_state, &node.params).unwrap(), 0);
    }

    #[test]
    fn test_verify_block() {
        let arc_block = safety(get_block(0));
        let rpc = MockRpc {
            return_block: arc_block.clone(),
        };
        let node = create_node(
            NodeState::Member {
                block_key: None,
                block_shared_keys: None,
                shared_block_secrets: BidirectionalSharedSecretMap::new(),
                candidate_block: None,
                participants: HashSet::new(),
                master_index: 0,
                block_height: 0,
            },
            rpc,
            None,
        );
        assert!(node.verify_block(&get_block(0)).is_ok());

        assert!(node.verify_block(&get_invalid_block()).is_err());
    }

    mod test_for_waiting_ibd_finish {
        use crate::errors::Error;
        use crate::rpc::{GetBlockchainInfoResult, TapyrusApi};
        use crate::signer_node::tests::create_node;
        use crate::signer_node::{BidirectionalSharedSecretMap, NodeState};
        use std::cell::Cell;
        use std::collections::HashSet;
        use tapyrus::blockdata::block::Block;
        use tapyrus::Address;

        struct MockRpc {
            pub results: [GetBlockchainInfoResult; 2],
            pub call_count: Cell<usize>,
        }

        impl TapyrusApi for MockRpc {
            fn getnewblockwithxfield(
                &self,
                _address: &Address,
                _required_age: &u32,
                _xfield: &tapyrus::blockdata::block::XField,
            ) -> Result<Block, Error> {
                unimplemented!()
            }

            fn getnewblock(&self, _address: &Address) -> Result<Block, Error> {
                unimplemented!()
            }

            fn testproposedblock(&self, _block: &Block) -> Result<bool, Error> {
                unimplemented!()
            }

            fn submitblock(&self, _block: &Block) -> Result<(), Error> {
                unimplemented!()
            }

            fn getblockchaininfo(&self) -> Result<GetBlockchainInfoResult, Error> {
                let result = self.results[self.call_count.get()].clone();

                self.call_count.set(self.call_count.get() + 1);

                Ok(result)
            }
        }

        #[test]
        fn test_wait_for_ibd_finish() {
            let json = serde_json::from_str("{\"chain\": \"test\", \"blocks\": 26826, \"headers\": 26826, \"bestblockhash\": \"7303687fb5d80781bd9fece466e76d97a94613d409d127030ff7f34081a899f7\", \"mediantime\": 1568103315, \"verificationprogress\": 1, \"initialblockdownload\": false, \"size_on_disk\": 11669126,  \"pruned\": false,  \"bip9_softforks\": {    \"csv\": {      \"status\": \"failed\",      \"startTime\": 1456790400, \"timeout\": 1493596800, \"since\": 2016 }, \"segwit\": { \"status\": \"failed\", \"startTime\": 1462060800, \"timeout\": 1493596800, \"since\": 2016 }},  \"aggregate_pubkeys\": [], \"max_block_sizes\": [], \"warnings\": \"\"}").unwrap();
            let mut result1 = serde_json::from_value::<GetBlockchainInfoResult>(json).unwrap();
            result1.initialblockdownload = true;
            let mut result2 = result1.clone();
            result2.initialblockdownload = false;

            let rpc = MockRpc {
                results: [result1, result2],
                call_count: Cell::new(0),
            };

            let node = create_node(
                NodeState::Member {
                    block_key: None,
                    block_shared_keys: None,
                    shared_block_secrets: BidirectionalSharedSecretMap::new(),
                    candidate_block: None,
                    participants: HashSet::new(),
                    master_index: 0,
                    block_height: 0,
                },
                rpc,
                None,
            );

            node.wait_for_ibd_finish(std::time::Duration::from_millis(1));

            let rpc = node.params.rpc.clone();
            assert_eq!(rpc.call_count.get(), 2);
        }
    }
}
