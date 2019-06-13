use crate::net::{ConnectionManager, RedisManager, MessageType};
use crate::signer::{RoundState, StateContext, Joining};
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey};

pub struct SignerNode<T: ConnectionManager, S: RoundState> {
    connection_manager: T,
    round_state: S,
    params: NodeParameters,
}

impl SignerNode<T, S> {
    pub fn new(connection_manager: T, round_state: S, params: NodeParameters) -> SignerNode {
        SignerNode {
            connection_manager,
            round_state,
            params,
        }
    }

    pub fn start(&mut self) {
        let mut round_state: S = Joining{};

        self.connection_manager.start(|message| {
            round_state = match message.message_type {
                MessageType::Candidateblock => { round_state.process_candidateblock(&message.payload[..]) },
                MessageType::Signature => { round_state.process_signature(&message.payload[..]) },
                MessageType::Completedblock => { round_state.process_completedblock(&message.payload[..]) },
                MessageType::Roundfailure => { round_state.process_roundfailure(&message.payload[..]) },
            };

            ControlFlow::Continue
        });
    }
}

impl StateContext for &mut SignerNode<T, S> {
    fn setState(&mut self, state: S) {
        self.round_state = state;
    }
}

pub struct NodeParameters {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u32,
    pub privateKey: PrivateKey,
}
