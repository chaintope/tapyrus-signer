use crate::net::{ConnectionManager, RedisManager, MessageType};
use crate::signer::RoundState;
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey};

pub struct SignerNode {
    connection_manager: Box<ConnectionManager>,
    round_state: RoundState,
    params: NodeParameters,
}

impl SignerNode {
    pub fn new(connection_manager: Box<ConnectionManager>, round_state: RoundState, params: NodeParameters) -> SignerNode {
        SignerNode {
            connection_manager,
            round_state,
            params,
        }
    }

    pub fn start(&mut self) {
        self.connection_manager.start(|message| {
            match message.message_type {
                _ => { println!("receive message! {:?}", message); }
//            MessageType::Candidateblock => { self.round_state.process_candidateblock(&self, message.payload) },
//            MessageType::Signature => { self.round_state.process_signature(&self, message.payload) },
//            MessageType::Completedblock => { self.round_state.process_completedblock(&self, message.payload) },
//            MessageType::Roundfailure => { self.round_state.process_roundfailure(&self, message.payload) },
            };

            ControlFlow::Continue
        });
    }
}

pub struct NodeParameters {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u32,
    pub privateKey: PrivateKey,
}
