use bitcoin::PublicKey;
use crate::net::{Message, MessageType};

/// Signerの識別子。公開鍵を識別子にする。
pub type SignerID = PublicKey;

pub struct StateContext {
    pub current_state: NodeState,
}

/// When node don't know round status because of just now joining to signer network.
pub enum NodeState {
    Joining,
    Master,
}

// state パターン
pub trait RoundState {
    fn process_candidateblock(&self, payload: &[u8]) -> NodeState;
    fn process_signature(&self, payload: &[u8]) -> NodeState;
    fn process_completedblock(&self, payload: &[u8]) -> NodeState;
    fn process_roundfailure(&self, payload: &[u8]) -> NodeState;
}

///// acts as master node in this round.
//pub struct Master {
//
//}
//
//impl RoundState for Master {
//
//}
//
///// acts as member node in this round.
//pub struct Member {
//    current_master: SignerID,
//}
//
//impl RoundState for Member {
//
//}

impl NodeState {
    pub fn process(&self, message: Message) -> NodeState {
        let processor = &self.to_processor();
        match message.message_type {
            MessageType::Candidateblock => processor.process_candidateblock(&message.payload[..]),
            MessageType::Signature => { processor.process_signature(&message.payload[..]) },
            MessageType::Completedblock => { processor.process_completedblock(&message.payload[..]) },
            MessageType::Roundfailure => { processor.process_roundfailure(&message.payload[..]) },
        }
    }

    fn to_processor(&self) -> Box<dyn RoundState> {
        match self {
            NodeState::Joining => Box::new(RoundStateJoining{}),
            _ => Box::new(RoundStateJoining),
        }
    }
}

impl StateContext {
    pub fn new() -> StateContext {
        StateContext {
            current_state: NodeState::Joining
        }
    }

    pub fn set_state(&mut self, s: NodeState) {
        self.current_state = s;
    }
}

struct RoundStateJoining;

impl RoundState for RoundStateJoining {
    fn process_candidateblock(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }

    fn process_signature(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }

    fn process_completedblock(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }

    fn process_roundfailure(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }
}
