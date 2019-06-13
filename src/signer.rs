use bitcoin::PublicKey;
use std::collections::HashMap;

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
    fn process_signature(&self, payload: &[u8]) -> Box<RoundState>;
    fn process_completedblock(&self, payload: &[u8]) -> Box<RoundState>;
    fn process_roundfailure(&self, payload: &[u8]) -> Box<RoundState>;
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
    pub fn process(&self) -> Box<RoundState> {
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
    fn process_candidateblock(&self, payload: &[u8]) -> NodeState {
        unimplemented!()
    }

    fn process_signature(&self, payload: &[u8]) -> Box<RoundState> {
        unimplemented!()
    }

    fn process_completedblock(&self, payload: &[u8]) -> Box<RoundState> {
        unimplemented!()
    }

    fn process_roundfailure(&self, payload: &[u8]) -> Box<RoundState> {
        unimplemented!()
    }
}
