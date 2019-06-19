use crate::net::{MessageType, Message, SignerID, Signature};
use crate::blockdata::Block;

pub struct StateContext {
    pub current_state: NodeState,
}

/// When node don't know round status because of just now joining to signer network.
#[derive(Debug)]
pub enum NodeState {
    Joining,
    Master,
    Member,
}

impl StateContext {
    pub fn new(current_state: NodeState) -> StateContext {
        StateContext {
            current_state
        }
    }

    pub fn set_state(&mut self, s: NodeState) {
        self.current_state = s;
    }
}

#[cfg(test)]
mod tests {
    use crate::signer_node::{NodeParameters, SignerNode};
    use crate::net::{RedisManager};
    use crate::test_helper::TestKeys;
    use std::thread;
    use crate::signer::NodeState;
    use crate::rpc::Rpc;

    fn setup_node() -> thread::JoinHandle<()> {
        let testkeys = TestKeys::new();
        let pubkey_list = testkeys.pubkeys();
        let threshold = 2;
        let private_key = testkeys.key[0];

        let rpc = Rpc::new("http://localhost:1281".to_string(), Some("user".to_string()), Some("pass".to_string()));
        let params = NodeParameters::new(pubkey_list, private_key, threshold, rpc);
        let con = RedisManager::new();

        let mut node = SignerNode::new(con, params);
        thread::spawn(move || {
            node.start(NodeState::Member);
        })
    }
}