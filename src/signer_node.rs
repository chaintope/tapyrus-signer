use crate::net::{ConnectionManager, Message, MessageType, SignerID, Signature};
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey, Address};
use crate::rpc::Rpc;
use std::sync::mpsc::{channel, Sender, Receiver};
use crate::blockdata::Block;
use crate::sign::sign;

pub struct SignerNode<T: ConnectionManager> {
    connection_manager: T,
    params: NodeParameters,
    current_state: NodeState,
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NodeState {
    Joining,
    Master,
    Member,
}

impl<T: ConnectionManager> SignerNode<T> {
    pub fn new(connection_manager: T, params: NodeParameters, current_state: NodeState) -> SignerNode<T> {
        SignerNode {
            connection_manager,
            params,
            current_state,
        }
    }

    pub fn start(&mut self) {
        let (sender, receiver): (Sender<Message>, Receiver<Message>) = channel();
        let closure = move |message: Message| {
            match sender.send(message) {
                Ok(_) => ControlFlow::Continue,
                Err(error) => {
                    println!("Happened error!: {:?}", error);
                    ControlFlow::Break(())
                }
            }
        };

        let _handler = self.connection_manager.start(closure);
        if self.current_state == NodeState::Master {
            // TODO: pseudo-implementation.
            let block = self.params.rpc.getnewblock(&self.params.address).unwrap();
            self.connection_manager.broadcast_message(Message {
                message_type: MessageType::Candidateblock(block),
                sender_id: self.params.signer_id,
            })
        };

        loop {
            // After process when received message. Get message from receiver,
            // then change that state in main thread side.
            // messageを受け取った後の処理。receiverからmessageを受け取り、
            // stateの変更はmain thread側で行う。
            let msg = receiver.recv().unwrap();
            let next = self.process_message(msg);
            self.current_state = next;
        }
    }

    pub fn process_message(&self, message: Message) -> NodeState {
        match message.message_type {
            MessageType::Candidateblock(block) => {
                self.process_candidateblock(&message.sender_id, &block)
            }
            MessageType::Signature(sig) => {
                self.process_signature(&message.sender_id, &sig)
            }
            MessageType::Completedblock(block) => {
                self.process_completedblock(&message.sender_id, &block)
            }
            MessageType::Roundfailure => {
                self.process_roundfailure(&message.sender_id)
            }
        }
    }

    fn process_candidateblock(&self, sender_id: &SignerID, block: &Block) -> NodeState {
        match self.current_state {
            NodeState::Member => {
                let block_hash = block.hash().unwrap();
                let sig = sign(&self.params.private_key, &block_hash);
                self.connection_manager.broadcast_message(Message {
                    message_type: MessageType::Signature(crate::net::Signature(sig)),
                    sender_id: self.params.signer_id,
                });
            }
            _ => {}
        };

        self.current_state
    }


    fn process_signature(&self, sender_id: &SignerID, signature: &Signature) -> NodeState {
        unimplemented!()
    }

    fn process_completedblock(&self, sender_id: &SignerID, block: &Block) -> NodeState {
        unimplemented!()
    }

    fn process_roundfailure(&self, sender_id: &SignerID) -> NodeState {
        unimplemented!()
    }
}

pub struct NodeParameters {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u32,
    pub private_key: PrivateKey,
    pub rpc: Rpc,
    pub address: Address,
    pub signer_id: SignerID,
}

impl NodeParameters {
    pub fn new(pubkey_list: Vec<PublicKey>, private_key: PrivateKey, threshold: u32, rpc: Rpc) -> NodeParameters {
        let secp = secp256k1::Secp256k1::new();
        let self_pubkey = private_key.public_key(&secp);
        let address = Address::p2pkh(&self_pubkey, private_key.network);
        let signer_id = SignerID { pubkey: self_pubkey };
        NodeParameters {
            pubkey_list,
            threshold,
            private_key,
            rpc,
            address,
            signer_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::signer_node::{NodeParameters, SignerNode, NodeState};
    use crate::net::{RedisManager};
    use crate::test_helper::TestKeys;
    use std::thread;
    use crate::rpc::Rpc;

    fn setup_node() -> thread::JoinHandle<()> {
        let testkeys = TestKeys::new();
        let pubkey_list = testkeys.pubkeys();
        let threshold = 2;
        let private_key = testkeys.key[0];

        let rpc = Rpc::new("http://localhost:1281".to_string(), Some("user".to_string()), Some("pass".to_string()));
        let params = NodeParameters::new(pubkey_list, private_key, threshold, rpc);
        let con = RedisManager::new();

        let mut node = SignerNode::new(con, params, NodeState::Member);
        thread::spawn(move || {
            node.start();
        })
    }
}
