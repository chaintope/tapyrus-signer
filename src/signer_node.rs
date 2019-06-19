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
    stop_signal: Option<Receiver<u32>>,
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
            stop_signal: None,
        }
    }

    pub fn stop_handler(&mut self, receiver: Receiver<u32>) {
        self.stop_signal = Some(receiver);
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
            match &self.stop_signal {
                Some(ref r) => match r.try_recv() {
                    Ok(_) => {
                        println!("Stop by Terminate Signal.");
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(e) => {
                        panic!("{:?}", e);
                    }
                }
                None => {}
            }
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
        self.current_state
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
    use crate::net::{RedisManager, ConnectionManager, Message, MessageType, SignerID};
    use crate::test_helper::TestKeys;
    use std::thread;
    use crate::rpc::Rpc;
    use std::sync::mpsc::{Sender, Receiver, channel};
    use redis::ControlFlow;
    use std::thread::JoinHandle;
    use std::sync::{Arc, Mutex};
    use std::cell::RefCell;

    pub struct TestConnectionManager<F: Fn(std::rc::Rc<Message>) -> () + Send + 'static> {
        pub sender: Sender<Message>,
        pub receiver: Receiver<Message>,
        pub broadcast_assert: F,
    }

    impl<F: Fn(std::rc::Rc<Message>) -> () + Send + 'static> TestConnectionManager<F> {
        pub fn new(broadcast_assert: F) -> TestConnectionManager<F> {
            let (sender, receiver): (Sender<Message>, Receiver<Message>) = channel();
            TestConnectionManager {
                sender,
                receiver,
                broadcast_assert,
            }
        }
    }

    impl<F: Fn(std::rc::Rc<Message>) -> () + Send + 'static> ConnectionManager for TestConnectionManager<F> {
        fn broadcast_message(&self, message: Message) {

            let rc_message = std::rc::Rc::new(message);
            (self.broadcast_assert)(rc_message.clone());
        }

        fn start(&self, mut message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static) -> JoinHandle<()> {
            match self.receiver.recv() {
                Ok(message) => {
                    println!("Test message receiving!! {:?}", message.message_type);
                    message_processor(message);
                }
                Err(e) => println!("happend receiver error: {:?}", e),
            }
            thread::spawn(|| {
                use std::time::Duration;
                thread::sleep(Duration::from_millis(300));
            })
        }
    }

    pub fn setup_node<F: Fn(std::rc::Rc<Message>) -> () + Send + 'static>(con: TestConnectionManager<F>, stop_handler: Receiver<u32>) -> thread::JoinHandle<()> {
        let testkeys = TestKeys::new();
        let pubkey_list = testkeys.pubkeys();
        let threshold = 2;
        let private_key = testkeys.key[0];

        let rpc = Rpc::new("http://localhost:1281".to_string(), Some("user".to_string()), Some("pass".to_string()));
        let params = NodeParameters::new(pubkey_list, private_key, threshold, rpc);
        thread::spawn(move || {
            let mut node = SignerNode::new(con, params, NodeState::Member);
            node.stop_handler(stop_handler);
            node.start();
        })
    }
}

#[test]
fn test_candidate_process() {
    use std::thread;
    use std::time::Duration;
    use crate::test_helper::TestKeys;

    let (ss, sr): (Sender<u32>, Receiver<u32>) = channel();

    let assertion = move |message: std::rc::Rc<Message>| {
        let actual = format!("{:?}", &message.message_type);
        assert!(actual.starts_with("Signature(Signature"));
        ss.send(1).unwrap();
    };

    let con = tests::TestConnectionManager::new(assertion);
    let sender = con.sender.clone();
    let handler = tests::setup_node(con, sr);
    let test_keys = TestKeys::new();
    let pubkey_list = test_keys.pubkeys();
    let block = Block::new(vec![]);
    let message_str = r#"{"message_type": {"Candidateblock": [0, 0, 0, 32, 237, 101, 140, 196, 6, 112, 204, 237, 162, 59, 176, 182, 20, 130, 31, 230, 212, 138, 65, 209, 7, 209, 159, 63, 58, 86, 8, 173, 61, 72, 48, 146, 177, 81, 22, 10, 183, 17, 51, 180, 40, 225, 246, 46, 174, 181, 152, 174, 133, 143, 246, 96, 23, 201, 150, 1, 242, 144, 136, 183, 198, 74, 72, 29, 98, 132, 225, 69, 210, 155, 112, 191, 84, 57, 45, 41, 112, 16, 49, 210, 175, 159, 237, 95, 155, 178, 31, 187, 40, 79, 167, 28, 235, 35, 143, 105, 166, 212, 9, 93, 0, 1, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 3, 92, 1, 1, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 25, 118, 169, 20, 207, 18, 219, 192, 75, 176, 222, 111, 182, 168, 122, 90, 235, 75, 46, 116, 201, 112, 6, 178, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },"sender_id": [3, 131, 26, 105, 184, 0, 152, 51, 171, 91, 3, 38, 1, 46, 175, 72, 155, 254, 163, 90, 115, 33, 177, 202, 21, 177, 29, 136, 19, 20, 35, 250, 252]}"#;
    let message = serde_json::from_str::<Message>(message_str).unwrap();

    thread::sleep(Duration::from_secs(1));
    sender.send(message).unwrap();
    thread::sleep(Duration::from_secs(1));
    handler.join().unwrap();
}