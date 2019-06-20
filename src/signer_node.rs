use crate::net::{ConnectionManager, Message, MessageType, SignerID, Signature};
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey, Address};
use crate::rpc::TapyrusApi;
use std::sync::mpsc::{channel, Sender, Receiver};
use crate::blockdata::Block;
use crate::sign::sign;
use std::sync::Arc;

pub struct SignerNode<T: TapyrusApi, C: ConnectionManager> {
    connection_manager: C,
    params: NodeParameters<T>,
    current_state: NodeState,
    stop_signal: Option<Receiver<u32>>,
}
#[derive(Debug, Clone, PartialEq)]
pub enum NodeState {
    Joining,
    Master {
        signatures: Vec<secp256k1::Signature>,
        candidate_block: Block,
    },
    Member,
}

impl<T: TapyrusApi, C: ConnectionManager> SignerNode<T, C> {
    pub fn new(connection_manager: C, params: NodeParameters<T>) -> SignerNode<T, C> {
        SignerNode {
            connection_manager,
            params,
            current_state: NodeState::Joining,
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

        self.current_state = if self.params.master_flag {
            self.start_new_round()
        } else {
            NodeState::Member
        };
        println!("node start. NodeState: {:?}", &self.current_state);

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

    // TODO: pseudo-implementation.
    pub fn start_new_round(&self) -> NodeState {
        let block = self.params.rpc.getnewblock(&self.params.address).unwrap();
        self.connection_manager.broadcast_message(Message {
            message_type: MessageType::Candidateblock(block.clone()),
            sender_id: self.params.signer_id,
        });

        let sig = sign(&self.params.private_key, &block.hash().unwrap());
        NodeState::Master {
            candidate_block: block,
            signatures: vec![sig],
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

    fn process_candidateblock(&self, _sender_id: &SignerID, block: &Block) -> NodeState {
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

        self.current_state.clone()
    }


    fn process_signature(&self, _sender_id: &SignerID, signature: &Signature) -> NodeState {
        match &self.current_state {
            NodeState::Master { signatures: ref sigs, candidate_block: ref block } => {
                let mut sigs = sigs.clone();
                sigs.push(signature.0.clone());

                if sigs.len() as u8 >= self.params.threshold {
                    // call combineblocksigs
                    let completed_block = self.params.rpc.combineblocksigs(&block, &sigs).unwrap();

                    // call submitblock
                    self.params.rpc.submitblock(&completed_block).unwrap();

                    // send completeblock message
                    let message = Message {
                        message_type: MessageType::Completedblock(completed_block),
                        sender_id: self.params.signer_id.clone(),
                    };
                    self.connection_manager.broadcast_message(message);

                    // start next round
                    self.start_new_round()
                } else {
                    NodeState::Master { signatures: sigs, candidate_block: block.clone() }
                }
            }
            state => {
                state.clone()
            }
        }
    }

    fn process_completedblock(&self, _sender_id: &SignerID, _block: &Block) -> NodeState {
        self.current_state.clone()
    }

    fn process_roundfailure(&self, _sender_id: &SignerID) -> NodeState {
        self.current_state.clone()
    }
}

pub struct NodeParameters<T: TapyrusApi> {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u8,
    pub private_key: PrivateKey,
    pub rpc: std::sync::Arc<T>,
    pub address: Address,
    pub signer_id: SignerID,
    pub master_flag: bool,
}

impl<T: TapyrusApi> NodeParameters<T> {
    pub fn new(pubkey_list: Vec<PublicKey>, private_key: PrivateKey, threshold: u8, rpc: T, master_flag: bool) -> NodeParameters<T> {
        let secp = secp256k1::Secp256k1::new();
        let self_pubkey = private_key.public_key(&secp);
        let address = Address::p2pkh(&self_pubkey, private_key.network);
        let signer_id = SignerID { pubkey: self_pubkey };
        let master_flag = master_flag;

        NodeParameters {
            pubkey_list,
            threshold,
            private_key,
            rpc: Arc::new(rpc),
            address,
            signer_id,
            master_flag,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::signer_node::{NodeParameters, SignerNode, NodeState};
    use crate::net::{ConnectionManager, Message};
    use crate::net::{RedisManager, SignerID, Signature};
    use crate::test_helper::{TestKeys, get_block};
    use std::thread;
    use crate::rpc::Rpc;
    use std::sync::mpsc::{Sender, Receiver, channel};
    use redis::ControlFlow;
    use std::thread::JoinHandle;
    use std::sync::Arc;
    use crate::sign::sign;
    use crate::rpc::tests::MockRpc;

    pub struct TestConnectionManager<F: Fn(Arc<Message>) -> () + Send + 'static> {
        pub sender: Sender<Message>,
        pub receiver: Receiver<Message>,
        pub broadcast_assert: F,
    }

    impl<F: Fn(Arc<Message>) -> () + Send + 'static> TestConnectionManager<F> {
        pub fn new(broadcast_assert: F) -> TestConnectionManager<F> {
            let (sender, receiver): (Sender<Message>, Receiver<Message>) = channel();
            TestConnectionManager {
                sender,
                receiver,
                broadcast_assert,
            }
        }
    }

    impl<F: Fn(Arc<Message>) -> () + Send + 'static> ConnectionManager for TestConnectionManager<F> {
        fn broadcast_message(&self, message: Message) {
            let rc_message = Arc::new(message);
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
            thread::Builder::new().name("TestConnectionManager start Thread".to_string()).spawn(|| {
                use std::time::Duration;
                thread::sleep(Duration::from_millis(300));
            }).unwrap()
        }
    }

    fn create_node<'a>(current_state: NodeState) -> SignerNode<MockRpc<'a>, RedisManager> {
        let testkeys = TestKeys::new();
        let pubkey_list = testkeys.pubkeys();
        let threshold = 2;
        let private_key = testkeys.key[0];

        let rpc = MockRpc { return_block: None };
        let params = NodeParameters::new(pubkey_list, private_key, threshold, rpc, true);
        let con = RedisManager::new();

        let mut node = SignerNode::new(con, params);
        node.current_state = current_state;
        node
    }

    pub fn setup_node<F>(con: TestConnectionManager<F>) -> (thread::JoinHandle<()>, Sender<u32>)
        where F: Fn(Arc<Message>) -> () + Send + 'static {
        let testkeys = TestKeys::new();
        let pubkey_list = testkeys.pubkeys();
        let threshold = 2;
        let private_key = testkeys.key[0];

        let (stop_signal, stop_handler): (Sender<u32>, Receiver<u32>) = channel();
        let rpc = Rpc::new("http://localhost:12381".to_string(), Some("user".to_string()), Some("pass".to_string()));
        let params = NodeParameters::new(pubkey_list, private_key, threshold, rpc, false);
        let handle = thread::Builder::new().name("NodeMainThread".to_string()).spawn(move || {
            let mut node = SignerNode::new(con, params);
            node.stop_handler(stop_handler);
            node.start();
        }).unwrap();

        (handle, stop_signal)
    }

    /// 3 of 5 multisig
    /// Round owner will collect signatures.
    #[test]
    fn process_signature_test() {
        let _node_owner = SignerID::new(TestKeys::new().pubkeys()[0]);
        let owner_private_key = TestKeys::new().key[0];

        let block = get_block();

        // Round master create signature itself, when broadcast candidate block. So,
        // signatures vector has one signature.
        let initial_state = NodeState::Master {
            candidate_block: block.clone(),
            signatures: vec![sign(&owner_private_key, &block.hash().unwrap())],
        };
        let mut node = create_node(initial_state);

        // sign node1
        {
            let private_key = TestKeys::new().key[1];
            let sender_id = SignerID::new(TestKeys::new().pubkeys()[1]);
            let block_hash = block.hash().unwrap();
            let sig = sign(&private_key, &block_hash);

            let next_state = node.process_signature(&sender_id, &Signature(sig));

            match next_state {
                NodeState::Master { signatures: ref sigs, .. } => {
                    assert_eq!(sigs.len(), 2);
                }
                ref state => panic!("{:?}", state),
            }

            node.current_state = next_state;
        }

        // sign node2
        // After node2 send signature, threshold is going to be met. So, signatures vector is
        // cleared and the block state object has is renewed.
        {
            let private_key = TestKeys::new().key[2];
            let sender_id = SignerID::new(TestKeys::new().pubkeys()[2]);
            let block_hash = block.hash().unwrap();
            let sig = sign(&private_key, &block_hash);

            let next_state = node.process_signature(&sender_id, &Signature(sig));

            match next_state {
                NodeState::Master { signatures: sigs, candidate_block: next_block } => {
                    assert_eq!(sigs.len(), 0);
                    assert_ne!(block, next_block);
                }
                _ => assert!(false),
            }
        }
    }
}

#[test]
fn test_candidate_process() {
    use std::sync::Arc;

    let (broadcast_s, broadcast_r): (Sender<Arc<Message>>, Receiver<Arc<Message>>) = channel();
    let assertion = move |message: Arc<Message>| {
        broadcast_s.send(message).unwrap();
    };
    let con = tests::TestConnectionManager::new(assertion);
    let sender = con.sender.clone();
    let (_handler, stop_signal) = tests::setup_node(con);
    let message_str = r#"{"message_type": {"Candidateblock": [0, 0, 0, 32, 237, 101, 140, 196, 6, 112, 204, 237, 162, 59, 176, 182, 20, 130, 31, 230, 212, 138, 65, 209, 7, 209, 159, 63, 58, 86, 8, 173, 61, 72, 48, 146, 177, 81, 22, 10, 183, 17, 51, 180, 40, 225, 246, 46, 174, 181, 152, 174, 133, 143, 246, 96, 23, 201, 150, 1, 242, 144, 136, 183, 198, 74, 72, 29, 98, 132, 225, 69, 210, 155, 112, 191, 84, 57, 45, 41, 112, 16, 49, 210, 175, 159, 237, 95, 155, 178, 31, 187, 40, 79, 167, 28, 235, 35, 143, 105, 166, 212, 9, 93, 0, 1, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 3, 92, 1, 1, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 25, 118, 169, 20, 207, 18, 219, 192, 75, 176, 222, 111, 182, 168, 122, 90, 235, 75, 46, 116, 201, 112, 6, 178, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },"sender_id": [3, 131, 26, 105, 184, 0, 152, 51, 171, 91, 3, 38, 1, 46, 175, 72, 155, 254, 163, 90, 115, 33, 177, 202, 21, 177, 29, 136, 19, 20, 35, 250, 252]}"#;
    let message = serde_json::from_str::<Message>(message_str).unwrap();

    sender.send(message).unwrap();
    let broadcast_message = broadcast_r.recv().unwrap();
    let actual = format!("{:?}", &broadcast_message.message_type);
    assert!(actual.starts_with("Signature(Signature"));
    stop_signal.send(1).unwrap(); // this line not necessary, but for manners.
}