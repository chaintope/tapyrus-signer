use crate::net::{ConnectionManager, MessageType, Message};
use crate::signer::{StateContext};
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey};

pub struct SignerNode<T: ConnectionManager> {
    connection_manager: T,
    _params: NodeParameters,
}

impl<T: ConnectionManager> SignerNode<T> {
    pub fn new(connection_manager: T, _params: NodeParameters) -> SignerNode<T> {
        SignerNode {
            connection_manager,
            _params,
        }
    }

    pub fn start(&mut self) {
        let mut context: StateContext = StateContext::new();
        let closure = move |message: Message| {
            let next = match message.message_type {
                MessageType::Candidateblock => context.current_state.process().process_candidateblock(&message.payload[..]),
                MessageType::Signature => { context.current_state.process().process_signature(&message.payload[..]) },
                MessageType::Completedblock => { context.current_state.process().process_completedblock(&message.payload[..]) },
                MessageType::Roundfailure => { context.current_state.process().process_roundfailure(&message.payload[..]) },
            };

            context.set_state(next);
            ControlFlow::Continue
        };
        self.connection_manager.start(closure);
    }
}

pub struct NodeParameters {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u32,
    pub private_key: PrivateKey,
}
