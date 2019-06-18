use crate::net::{ConnectionManager, MessageType, Message};
use crate::signer::{StateContext};
use crate::net::{ConnectionManager, Message};
use crate::net::{ConnectionManager, Message, MessageType};
use crate::signer::{StateContext, NodeState};
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey, Address};
use crate::rpc::Rpc;
use bitcoin::{PublicKey, PrivateKey};
use std::sync::mpsc::channel;

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

    pub fn start(&mut self, state: NodeState) {
        let mut context: StateContext = StateContext::new(state);
        if let NodeState::Master = &context.current_state {
            let block = self._params.rpc.getnewblock(&self._params.address).unwrap();
            self.connection_manager.broadcast_message(Message {
                message_type: MessageType::Candidateblock,
                payload: block.payload(),
            })
        };

        let closure = move |message: Message| {
            let next = context.current_state.process_message(message);
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
    pub rpc: Rpc,
    pub address: Address,
}

impl NodeParameters {
    pub fn new(pubkey_list: Vec<PublicKey>, private_key: PrivateKey, threshold: u32, rpc: Rpc) -> NodeParameters {
        let secp = secp256k1::Secp256k1::new();
        let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);

        NodeParameters {
            pubkey_list,
            threshold,
            private_key,
            rpc,
            address,
        }
    }
}