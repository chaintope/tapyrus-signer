use crate::net::{BlockGenerationRoundMessageType, Message, MessageType, SignerID};
use crate::tests::helper::keys::TEST_KEYS;
use bitcoin::{Address, PrivateKey};

pub mod blocks;
pub mod keys;
pub mod net;
pub mod node_parameters_builder;
pub mod node_state_builder;
pub mod rpc;

pub fn enable_log(log_level: Option<log::Level>) {
    if let Some(level) = log_level {
        std::env::set_var("RUST_LOG", level.to_string());
    } else {
        std::env::set_var("RUST_LOG", "TRACE");
    }

    let _ = env_logger::builder().is_test(true).try_init();
}

pub fn create_message() -> Message {
    let signer_id = SignerID::new(TEST_KEYS.pubkeys()[0]);
    Message {
        message_type: MessageType::BlockGenerationRoundMessages(
            BlockGenerationRoundMessageType::Roundfailure,
        ),
        sender_id: signer_id,
        receiver_id: None,
    }
}

pub fn address(private_key: &PrivateKey) -> Address {
    let secp = secp256k1::Secp256k1::new();
    let self_pubkey = private_key.public_key(&secp);
    Address::p2pkh(&self_pubkey, private_key.network)
}
