extern crate tapyrus_siner;
extern crate bitcoin;
extern crate log;
extern crate redis;

use tapyrus_siner::net::{RedisManager, Message, MessageType, ConnectionManager, SignerID};
use std::str::FromStr;
use bitcoin::PublicKey;

fn main() {
    let connection_manager = RedisManager::new();
    let sender_id = SignerID::new(PublicKey::from_str("03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc").unwrap());
    let message = Message { message_type: MessageType::Candidateblock, sender_id, payload: [].to_vec() };
    connection_manager.broadcast_message(message);
}



