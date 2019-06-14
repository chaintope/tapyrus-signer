extern crate tapyrus_siner;
extern crate bitcoin;
extern crate log;
extern crate redis;

use tapyrus_siner::net::{RedisManager, Message, MessageType, ConnectionManager};

fn main() {
    let connection_manager = RedisManager::new();
    let message = Message { message_type: MessageType::Candidateblock, payload: [].to_vec() };
    connection_manager.broadcast_message(message);
}



