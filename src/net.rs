/// メッセージを受け取って、それを処理するためのモジュール
/// メッセージの処理は、メッセージの種類とラウンドの状態に依存する。
/// ラウンドの状態は 誰が master であるか（自身がmaster であるか）。ラウンドが実行中であるか、開始待ちであるか。などで変わる


use bitcoin::PublicKey;
use std::sync::Arc;
use redis::{Client, Commands, ControlFlow, PubSubCommands};
use std::thread;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Signerの識別子。公開鍵を識別子にする。
type SignerID = PublicKey;

/// ラウンドの状態を持つ構造体。シングルトン。
struct RoundState {
    current_master: SignerID,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
enum MessageType {
    Candidateblock,
    Signature,
    Completedblock,
    Roiundfailure,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    message_type: MessageType,
    payload: Vec<u8>,
}

// state パターン
//trait MessageProcessor {
//    fn process_candidateblock();
//    fn process_signature();
//    fn process_completedblock();
//    fn process_roundfailure();
//}

// master用の Message Processor
struct Master {

}

//impl MessageProcessor for Master {
//
//}

trait ConnectionManager {
    fn broadcast_message(&self, message: Message);
}

struct RedisManager {
    pub client: Arc<Client>,
    subscriber: thread::JoinHandle<()>,
}

type MessageProcessor = fn(message: Message) -> ControlFlow<()>;

impl RedisManager {
    pub fn new(message_processor: MessageProcessor) -> RedisManager {
        let client = Arc::new(Client::open("redis://localhost").unwrap());

        let subscriber = RedisManager::subscribe(&client, message_processor);
        RedisManager { client, subscriber, }
    }

    fn subscribe(client: &Arc<Client>, message_processor: MessageProcessor) -> thread::JoinHandle<()> {
        let client = Arc::clone(client);
        thread::spawn(move || {
            let mut conn = client.get_connection().unwrap();

            conn.subscribe(&["tapyrus-signer"], |msg| {
                let _ch = msg.get_channel_name();
                let payload: String = msg.get_payload().unwrap();
                println!("receive message. payload: {}", payload);

                let message: Message = serde_json::from_str(&payload).unwrap();
                message_processor(message)
            }).unwrap();
        })
    }
}

impl ConnectionManager for RedisManager {
    fn broadcast_message(&self, message: Message) {
        let client = Arc::clone(&self.client);
        let message_in_thread = serde_json::to_string(&message).unwrap();
        thread::spawn(move || {
            let conn = client.get_connection().unwrap();
            thread::sleep(Duration::from_millis(500));

            println!("Publish {} to tapyrus-signer channel.", message_in_thread);

            let _: () = conn.publish("tapyrus-signer", message_in_thread).unwrap();
        });
    }
}


pub fn initialize_network() {
    let connection_manager = RedisManager::new(|message|{
        ControlFlow::Break(())
    });
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::net::MessageType::Candidateblock;

    #[test]
    fn redis_connection_test() {
        let connection_manager = RedisManager::new(|message| {
            assert_eq!(message.message_type, MessageType::Candidateblock);
            ControlFlow::Break(())
        });
        let message = Message { message_type: MessageType::Candidateblock, payload: [].to_vec(), };
        connection_manager.broadcast_message(message);

        assert!(true);
        connection_manager.subscriber.join();
    }
}