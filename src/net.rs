/// メッセージを受け取って、それを処理するためのモジュール
/// メッセージの処理は、メッセージの種類とラウンドの状態に依存する。
/// ラウンドの状態は 誰が master であるか（自身がmaster であるか）。ラウンドが実行中であるか、開始待ちであるか。などで変わる
use std::sync::Arc;
use redis::{Client, Commands, ControlFlow, PubSubCommands};
use std::thread;
use std::time::Duration;
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum MessageType {
    Candidateblock,
    Signature,
    Completedblock,
    Roundfailure,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

pub trait ConnectionManager {
    fn broadcast_message(&self, message: Message);
    fn start(&self, message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + Sync + 'static);
}

pub struct RedisManager {
    pub client: Arc<Client>,
}

impl RedisManager {
    pub fn new() -> RedisManager {
        let client = Arc::new(Client::open("redis://localhost").unwrap());
        RedisManager { client }
    }

    fn subscribe(&self, mut message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + Sync + 'static) -> thread::JoinHandle<()>
     {
        let client = Arc::clone(&self.client);

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
        }).join().unwrap();
    }

    fn start(&self, message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + Sync + 'static)
         {
        let subscriber = self.subscribe(message_processor);

        subscriber.join().unwrap();
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn redis_connection_test() {
        let connection_manager = Arc::new(RedisManager::new());

        let message_processor = move |message: Message|  {
            assert_eq!(message.message_type, MessageType::Candidateblock);
            ControlFlow::Break(())
        };

        let subscriber = connection_manager.subscribe(message_processor);

        let message = Message { message_type: MessageType::Candidateblock, payload: [].to_vec() };
        connection_manager.broadcast_message(message);

        subscriber.join().unwrap();
    }
}