/// メッセージを受け取って、それを処理するためのモジュール
/// メッセージの処理は、メッセージの種類とラウンドの状態に依存する。
/// ラウンドの状態は 誰が master であるか（自身がmaster であるか）。ラウンドが実行中であるか、開始待ちであるか。などで変わる
use std::sync::Arc;
use redis::{Client, Commands, ControlFlow, PubSubCommands};
use std::thread;
use std::time::Duration;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use bitcoin::PublicKey;
use crate::serialize::ByteBufVisitor;
use crate::blockdata::Block;
use std::thread::JoinHandle;


/// Signerの識別子。公開鍵を識別子にする。
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct SignerID {
    pub pubkey: PublicKey
}

impl SignerID {
    pub fn new(pubkey: PublicKey) -> SignerID {
        SignerID {
            pubkey
        }
    }
}

impl Serialize for SignerID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use bitcoin::util::psbt::serialize::Serialize;

        let ser = self.pubkey.serialize();
        serializer.serialize_bytes(&ser[..])
    }
}

impl<'de> Deserialize<'de> for SignerID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        let vec = deserializer.deserialize_byte_buf(ByteBufVisitor)?;

        // TODO: Handle when PublicKey::from_slice returns Error
        let pubkey = PublicKey::from_slice(&vec).unwrap();
        let signer_id = SignerID::new(pubkey);
        Ok(signer_id)
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum MessageType {
    Candidateblock(Block),
    Signature(Signature),
    Completedblock(Block),
    Roundfailure,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub message_type: MessageType,
    pub sender_id: SignerID,
}

#[derive(Debug, PartialEq)]
pub struct Signature(pub secp256k1::Signature);

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let ser = self.0.serialize_der();
        serializer.serialize_bytes(&ser[..])
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        let vec = deserializer.deserialize_byte_buf(ByteBufVisitor)?;

        // TODO: handle parse error
        let signature = secp256k1::Signature::from_der(&vec).unwrap();
        Ok(Signature(signature))
    }
}


pub trait ConnectionManager {
    fn broadcast_message(&self, message: Message);
    fn start(&self, message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static) -> JoinHandle<()>;
}

pub struct RedisManager {
    pub client: Arc<Client>,
}

impl RedisManager {
    pub fn new() -> RedisManager {
        let client = Arc::new(Client::open("redis://localhost").unwrap());
        RedisManager { client }
    }

    fn subscribe(&self, mut message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static) -> thread::JoinHandle<()>
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

    fn start(&self, message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static) -> JoinHandle<()>
    {
        self.subscribe(message_processor)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helper::{TestKeys, create_message};

    #[test]
    fn redis_connection_test() {
        let connection_manager = Arc::new(RedisManager::new());
        let sender_id = SignerID { pubkey: TestKeys::new().pubkeys()[0] };

        let message_processor = move |message: Message| {
            assert_eq!(message.message_type, MessageType::Roundfailure);
            ControlFlow::Break(())
        };

        let subscriber = connection_manager.subscribe(message_processor);

        let message = Message {
            message_type: MessageType::Roundfailure,
            sender_id,
        };
        connection_manager.broadcast_message(message);

        subscriber.join().unwrap();
    }

    #[test]
    fn signer_id_serialize_test() {
        let pubkey = TestKeys::new().pubkeys()[0];
        let signer_id: SignerID = SignerID { pubkey };
        let serialized = serde_json::to_string(&signer_id).unwrap();
        assert_eq!("[3,131,26,105,184,0,152,51,171,91,3,38,1,46,175,72,155,254,163,90,115,33,177,202,21,177,29,136,19,20,35,250,252]", serialized);
    }

    #[test]
    fn signer_id_deserialize_test() {
        let serialized = "[3,131,26,105,184,0,152,51,171,91,3,38,1,46,175,72,155,254,163,90,115,33,177,202,21,177,29,136,19,20,35,250,252]";
        let signer_id = serde_json::from_str::<SignerID>(serialized).unwrap();

        let pubkey = TestKeys::new().pubkeys()[0];
        let expected: SignerID = SignerID { pubkey };
        assert_eq!(expected, signer_id);
    }

    #[test]
    fn signature_message_serialize_deserialize_test() {
        let message = create_message();

        let serialized = serde_json::to_string(&message).unwrap();

        // check serialize
        let expected_serialized_message = r#"{"message_type":{"Signature":[48,69,2,33,0,209,78,75,40,108,63,135,236,126,58,248,69,201,134,198,123,9,100,136,101,202,168,134,119,114,0,86,36,17,238,152,190,2,32,91,12,234,133,10,255,32,122,215,249,21,62,10,88,133,223,155,69,205,171,31,105,114,13,174,21,159,118,161,43,58,137]},"sender_id":[3,131,26,105,184,0,152,51,171,91,3,38,1,46,175,72,155,254,163,90,115,33,177,202,21,177,29,136,19,20,35,250,252]}"#;
        assert_eq!(expected_serialized_message, serialized);

        // check deserialize
        let sig = Signature(secp256k1::Signature::from_der(&base64::decode("MEUCIQDRTksobD+H7H46+EXJhsZ7CWSIZcqohndyAFYkEe6YvgIgWwzqhQr/IHrX+RU+CliF35tFzasfaXINrhWfdqErOok=").unwrap()).unwrap());
        let deserialized = serde_json::from_str::<Message>(expected_serialized_message).unwrap();
        assert_eq!(deserialized.message_type, MessageType::Signature(sig));
        assert_eq!(deserialized.sender_id, SignerID::new(TestKeys::new().pubkeys()[0]));
    }
}