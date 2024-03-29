// Copyright (c) 2019 Chaintope Inc.

use crate::errors;
use crate::serialize::{ByteBufVisitor, HexStrVisitor};
use redis::{Client, Commands, ControlFlow, PubSubCommands, RedisError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt::{Debug, Display};
use std::sync::mpsc::{channel, Receiver, Sender};
/// メッセージを受け取って、それを処理するためのモジュール
/// メッセージの処理は、メッセージの種類とラウンドの状態に依存する。
/// ラウンドの状態は 誰が master であるか（自身がmaster であるか）。ラウンドが実行中であるか、開始待ちであるか。などで変わる
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use tapyrus::PublicKey;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;
use serde::export::fmt::Error;
use serde::export::Formatter;
use std::collections::HashSet;
use std::sync::mpsc::TryRecvError;
use tapyrus::blockdata::block::Block;
use tapyrus::hash_types::BlockSigHash;

/// Signer identifier is his public key.
#[derive(Eq, Hash, Copy, Clone)]
pub struct SignerID {
    pub pubkey: PublicKey,
}

impl Debug for SignerID {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "SignerID({})", self.pubkey)
    }
}

impl SignerID {
    pub fn new(pubkey: PublicKey) -> Self {
        SignerID { pubkey }
    }
}

impl std::fmt::Display for SignerID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pubkey)
    }
}

impl PartialEq for SignerID {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey.to_bytes().eq(&other.pubkey.to_bytes())
    }
}

impl PartialOrd for SignerID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = self.pubkey.key.serialize();
        let b = other.pubkey.key.serialize();
        PartialOrd::partial_cmp(&a[..], &b[..])
    }
}

impl Ord for SignerID {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.pubkey.key.serialize();
        let b = other.pubkey.key.serialize();
        Ord::cmp(&a[..], &b[..])
    }
}

impl Serialize for SignerID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = hex::encode(&self.pubkey.key.serialize()[..]);
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for SignerID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = deserializer.deserialize_str(HexStrVisitor::new())?;

        // TODO: Handle when PublicKey::from_slice returns Error
        let pubkey = PublicKey::from_slice(&vec).unwrap();
        let signer_id = SignerID::new(pubkey);
        Ok(signer_id)
    }
}

/// Messages which are sent to and received from other signer nodes
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum MessageType {
    Candidateblock(Block),
    Completedblock(Block),
    Blockvss(BlockSigHash, VerifiableSS, FE, VerifiableSS, FE),
    Blockparticipants(BlockSigHash, HashSet<SignerID>),
    Blocksig(BlockSigHash, FE, FE),
}

impl Display for MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            MessageType::Candidateblock(_) => write!(f, "Candidateblock"),
            MessageType::Completedblock(_) => write!(f, "Completedblock"),
            MessageType::Blockvss(_, _, _, _, _) => write!(f, "Blockvss"),
            MessageType::Blockparticipants(_, _) => write!(f, "Blockparticipants"),
            MessageType::Blocksig(_, _, _) => write!(f, "Blocksig"),
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct Message {
    pub message_type: MessageType,
    pub sender_id: SignerID,
    pub receiver_id: Option<SignerID>,
}

#[derive(Debug, PartialEq)]
pub struct Signature(pub secp256k1::Signature);

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ser = self.0.serialize_der();
        serializer.serialize_bytes(&ser[..])
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = deserializer.deserialize_byte_buf(ByteBufVisitor)?;

        // TODO: handle parse error
        let signature = secp256k1::Signature::from_der(&vec).unwrap();
        Ok(Signature(signature))
    }
}

pub trait ConnectionManager {
    type ERROR: std::error::Error;
    fn broadcast_message(&self, message: Message);
    fn send_message(&self, message: Message);
    fn start(
        &self,
        message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static,
        id: SignerID,
    ) -> JoinHandle<()>;
    fn test_connection(&self) -> Result<(), errors::Error>;
    fn take_error(
        &mut self,
    ) -> Result<ConnectionManagerError<Self::ERROR>, std::sync::mpsc::TryRecvError>;
}

#[derive(Debug)]
pub struct ConnectionManagerError<E: std::error::Error> {
    description: String,
    cause: Option<E>,
}

impl<E: std::error::Error> std::fmt::Display for ConnectionManagerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<E: std::error::Error> std::error::Error for ConnectionManagerError<E> {
    fn description(&self) -> &str {
        &self.description
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self.cause {
            Some(ref e) => Some(e),
            None => None,
        }
    }
}

impl From<RedisError> for ConnectionManagerError<RedisError> {
    fn from(cause: RedisError) -> ConnectionManagerError<RedisError> {
        ConnectionManagerError {
            description: format!("{:?}", cause),
            cause: Some(cause),
        }
    }
}

pub struct RedisManager {
    pub client: Arc<Client>,
    error_sender: Sender<ConnectionManagerError<RedisError>>,
    pub error_receiver: Receiver<ConnectionManagerError<RedisError>>,
}

impl RedisManager {
    pub fn new(host: String, port: String) -> Self {
        let url: &str = &format!("redis://{}:{}", host, port);
        let client = Arc::new(Client::open(url).unwrap());
        let (s, r): (
            Sender<ConnectionManagerError<RedisError>>,
            Receiver<ConnectionManagerError<RedisError>>,
        ) = channel();
        RedisManager {
            client,
            error_sender: s,
            error_receiver: r,
        }
    }

    fn subscribe<F>(&self, message_processor: F, id: SignerID) -> thread::JoinHandle<()>
    where
        F: FnMut(Message) -> ControlFlow<()> + Send + 'static,
    {
        let client = Arc::clone(&self.client);
        let error_sender = self.error_sender.clone();
        let channel_name = format!("tapyrus-signer-{}", id.pubkey.key);
        thread::Builder::new()
            .name("RedisManagerThread".to_string())
            .spawn(move || {
                fn inner_subscribe<F2>(
                    id: SignerID,
                    client: Arc<Client>,
                    mut message_processor: F2,
                    channel_name: &str,
                ) -> Result<(), ConnectionManagerError<RedisError>>
                where
                    F2: FnMut(Message) -> ControlFlow<()> + Send + 'static,
                {
                    let mut conn = client.get_connection()?;
                    conn.subscribe(&["tapyrus-signer", channel_name], |msg| {
                        let _ch = msg.get_channel_name();
                        let payload: String = msg.get_payload().unwrap();
                        log::trace!("receive message. payload: {}", payload);

                        let message: Message = serde_json::from_str(&payload).unwrap();
                        if id == message.sender_id {
                            // Ignore the message when the sender is myself.
                            ControlFlow::Continue
                        } else {
                            message_processor(message)
                        }
                    })?;
                    Ok(())
                }
                if let Err(e) = inner_subscribe(id, client, message_processor, &channel_name) {
                    let _ = error_sender.send(e);
                }
            })
            .expect("Failed create RedisManagerThread.")
    }

    fn process_message(&self, message: Message, to: String) {
        let client = Arc::clone(&self.client);
        let error_sender = self.error_sender.clone();
        let message_in_thread = serde_json::to_string(&message).unwrap();

        let thread = thread::Builder::new()
            .name("RedisBroadcastThread".to_string())
            .spawn(move || {
                fn inner_process_message(
                    client: Arc<Client>,
                    message: &str,
                    to: &str,
                ) -> Result<(), ConnectionManagerError<RedisError>> {
                    let mut conn = client.get_connection()?;
                    thread::sleep(Duration::from_millis(500));

                    conn.set_write_timeout(Some(Duration::from_secs(5)))?;
                    log::trace!("Publish {} to tapyrus-signer channel.", message);

                    let _: () = conn.publish(to, message)?;
                    Ok(())
                }
                match inner_process_message(client, &message_in_thread, &to) {
                    Ok(()) => log::trace!(
                        "Success to send message {} in channel {}",
                        message_in_thread,
                        to
                    ),
                    Err(e) => {
                        let _ = error_sender.send(e);
                    }
                };
            })
            .unwrap();
        if let Err(e) = thread.join() {
            log::error!("Can't connect to Redis Server: {:?}", e);
        }
    }

    fn clear_error(&self) {
        loop {
            match self.error_receiver.try_recv() {
                Ok(e) => log::warn!("Exhaust error {:?}", e),
                Err(TryRecvError::Empty) => break,
                Err(_) => break,
            }
        }
    }
}

impl ConnectionManager for RedisManager {
    type ERROR = RedisError;

    fn broadcast_message(&self, message: Message) {
        assert!(message.receiver_id.is_none());
        let channel_name = "tapyrus-signer".to_string();
        log::debug!(
            "broadcast_message channel_name: {}, message: {:?}",
            channel_name,
            message
        );
        self.process_message(message, channel_name);
    }

    fn send_message(&self, message: Message) {
        assert!(message.receiver_id.is_some());
        let channel_name = format!("tapyrus-signer-{}", message.receiver_id.unwrap().pubkey.key);
        log::debug!(
            "send_message channel_name: {}, message: {:?}",
            channel_name,
            message
        );
        self.process_message(message, channel_name);
    }

    fn start(
        &self,
        message_processor: impl FnMut(Message) -> ControlFlow<()> + Send + 'static,
        id: SignerID,
    ) -> JoinHandle<()> {
        self.clear_error();
        self.subscribe(message_processor, id)
    }

    fn test_connection(&self) -> Result<(), errors::Error> {
        match self.client.get_connection() {
            Ok(_) => Ok(()),
            Err(e) => Err(errors::Error::from(e)),
        }
    }

    fn take_error(
        &mut self,
    ) -> Result<ConnectionManagerError<Self::ERROR>, std::sync::mpsc::TryRecvError> {
        self.error_receiver.try_recv()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::helper::blocks::get_block;
    use crate::tests::helper::keys::TEST_KEYS;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "ConnectionManagerError")]
    fn test_error_when_sending_message_without_redis_connection() {
        // create un-usable connection
        let mut connection_manager = RedisManager::new("0.0.0.0".to_string(), "999".to_string());
        let sender_id = SignerID {
            pubkey: TEST_KEYS.pubkeys()[4],
        };

        let block = get_block(0);

        let message = Message {
            message_type: MessageType::Candidateblock(block),
            sender_id,
            receiver_id: None,
        };

        connection_manager.process_message(message, "channel".to_string());

        match connection_manager.take_error() {
            Ok(e) => {
                panic!("{}", e.to_string());
            }
            Err(_e) => {}
        }
    }

    #[test]
    #[ignore]
    fn redis_connection_test() {
        let connection_manager = Arc::new(RedisManager::new(
            "localhost".to_string(),
            "6379".to_string(),
        ));
        let sender_id = SignerID {
            pubkey: TEST_KEYS.pubkeys()[4],
        };

        let message_processor = move |message: Message| {
            let block = get_block(0);
            assert_eq!(message.message_type, MessageType::Candidateblock(block));
            ControlFlow::Break(())
        };

        let subscriber = connection_manager.subscribe(message_processor, sender_id);

        let block = get_block(0);
        let message = Message {
            message_type: MessageType::Candidateblock(block),
            sender_id,
            receiver_id: None,
        };
        connection_manager.broadcast_message(message);

        subscriber.join().unwrap();
    }

    #[test]
    fn signer_id_serialize_test() {
        let pubkey = TEST_KEYS.pubkeys()[4];
        let signer_id: SignerID = SignerID { pubkey };
        let serialized = serde_json::to_string(&signer_id).unwrap();
        assert_eq!(
            "\"03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc\"",
            serialized
        );
    }

    #[test]
    fn signer_id_deserialize_test() {
        let serialized = "\"03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc\"";
        let signer_id = serde_json::from_str::<SignerID>(serialized).unwrap();

        let pubkey = TEST_KEYS.pubkeys()[4];
        let expected: SignerID = SignerID { pubkey };
        assert_eq!(expected, signer_id);
    }

    #[test]
    fn test_sort_signer_id() {
        let alice = SignerID::new(
            PublicKey::from_str(
                "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc",
            )
            .unwrap(),
        );
        let bob = SignerID::new(
            PublicKey::from_str(
                "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900",
            )
            .unwrap(),
        );
        let carol = SignerID::new(
            PublicKey::from_str(
                "0461cc17fc4755599a903c59b2f2b886824afc1dd746632bb053ca2f4297f4b10fc02b133f1644f0fd64a74a7a6b35f78bf5d3354c0be5bb66d16d8fc499fa2a82",
            )
            .unwrap(),
        );

        assert!(alice > bob);
        assert!(bob > carol);

        //Sort key in BTreeMap.
        let mut map: BTreeMap<SignerID, &str> = BTreeMap::new();
        map.insert(alice, "a");
        map.insert(bob, "b");
        map.insert(carol, "c");
        let values: Vec<&str> = map.values().cloned().collect();
        assert_eq!(values, vec!["c", "b", "a"]);
    }
}
