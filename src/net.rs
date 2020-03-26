// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::blockdata::hash::SHA256Hash;
use crate::blockdata::Block;
use crate::errors;
use crate::serialize::{ByteBufVisitor, HexStrVisitor};
use bitcoin::PublicKey;
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

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;
use serde::export::fmt::Error;
use serde::export::Formatter;
use std::collections::HashSet;

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
        self.pubkey.to_bytes().partial_cmp(&other.pubkey.to_bytes())
    }
}

impl Ord for SignerID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pubkey.to_bytes().cmp(&other.pubkey.to_bytes())
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
    BlockGenerationRoundMessages(BlockGenerationRoundMessageType),
}

impl Display for MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            MessageType::BlockGenerationRoundMessages(m) => write!(f, "{}", m),
        }
    }
}

/// # Round Messages
/// These messages are used in block generation rounds.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum BlockGenerationRoundMessageType {
    Candidateblock(Block),
    Completedblock(Block),
    Blockvss(SHA256Hash, VerifiableSS, FE, VerifiableSS, FE),
    Blockparticipants(SHA256Hash, HashSet<SignerID>),
    Blocksig(SHA256Hash, FE, FE),
    Roundfailure,
}

impl Display for BlockGenerationRoundMessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            BlockGenerationRoundMessageType::Candidateblock(_) => write!(f, "Candidateblock"),
            BlockGenerationRoundMessageType::Completedblock(_) => write!(f, "Completedblock"),
            BlockGenerationRoundMessageType::Blockvss(_, _, _, _, _) => write!(f, "Blockvss"),
            BlockGenerationRoundMessageType::Blockparticipants(_, _) => {
                write!(f, "Blockparticipants")
            }
            BlockGenerationRoundMessageType::Blocksig(_, _, _) => write!(f, "Blocksig"),
            BlockGenerationRoundMessageType::Roundfailure => write!(f, "Roundfailure"),
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
    fn error_handler(&mut self) -> Option<Receiver<ConnectionManagerError<Self::ERROR>>>;
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
    pub error_receiver: Option<Receiver<ConnectionManagerError<RedisError>>>,
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
            error_receiver: Some(r),
        }
    }

    pub fn test_connection(&self) -> Result<(), errors::Error> {
        match self.client.get_connection() {
            Ok(_) => Ok(()),
            Err(e) => Err(errors::Error::from(e)),
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
                        message_processor(message)
                    })?;
                    Ok(())
                }
                match inner_subscribe(client, message_processor, &channel_name) {
                    Ok(()) => {}
                    Err(e) => error_sender
                        .send(e)
                        .expect("Can't notify RedisManager connection error"),
                };
            })
            .expect("Failed create RedisManagerThread.")
    }

    fn process_message(&self, message: Message, to: String) {
        let client = Arc::clone(&self.client);
        let error_sender = self.error_sender.clone();
        let message_in_thread = serde_json::to_string(&message).unwrap();

        thread::Builder::new()
            .name("RedisBroadcastThread".to_string())
            .spawn(move || {
                fn inner_process_message(
                    client: Arc<Client>,
                    message: &str,
                    to: &str,
                ) -> Result<(), ConnectionManagerError<RedisError>> {
                    let conn = client.get_connection()?;
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
                    Err(e) => error_sender
                        .send(e)
                        .expect("Can't notify RedisManager connection error"),
                };
            })
            .unwrap()
            .join()
            .expect("Can't connect to Redis Server.");
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
        self.subscribe(message_processor, id)
    }

    fn error_handler(&mut self) -> Option<Receiver<ConnectionManagerError<Self::ERROR>>> {
        self.error_receiver.take()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::helper::keys::TEST_KEYS;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "ConnectionManagerError")]
    fn test_error_when_sending_message_without_redis_connection() {
        // create un-usable connection
        let mut connection_manager = RedisManager::new("0.0.0.0".to_string(), "999".to_string());
        let sender_id = SignerID {
            pubkey: TEST_KEYS.pubkeys()[0],
        };

        let message = Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Roundfailure,
            ),
            sender_id,
            receiver_id: None,
        };

        connection_manager.process_message(message, "channel".to_string());

        let error_handler = connection_manager.error_handler().unwrap();
        match error_handler.try_recv() {
            Ok(e) => {
                panic!(e.to_string());
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
            pubkey: TEST_KEYS.pubkeys()[0],
        };

        let message_processor = move |message: Message| {
            assert_eq!(
                message.message_type,
                MessageType::BlockGenerationRoundMessages(
                    BlockGenerationRoundMessageType::Roundfailure
                )
            );
            ControlFlow::Break(())
        };

        let subscriber = connection_manager.subscribe(message_processor, sender_id);

        let message = Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Roundfailure,
            ),
            sender_id,
            receiver_id: None,
        };
        connection_manager.broadcast_message(message);

        subscriber.join().unwrap();
    }

    #[test]
    fn signer_id_serialize_test() {
        let pubkey = TEST_KEYS.pubkeys()[0];
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

        let pubkey = TEST_KEYS.pubkeys()[0];
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
                "02a85a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e",
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
