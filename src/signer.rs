use bitcoin::PublicKey;

/// Signerの識別子。公開鍵を識別子にする。
pub type SignerID = PublicKey;

pub struct StateContext {
    pub current_state: NodeState,
}

/// When node don't know round status because of just now joining to signer network.
pub enum NodeState {
    Joining,
    Master,
}

// state パターン
pub trait RoundState {
    fn process_candidateblock(&self, payload: &[u8]) -> NodeState;
    fn process_signature(&self, payload: &[u8]) -> NodeState;
    fn process_completedblock(&self, payload: &[u8]) -> NodeState;
    fn process_roundfailure(&self, payload: &[u8]) -> NodeState;
}

///// acts as master node in this round.
//pub struct Master {
//
//}
//
//impl RoundState for Master {
//
//}
//
///// acts as member node in this round.
//pub struct Member {
//    current_master: SignerID,
//}
//
//impl RoundState for Member {
//
//}

impl NodeState {
    pub fn process(&self) -> Box<dyn RoundState> {
        match self {
            NodeState::Joining => Box::new(RoundStateJoining{}),
            _ => Box::new(RoundStateJoining),
        }
    }
}

impl StateContext {
    pub fn new() -> StateContext {
        StateContext {
            current_state: NodeState::Joining
        }
    }

    pub fn set_state(&mut self, s: NodeState) {
        self.current_state = s;
    }
}

struct RoundStateJoining;

impl RoundState for RoundStateJoining {
    fn process_candidateblock(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }

    fn process_signature(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }

    fn process_completedblock(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }

    fn process_roundfailure(&self, _payload: &[u8]) -> NodeState {
        unimplemented!()
    }
}


#[cfg(test)]
mod tests {
    use crate::signer_node::{NodeParameters, SignerNode};
    use crate::net::{RedisManager, ConnectionManager, MessageType, Message, SignerID};
    use crate::test_helper::TestKeys;
    use std::thread;

    fn setup_node() -> thread::JoinHandle<()> {
        let testkeys = TestKeys::new();
        let pubkey_list = testkeys.pubkeys();
        let threshold = 2;
        let private_key = testkeys.key[0];

        let params = NodeParameters { pubkey_list, threshold, private_key };
        let con = RedisManager::new();

        let mut node = SignerNode::new(con, params);
        thread::spawn(move || {
            node.start();
        })
    }

    #[test]
    fn signature_message_serialize_deserialize_test() {
        let node = setup_node();
        let signer_id= SignerID::new(TestKeys::new().pubkeys()[0]);

        let redis = RedisManager::new();
        let message = Message {
            message_type: MessageType::Signature,
            sender_id: signer_id,
            payload: base64::decode("MEUCIQDRTksobD+H7H46+EXJhsZ7CWSIZcqohndyAFYkEe6YvgIgWwzqhQr/IHrX+RU+CliF35tFzasfaXINrhWfdqErOok=").unwrap(),
        };

        let serialized = serde_json::to_string(&message).unwrap();

        // check serialize
        let expected_serialized_message = r#"{"message_type":"Signature","sender_id":[3,131,26,105,184,0,152,51,171,91,3,38,1,46,175,72,155,254,163,90,115,33,177,202,21,177,29,136,19,20,35,250,252],"payload":[48,69,2,33,0,209,78,75,40,108,63,135,236,126,58,248,69,201,134,198,123,9,100,136,101,202,168,134,119,114,0,86,36,17,238,152,190,2,32,91,12,234,133,10,255,32,122,215,249,21,62,10,88,133,223,155,69,205,171,31,105,114,13,174,21,159,118,161,43,58,137]}"#;
        assert_eq!(expected_serialized_message, serialized);

        // check deserialize
        let deserialized = serde_json::from_str::<Message>(expected_serialized_message).unwrap();
        assert_eq!(deserialized.message_type, MessageType::Signature);
        assert_eq!(deserialized.sender_id, SignerID::new(TestKeys::new().pubkeys()[0]));
        assert_eq!(deserialized.payload, base64::decode("MEUCIQDRTksobD+H7H46+EXJhsZ7CWSIZcqohndyAFYkEe6YvgIgWwzqhQr/IHrX+RU+CliF35tFzasfaXINrhWfdqErOok=").unwrap());
    }
}