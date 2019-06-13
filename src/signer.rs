use bitcoin::PublicKey;

/// Signerの識別子。公開鍵を識別子にする。
pub type SignerID = PublicKey;

pub trait StateContext {
    fn setState(&mut self, state: Box<RoundState>);
}

// state パターン
pub trait RoundState {
    fn process_candidateblock(&self, payload: &[u8]) -> Box<RoundState>;
    fn process_signature(&self, payload: &[u8]) -> Box<RoundState>;
    fn process_completedblock(&self, payload: &[u8]) -> Box<RoundState>;
    fn process_roundfailure(&self, payload: &[u8]) -> Box<RoundState>;
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

/// When node don't know round status because of just now joining to signer network.
pub struct Joining {

}

impl RoundState for Joining {
    fn process_candidateblock(&self, payload: &[u8]) -> Box<RoundState> {
        unimplemented!()
    }

    fn process_signature(&self, payload: &[u8]) -> Box<RoundState> {
        unimplemented!()
    }

    fn process_completedblock(&self, payload: &[u8]) -> Box<RoundState> {
        unimplemented!()
    }

    fn process_roundfailure(&self, payload: &[u8]) -> Box<RoundState> {
        unimplemented!()
    }
}
