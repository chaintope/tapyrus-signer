use bitcoin::PublicKey;

/// Signerの識別子。公開鍵を識別子にする。
pub type SignerID = PublicKey;

/// ラウンドの状態を持つ構造体。シングルトン。
pub struct RoundState {
    current_master: SignerID,
}

impl RoundState {
    pub fn new(current_master: SignerID) -> RoundState {
        RoundState {
            current_master,
        }
    }
}
