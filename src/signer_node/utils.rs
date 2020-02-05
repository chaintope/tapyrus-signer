use crate::net::SignerID;
use bitcoin::PublicKey;

pub fn sender_index(sender_id: &SignerID, pubkey_list: &[PublicKey]) -> usize {
    //Unknown sender is already ignored.
    pubkey_list
        .iter()
        .position(|pk| pk == &sender_id.pubkey)
        .unwrap()
}
