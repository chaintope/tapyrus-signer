use crate::net::{ConnectionManager, SignerID};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::{NodeState, SharedSecret, SignerNode};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;

pub fn process_nodevss<T, C>(
    sender_id: &SignerID,
    vss: VerifiableSS,
    secret_share: FE,
    signer_node: &mut SignerNode<T, C>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    let params = signer_node.sharing_params();

    signer_node.shared_secrets.insert(
        sender_id.clone(),
        SharedSecret {
            vss: vss.clone(),
            secret_share,
        },
    );

    if signer_node.shared_secrets.len() == signer_node.params.pubkey_list.len() {
        let shared_keys = Sign::verify_vss_and_construct_key(
            &params,
            &signer_node.shared_secrets,
            &(signer_node.params.self_node_index + 1),
        )
        .expect("invalid vss");

        signer_node.priv_shared_keys = Some(shared_keys.clone());
        log::info!("All VSSs are collected. Ready to start Signature Issuing Protocol");
        log::debug!(
            "All VSSs are stored. My share for generating local sig: {:?}, Aggregated Pubkey: {:?}",
            shared_keys.x_i,
            shared_keys.y
        );
    }
    signer_node.current_state.clone()
}
