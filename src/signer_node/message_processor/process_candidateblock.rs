use crate::blockdata::Block;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::utils::sender_index;
use crate::signer_node::{NodeParameters, NodeState};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::ECScalar;
use curv::{BigInt, FE};
use multi_party_schnorr::protocols::thresholdsig::bitcoin_schnorr::Keys;

pub fn process_candidateblock<T, C>(
    sender_id: &SignerID,
    block: &Block,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    log::info!(
        "candidateblock received. block hash for signing: {:?}",
        block.sighash()
    );

    match &prev_state {
        NodeState::Member {
            shared_block_secrets,
            block_shared_keys,
            master_index,
            ..
        } => {
            match params.rpc.testproposedblock(&block) {
                Ok(_) => {
                    let key = create_block_vss(block.clone(), params, conman);
                    // TODO: Errorを処理する必要あるかな？
                    NodeState::Member {
                        block_key: Some(key.u_i),
                        shared_block_secrets: shared_block_secrets.clone(),
                        block_shared_keys: block_shared_keys.clone(),
                        candidate_block: Some(block.clone()),
                        master_index: sender_index(sender_id, &params.pubkey_list),
                    }
                }
                Err(_e) => {
                    log::warn!("Received Invalid candidate block sender: {}", sender_id);
                    NodeState::Member {
                        block_key: None,
                        shared_block_secrets: shared_block_secrets.clone(),
                        block_shared_keys: block_shared_keys.clone(),
                        candidate_block: Some(block.clone()),
                        master_index: *master_index,
                    }
                }
            }
        }
        NodeState::Master {
            block_shared_keys,
            shared_block_secrets,
            signatures,
            round_is_done: false,
            ..
        } => {
            let key = create_block_vss(block.clone(), params, conman);
            NodeState::Master {
                block_key: Some(key.u_i),
                block_shared_keys: block_shared_keys.clone(),
                shared_block_secrets: shared_block_secrets.clone(),
                candidate_block: block.clone(),
                signatures: signatures.clone(),
                round_is_done: false,
            }
        }
        _ => prev_state.clone(),
    }
}

fn create_block_vss<T, C>(block: Block, params: &NodeParameters<T>, conman: &C) -> Keys
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    let sharing_params = params.sharing_params();
    let key = Sign::create_key(params.self_node_index + 1, None);

    let parties = (0..sharing_params.share_count)
        .map(|i| i + 1)
        .collect::<Vec<usize>>();

    let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
        sharing_params.threshold,
        sharing_params.share_count,
        &key.u_i,
        &parties,
    );
    let order: BigInt = FE::q();
    let (vss_scheme_for_negative, secret_shares_for_negative) = VerifiableSS::share_at_indices(
        sharing_params.threshold,
        sharing_params.share_count,
        &(ECScalar::from(&(order - key.u_i.to_big_int()))),
        &parties,
    );
    for i in 0..params.pubkey_list.len() {
        conman.send_message(Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Blockvss(
                    block.sighash(),
                    vss_scheme.clone(),
                    secret_shares[i],
                    vss_scheme_for_negative.clone(),
                    secret_shares_for_negative[i],
                ),
            ),
            sender_id: params.signer_id,
            receiver_id: Some(SignerID {
                pubkey: params.pubkey_list[i],
            }),
        });
    }
    key
}
