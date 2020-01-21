use crate::blockdata::hash::Hash;
use crate::blockdata::Block;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::utils::sender_index;
use crate::signer_node::ToSharedSecretMap;
use crate::signer_node::ToVerifiableSS;
use crate::signer_node::{NodeState, SignerNode};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;
use multi_party_schnorr::protocols::thresholdsig::bitcoin_schnorr::LocalSig;

pub fn process_blocksig<T, C>(
    sender_id: &SignerID,
    blockhash: Hash,
    gamma_i: FE,
    e: FE,
    signer_node: &mut SignerNode<T, C>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    match &signer_node.current_state {
        NodeState::Master {
            block_key,
            block_shared_keys,
            shared_block_secrets,
            candidate_block,
            signatures,
            round_is_done: false,
        } => {
            let mut new_signatures = signatures.clone();
            new_signatures.insert(sender_id.clone(), (gamma_i, e));
            log::trace!(
                "number of signatures: {:?} (threshold: {:?})",
                new_signatures.len(),
                signer_node.params.threshold
            );
            if candidate_block.sighash() != blockhash {
                log::error!("Invalid blockvss message received. Received message is based different block. expected: {:?}, actual: {:?}", candidate_block.sighash(), blockhash);
                return signer_node.current_state.clone();
            }

            if new_signatures.len() >= signer_node.params.threshold as usize {
                if block_shared_keys.is_none() {
                    log::error!("key is not shared.");
                    return signer_node.current_state.clone();
                }

                let parties = new_signatures
                    .keys()
                    .map(|k| sender_index(k, &signer_node.params.pubkey_list))
                    .collect::<Vec<usize>>();
                let key_gen_vss_vec: Vec<VerifiableSS> = signer_node.shared_secrets.to_vss();
                let local_sigs: Vec<LocalSig> = new_signatures
                    .values()
                    .map(|s| LocalSig {
                        gamma_i: s.0,
                        e: s.1,
                    })
                    .collect();
                let eph_vss_vec: Vec<VerifiableSS> = if block_shared_keys.unwrap().0 {
                    shared_block_secrets.for_positive().to_vss()
                } else {
                    shared_block_secrets.for_negative().to_vss()
                };
                let sum_of_local_sigs = LocalSig::verify_local_sigs(
                    &local_sigs,
                    &parties[..],
                    &key_gen_vss_vec,
                    &eph_vss_vec,
                );

                let verification = match sum_of_local_sigs {
                    Ok(vss_sum) => {
                        let signature = Sign::aggregate(
                            &vss_sum,
                            &local_sigs,
                            &parties[..],
                            block_shared_keys.unwrap().2,
                        );
                        let public_key = signer_node.priv_shared_keys.clone().unwrap().y;
                        let hash = candidate_block.sighash().into_inner();
                        match signature.verify(&hash, &public_key) {
                            Ok(_) => Ok(signature),
                            Err(e) => Err(e),
                        }
                    }
                    Err(_) => {
                        log::error!("local signature is invalid.");
                        return signer_node.current_state.clone();
                    }
                };
                let result = match verification {
                    Ok(signature) => {
                        let sig_hex = Sign::format_signature(&signature);
                        let new_block: Block =
                            candidate_block.add_proof(hex::decode(sig_hex).unwrap());
                        match signer_node.params.rpc.submitblock(&new_block) {
                            Ok(_) => Ok(new_block),
                            Err(e) => Err(e),
                        }
                    }
                    Err(_) => {
                        log::error!("aggregated signature is invalid");
                        return signer_node.current_state.clone();
                    }
                };
                match result {
                    Ok(new_block) => {
                        log::info!(
                                "Round Success. caindateblock(block hash for sign)={:?} completedblock={:?}",
                                candidate_block.sighash(),
                                new_block.hash()
                            );
                        // send completeblock message
                        log::info!("Broadcast CompletedBlock message. {:?}", new_block.hash());
                        let message = Message {
                            message_type: MessageType::BlockGenerationRoundMessages(
                                BlockGenerationRoundMessageType::Completedblock(new_block),
                            ),
                            sender_id: signer_node.params.signer_id.clone(),
                            receiver_id: None,
                        };
                        signer_node.connection_manager.broadcast_message(message);

                        return NodeState::Master {
                            block_key: block_key.clone(),
                            block_shared_keys: block_shared_keys.clone(),
                            shared_block_secrets: shared_block_secrets.clone(),
                            candidate_block: candidate_block.clone(),
                            signatures: new_signatures,
                            round_is_done: true,
                        };
                    }
                    Err(e) => {
                        log::error!("block rejected by Tapyrus Core: {:?}", e);
                    }
                }
            }
            NodeState::Master {
                block_key: block_key.clone(),
                block_shared_keys: block_shared_keys.clone(),
                shared_block_secrets: shared_block_secrets.clone(),
                candidate_block: candidate_block.clone(),
                signatures: new_signatures,
                round_is_done: false,
            }
        }
        state @ _ => state.clone(),
    }
}
