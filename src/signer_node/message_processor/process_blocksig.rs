use crate::blockdata::hash::Hash;
use crate::blockdata::Block;
use crate::crypto::multi_party_schnorr::{LocalSig, SharedKeys};
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::utils::sender_index;
use crate::signer_node::NodeState;
use crate::signer_node::ToVerifiableSS;
use crate::signer_node::{NodeParameters, SharedSecretMap, ToSharedSecretMap};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;

pub fn process_blocksig<T, C>(
    sender_id: &SignerID,
    blockhash: Hash,
    gamma_i: FE,
    e: FE,
    priv_shared_keys: &SharedKeys,
    shared_secrets: &SharedSecretMap,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    match prev_state {
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
                params.threshold
            );
            if candidate_block.sighash() != blockhash {
                log::error!("Invalid blockvss message received. Received message is based different block. expected: {:?}, actual: {:?}", candidate_block.sighash(), blockhash);
                return prev_state.clone();
            }

            if new_signatures.len() >= params.threshold as usize {
                if block_shared_keys.is_none() {
                    log::error!("key is not shared.");
                    return prev_state.clone();
                }

                let parties = new_signatures
                    .keys()
                    .map(|k| sender_index(k, &params.pubkey_list))
                    .collect::<Vec<usize>>();
                let key_gen_vss_vec: Vec<VerifiableSS> = shared_secrets.to_vss();
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
                        let public_key = priv_shared_keys.y;
                        let hash = candidate_block.sighash().into_inner();
                        match signature.verify(&hash, &public_key) {
                            Ok(_) => Ok(signature),
                            Err(e) => Err(e),
                        }
                    }
                    Err(_) => {
                        log::error!("local signature is invalid.");
                        return prev_state.clone();
                    }
                };
                let result = match verification {
                    Ok(signature) => {
                        let sig_hex = Sign::format_signature(&signature);
                        let new_block: Block =
                            candidate_block.add_proof(hex::decode(sig_hex).unwrap());
                        match params.rpc.submitblock(&new_block) {
                            Ok(_) => Ok(new_block),
                            Err(e) => Err(e),
                        }
                    }
                    Err(_) => {
                        log::error!("aggregated signature is invalid");
                        return prev_state.clone();
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
                            sender_id: params.signer_id.clone(),
                            receiver_id: None,
                        };
                        conman.broadcast_message(message);

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

#[cfg(test)]
mod tests {
    use super::process_blocksig;
    use crate::blockdata::Block;
    use crate::crypto::multi_party_schnorr::SharedKeys;
    use crate::signer_node::*;
    use crate::tests::helper::blocks::get_block;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_parameters_builder::NodeParametersBuilder;
    use crate::tests::helper::node_state_builder::{Builder, Master, Member};
    use crate::tests::helper::rpc::MockRpc;
    use bitcoin::{PrivateKey, PublicKey};
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::*;
    use curv::elliptic::curves::traits::*;
    use curv::{BigInt, FE};
    use std::collections::BTreeMap;
    use std::str::FromStr;

    fn prepare() -> (
        Block,
        TestConnectionManager,
        NodeParameters<MockRpc>,
        ShamirSecretSharing,
    ) {
        let params = NodeParametersBuilder::new().rpc(MockRpc::new()).build();
        let sharing_params = ShamirSecretSharing {
            threshold: params.sharing_params().threshold,
            share_count: params.sharing_params().share_count,
        };
        (
            get_block(0),
            TestConnectionManager::new(),
            params,
            sharing_params,
        )
    }

    fn test_data(sharing_params: ShamirSecretSharing) -> (FE, FE, SharedKeys, SharedSecretMap, FE) {
        let gamma_i = ECScalar::from(&BigInt::from(100));
        let e = ECScalar::from(&BigInt::from(200));
        let priv_shared_key = SharedKeys {
            x_i: ECScalar::from(&BigInt::from(300)),
            y: ECPoint::generator(),
        };
        let mut shared_secrets = SharedSecretMap::new();
        for signer_id in TEST_KEYS.signer_ids() {
            shared_secrets.insert(
                signer_id,
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: sharing_params.clone(),
                        commitments: vec![],
                    },
                    secret_share: FE::zero(),
                },
            );
        }
        let block_key = ECScalar::new_random();
        (gamma_i, e, priv_shared_key, shared_secrets, block_key)
    }

    #[test]
    fn test_process_blocksig_for_member() {
        // if node state is Member, process_blocksig should return Member state(it is same as prev_state).
        let (block, conman, params, sharing_params) = prepare();

        let (gamma_i, e, priv_shared_key, shared_secrets, _) = test_data(sharing_params);
        let prev_state = Member::new().master_index(0).build();

        let next = process_blocksig(
            &TEST_KEYS.signer_id(),
            block.hash(),
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_invalid_block() {
        // if node receives invalid block (that means block is not the same as candidate block),
        // node should return prev_state immediately.
        let (block, conman, params, sharing_params) = prepare();

        let (gamma_i, e, priv_shared_key, shared_secrets, _) = test_data(sharing_params);
        let prev_state = Master::new().candidate_block(block).build();

        let invalid_block = get_block(1);
        let next = process_blocksig(
            &TEST_KEYS.signer_id(),
            invalid_block.sighash(),
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_1_valid_block() {
        // when node
        //  - receives a valid block,
        //  - but the number of signatures(2) is not enough (3) to generate a aggregated signature,
        // node should return new Master state which has signatures.
        let (block, conman, params, sharing_params) = prepare();

        let (gamma_i, e, priv_shared_key, shared_secrets, _) = test_data(sharing_params);
        let mut signatures = BTreeMap::new();
        let signer_ids = TEST_KEYS.signer_ids();
        let gamma_0 = ECScalar::from(&BigInt::from(1000));
        signatures.insert(signer_ids[1], (gamma_0, e));

        let prev_state = Master::new()
            .candidate_block(block.clone())
            .signatures(signatures)
            .build();

        let next = process_blocksig(
            &TEST_KEYS.signer_id(),
            block.sighash(),
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        match prev_state {
            NodeState::Master { signatures, .. } => {
                assert_eq!(signatures.len(), 1);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
        match next {
            NodeState::Master {
                signatures,
                round_is_done,
                ..
            } => {
                assert_eq!(signatures.len(), 2);
                assert_eq!(round_is_done, false);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
    }

    #[test]
    fn test_process_blocksig_with_no_block_key() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - but block key is not supplied.
        // node should return prev_state.
        let (block, conman, params, sharing_params) = prepare();

        let (gamma_i, e, priv_shared_key, shared_secrets, _) = test_data(sharing_params);
        let mut signatures = BTreeMap::new();
        let signer_ids = TEST_KEYS.signer_ids();
        let gamma_0 = ECScalar::from(&BigInt::from(1000));
        let gamma_1 = ECScalar::from(&BigInt::from(1001));
        signatures.insert(signer_ids[1], (gamma_0, e));
        signatures.insert(signer_ids[2], (gamma_1, e));

        let prev_state = Master::new()
            .candidate_block(block.clone())
            .signatures(signatures)
            .build();

        let next = process_blocksig(
            &TEST_KEYS.signer_id(),
            block.sighash(),
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_successfully() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - has block key,
        // then node should
        //  - call rpc submitblock
        //  - send message `Completedblock`
        //  - return Master

        let private_key =
            PrivateKey::from_wif("cQYYBMFS9dRR3Mt16gW4jixCqSiMhCwuDMHUBs6WeHMTxMnsq8Gh").unwrap();
        let pubkey_1 = PublicKey::from_str(
            "03e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee1",
        )
        .unwrap();
        let pubkey_2 = PublicKey::from_str(
            "03842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2",
        )
        .unwrap();
        let pubkey_3 = PublicKey::from_str(
            "02a1c8965ed06987fa6d7e0f552db707065352283ab3c1471510b12a76a5905287",
        )
        .unwrap();

        let conman = TestConnectionManager::new();
        let sharing_params = ShamirSecretSharing {
            threshold: 1,
            share_count: 3,
        };
        let mut rpc = MockRpc::new();
        rpc.should_call_submitblock(Ok(()));
        let params = NodeParametersBuilder::new()
            .rpc(rpc)
            .threshold(1)
            .pubkey_list(vec![pubkey_1, pubkey_2, pubkey_3])
            .private_key(private_key)
            .build();

        let block_key = ECScalar::from(
            &BigInt::from_str_radix(
                "dc0ba5ed1aae7e573fe4450f1faa4d98be93a973df5156b5350ef059376a3dbc",
                16,
            )
            .unwrap(),
        );
        let hex = hex::decode("01000000a8b61e31f3d6b655eb8fc387a22d139f141a14cb79c3a12a18192aa4d25941dfcb2edbbd1385a5d5c3bd037b6fd0ca8d691c13875fa74014a115f096a59be33a3447345d02f1420d9f5bc070aa00dc2bcb201ef470842fa5ec4f5c9986345ee91ae23b5e00000101000000010000000000000000000000000000000000000000000000000000000000000000260000000401260101ffffffff0200f2052a010000001976a9145f3f3758e7a4cf159c7bdb441ae4ff80999c62e888ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000").unwrap();
        let block = Block::new(hex);

        let signer_1 = SignerID { pubkey: pubkey_1 };
        let signer_2 = SignerID { pubkey: pubkey_2 };
        let signer_3 = SignerID { pubkey: pubkey_3 };

        let hash = block.sighash();
        let gamma_i = ECScalar::from(
            &BigInt::from_str_radix(
                "6a391bd26d20b9a02188ee8bf8a6f1784b483fd8ecf97eaf2573cca695b629ee",
                16,
            )
            .unwrap(),
        );
        let e = ECScalar::from(
            &BigInt::from_str_radix(
                "91873704d52454f1d56eba45aa78e227e8bb214857d92e36bce3d2a4806685aa",
                16,
            )
            .unwrap(),
        );
        let priv_shared_key = SharedKeys {
            x_i: ECScalar::from(
                &BigInt::from_str_radix(
                    "5a4485e600f9b9ae896e86667c22f66ea60b098f59dbeb65af969d0de7cce51b",
                    16,
                )
                .unwrap(),
            ),
            y: ECPoint::from_coor(
                &BigInt::from_str_radix(
                    "5700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3",
                    16,
                )
                .unwrap(),
                &BigInt::from_str_radix(
                    "795417c110e4482230f624e75d6e7fcd6ca11ea393cd21f1760049a7528f3686",
                    16,
                )
                .unwrap(),
            ),
        };

        let mut shared_secrets = SharedSecretMap::new();
        shared_secrets.insert(
            signer_1,
            SharedSecret {
                vss: VerifiableSS {
                    parameters: sharing_params.clone(),
                    commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee1",
                                16,
                            )
                            .expect("invalid x-cood 1"),
                            &BigInt::from_str_radix(
                                "0be702bc5fdcc63822040f31042a0f1284060826f5744beee13c58278b742853",
                                16,
                            )
                            .expect("invalid y-cood 1"),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "8815358b9ed40317c51a967a7b7d8e58b0c081af28e196c62277f8ea6078707a",
                                16,
                            )
                            .expect("invalid x-cood 2"),
                            &BigInt::from_str_radix(
                                "85874f417ffdc65a2a57a9bef08854738fd5ca8d2493bbe43b0ed494b6554e73",
                                16,
                            )
                            .expect("invalid y-cood 2"),
                        ),
                    ],
                },
                secret_share: ECScalar::from(
                    &BigInt::from_str_radix(
                        "4a9ba0134995e23cf44e2db20d9c0af983f02a0fb958f383c9f64861bea73df5",
                        16,
                    )
                    .expect("invalid secret_share"),
                ),
            },
        );

        shared_secrets.insert(
            signer_2,
            SharedSecret {
                vss: VerifiableSS {
                    parameters: sharing_params.clone(),
                    commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "c89314bbafe84e0a29be49397843808ab8d94118dcc1bdf619d04fee039ccd9f",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "2d5c3cd7200f27b067710390a3ded5301cff64bce8ddf9fcf8b9944200e969e3",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "df7557e4ed7ccdd068b1218b5569ae8815bd350dfaf359576a9bd56cf2bbee3a",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                },
                secret_share: ECScalar::from(
                    &BigInt::from_str_radix(
                        "38a62cfc110f0970e59788f80010237a83a63204681603c982774aa4c4263fa7",
                        16,
                    )
                    .expect("invalid secret_share"),
                ),
            },
        );

        shared_secrets.insert(
            signer_3,
            SharedSecret {
                vss: VerifiableSS {
                    parameters: sharing_params.clone(),
                    commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "a1c8965ed06987fa6d7e0f552db707065352283ab3c1471510b12a76a5905287",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "516e77d282d611bb99384f63299aeb7038b9f99c369c688cb16136b7151cf842",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "f5bd401e73dd7970863a7e1ae4656fe87e5e2dfc3c58b6430c5c4b9854ced416",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "1edcd081537ff85fde6c85bdc169e065ee72ab63c5fad0fa633551e876578e4d",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                },
                secret_share: ECScalar::from(
                    &BigInt::from_str_radix(
                        "d702b8d6a654ce00af88cfbc6e76c7f959238a61e7b5945422fb68943535a8c0",
                        16,
                    )
                    .expect("invalid secret_share"),
                ),
            },
        );

        let mut signatures = BTreeMap::new();
        let gamma_0 = ECScalar::from(
            &BigInt::from_str_radix(
                "2e50de7be75487b17e9e5af27928b2db355fcce4f8e0700a6d3a2e80f817c8f8",
                16,
            )
            .unwrap(),
        );
        signatures.insert(signer_2, (gamma_0, e));

        let mut shared_block_secrets = BTreeMap::new();
        shared_block_secrets.insert(
            signer_3,
            (
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: sharing_params.clone(),
                        commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "d438e84a76cd8a764017c9346ddbed174c0865b97a50e4d2d337d3c6122488a2",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "a5ba179261c5ccad934cf7e20f7d7dc05dc38edc104ab5b30a355c35c5d41634",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "2885667a51c527d790d808e324f3c4a7c26a0952404438e2f910f6d4a49292f5",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "c44cab8783c3aed4757f667231a18ae965ff3c8707e4e8a31a0eca403a8e7d9d",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                    },
                    secret_share: ECScalar::from(
                        &BigInt::from_str_radix(
                            "59a2669bc7dc39bfc2cae1bc3aabe39cc5995a5b0cf6537be90cd084f9a6529f",
                            16,
                        )
                        .unwrap(),
                    ),
                },
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: sharing_params.clone(),
                        commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "d438e84a76cd8a764017c9346ddbed174c0865b97a50e4d2d337d3c6122488a2",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "5a45e86d9e3a33526cb3081df082823fa23c7123efb54a4cf5caa3c93a2be5fb",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "74e1b15e5dce4264c8a4a766680f8f82f85a8f176a7c7d2a2912e8735a4f69d8",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "fd3b650bc386369819ac7a9d2707dc1d706028fdcd951340963f1512b3e8fd07",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                    },
                    secret_share: ECScalar::from(
                        &BigInt::from_str_radix(
                            "0d13812f053500d33673637a2827b1366c7aa02ca2874cea0a9f15859d608aa3",
                            16,
                        )
                        .unwrap(),
                    ),
                },
            ),
        );

        shared_block_secrets.insert(
            signer_2,
            (
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: sharing_params.clone(),
                        commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "e957fa3c937022fe19bfa38b75b8c4ac5e88c9406b5a0eda284ee48f22dbae9e",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "7ede5a328ead0d9ac8c3e9a63d702c4a7ca2613caba9700a5a28e80d52031f15",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "3b103b7f25160d8915d80b331ab304ba571f4314d545e22a7f3b31d62e22dea5",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "498fb50f013daf905724be8cac1d53f4104664022952090fc55ac3760a210a4a",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                    },
                    secret_share: ECScalar::from(
                        &BigInt::from_str_radix(
                            "1942a2fea051f34e9e5e55a58e3482a45cdaadab5bd7bb80055b64eeacce90d7",
                            16,
                        )
                        .unwrap(),
                    ),
                },
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: sharing_params.clone(),
                        commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "e957fa3c937022fe19bfa38b75b8c4ac5e88c9406b5a0eda284ee48f22dbae9e",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "8121a5cd7152f265373c1659c28fd3b5835d9ec354568ff5a5d717f1adfcdd1a",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "bcc101561615a3ccdc7767c688cd0e79c5904a29a4c2d7b58ac415b5bed44f1a",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "2384c11cea3a943f5ee57074ae586713fe777036ddf32beb314bfc063a160c36",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                    },
                    secret_share: ECScalar::from(
                        &BigInt::from_str_radix(
                            "52d3edf66a690c04686a9c3b277d0fbb6fb1ef7c7692899d007b1f59bbe3aa30",
                            16,
                        )
                        .unwrap(),
                    ),
                },
            ),
        );

        shared_block_secrets.insert(
            signer_1,
            (
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: sharing_params.clone(),
                        commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "0bab4e3c97cda086318cd4061396d32c7b32028a111a77a2dd9fb197bc0c40d0",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "e98dd2752dd88a6e8c0a9fdd264ba62fb7d25ed3208b8dbbe3819b36e5fd39f8",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "120be2048bddc31ceb3497ce2afbcdc351f0746d588db1d151eb464b3df4c86b",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "8b05be8fede2fd9af223b497805afb97b77516227ca6a39f8011efc2ac403745",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                    },
                    secret_share: ECScalar::from(
                        &BigInt::from_str_radix(
                            "7b1127b8ed8520ba16b5e60333204cc023e2c267bc3d9028294507bdb2d8acf4",
                            16,
                        )
                        .unwrap(),
                    ),
                },
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: sharing_params.clone(),
                        commitments: vec![
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "0bab4e3c97cda086318cd4061396d32c7b32028a111a77a2dd9fb197bc0c40d0",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "16722d8ad227759173f56022d9b459d0482da12cdf7472441c7e64c81a02c237",
                                16,
                            )
                            .unwrap(),
                        ),
                        ECPoint::from_coor(
                            &BigInt::from_str_radix(
                                "255bebdc03fbd82ff14561244f81042fd74c9f4fc0103a680728778a98e97767",
                                16,
                            )
                            .unwrap(),
                            &BigInt::from_str_radix(
                                "86dfeec343b7c1d22175ca83d8a2c5def0215bc3250c45787cf4f53413520e45",
                                16,
                            )
                            .unwrap(),
                        ),
                    ],
                    },
                    secret_share: ECScalar::from(
                        &BigInt::from_str_radix(
                            "3c07e8667c9481ec0c828a3cad5aaf906205c7a349af2efafe6424a150c85f13",
                            16,
                        )
                        .unwrap(),
                    ),
                },
            ),
        );

        let block_shared_keys = Some((
            true,
            ECScalar::from(
                &BigInt::from_str_radix(
                    "edf6315355b34dc877df1d64fc00b3014656ca6e250b9f2417ad3d31594d906a",
                    16,
                )
                .unwrap(),
            ),
            ECPoint::from_coor(
                &BigInt::from_str_radix(
                    "5ae1f76b9c579af4afedcec8d04657da39aad660b091f0cb3014bb9d42157d2d",
                    16,
                )
                .unwrap(),
                &BigInt::from_str_radix(
                    "f4c24144cc8cb4692c41d6ce6c4cf000342f132a72c6c4197925eb7231d0ce2d",
                    16,
                )
                .unwrap(),
            ),
        ));

        let prev_state = Master::new()
            .block_key(Some(block_key))
            .candidate_block(block.clone())
            .block_shared_keys(block_shared_keys)
            .shared_block_secrets(shared_block_secrets)
            .signatures(signatures)
            .build();

        let next = process_blocksig(
            &signer_1,
            hash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        match next {
            NodeState::Master {
                signatures,
                round_is_done,
                ..
            } => {
                params.rpc.assert();
                assert_eq!(signatures.len(), 2);
                assert_eq!(round_is_done, true);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
    }
}
