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
    let params = signer_node.params.sharing_params();

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

#[cfg(test)]
mod tests {
    use super::process_nodevss;
    use crate::crypto::multi_party_schnorr::SharedKeys;
    use crate::net::SignerID;
    use crate::signer_node::NodeState;
    use crate::signer_node::SignerNode;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::test_vectors::*;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::*;
    use curv::FE;
    use serde_json::Value;

    #[test]
    fn test_process_nodevss_successfully() {
        // When
        //    - the node receives node VSS,
        //    - the node has all secrets to aggregate publickey
        // Then
        //    - the node generate shared key,
        //    - the node state does not change.
        let contents = load_test_vector("./tests/resources/process_nodevss.json").unwrap();

        let rpc = MockRpc::new();
        let (sender_id, vss, secret_share, mut signer_node, prev_state, expect_priv_shared_keys) =
            load_test_case(&contents, "process_nodevss_successfully", rpc);

        let next = process_nodevss(&sender_id, vss, secret_share, &mut signer_node);

        assert_eq!(
            signer_node.priv_shared_keys.unwrap(),
            expect_priv_shared_keys
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_nodevss_not_enough_number() {
        // When
        //    - the node receives node VSS,
        //    - but it is not enough to aggregate public key
        // Then
        //    - the node does not generate shared key,
        //    - the node state does not change.
        let contents = load_test_vector("./tests/resources/process_nodevss.json").unwrap();

        let rpc = MockRpc::new();
        let (sender_id, vss, secret_share, mut signer_node, prev_state, _expect_priv_shared_keys) =
            load_test_case(&contents, "process_nodevss_not_enough_number", rpc);

        let next = process_nodevss(&sender_id, vss, secret_share, &mut signer_node);

        assert_eq!(signer_node.priv_shared_keys, None);
        assert_eq!(next, prev_state);
    }

    fn load_test_case(
        contents: &Value,
        case: &str,
        rpc: MockRpc,
    ) -> (
        SignerID,
        VerifiableSS,
        FE,
        SignerNode<MockRpc, TestConnectionManager>,
        NodeState,
        SharedKeys,
    ) {
        let v = &contents["cases"][case];

        let sender = to_signer_id(&v["received"]["sender"].as_str().unwrap().to_string());
        let vss: VerifiableSS = serde_json::from_value(v["received"]["vss"].clone()).unwrap();
        let secret = to_fe(&v["received"]["secret_share"]);
        let priv_shared_key: SharedKeys =
            serde_json::from_value(v["priv_shared_key"].clone()).unwrap();
        let con = TestConnectionManager::new();
        let params = to_node_parameters(&v, rpc);
        let shared_secrets = v["shared_secrets"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, value)| (to_signer_id(k), to_shared_secret(&value)))
            .collect();
        let mut node = SignerNode::new(con, params);
        node.current_state = NodeState::Joining;
        node.shared_secrets = shared_secrets;
        let prev_state = NodeState::Joining;
        (sender, vss, secret, node, prev_state, priv_shared_key)
    }
}
