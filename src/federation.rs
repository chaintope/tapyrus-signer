use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::SignerID;
use crate::sign::Sign;
use crate::signer_node::{SharedSecret, SharedSecretMap};
use bitcoin::PublicKey;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use std::collections::HashSet;

#[derive(Debug)]
pub struct Federations {
    /// The vector of federations. This vector should be sorted by block height.
    federations: Vec<Federation>,
}

impl Federations {
    pub fn new(federations: Vec<Federation>) -> Self {
        let mut federations = federations;
        federations.sort_by_key(|f| f.block_height());
        Federations {
            federations: federations,
        }
    }

    pub fn len(&self) -> usize {
        self.federations.len()
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.federations.len() == 0 {
            return Err(Error::InvalidFederation(
                None,
                "At least the node must have one federation",
            ));
        }

        for federation in &self.federations {
            federation.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Federation {
    /// The id of the signer who runs this node.
    signer_id: SignerID,
    /// The block height where the federation would try to get started at.
    /// If the block height is 100, the aggregated public key of this federation is set at 99 height
    /// block. Then from the next block which height is 100, Tapyrus network would get started to
    /// use new aggreted public key to verify blocks.
    block_height: u64,
    /// The theshold which is requirement number of signer's agreements to produce block signatures.
    threshold: u8,
    /// Verifiable Secre Share and commitments from all signers in the federation.
    nodevss: Vec<Vss>,
}

impl Federation {
    pub fn new(public_key: PublicKey, block_height: u64, threshold: u8, nodevss: Vec<Vss>) -> Self {
        Self {
            signer_id: SignerID::new(public_key),
            block_height,
            threshold,
            nodevss,
        }
    }

    pub fn node_index(&self) -> usize {
        self.signers()
            .iter()
            .position(|i| *i == self.signer_id)
            .expect(&format!(
                "The federation doesn't include the own node({}).",
                self.signer_id
            ))
    }

    pub fn signers(&self) -> Vec<SignerID> {
        let mut signers: Vec<SignerID> = self
            .nodevss
            .iter()
            .map(|i| SignerID::new(i.sender_public_key.clone()))
            .collect();
        signers.sort();
        signers
    }

    pub fn block_height(&self) -> u64 {
        self.block_height
    }
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
    pub fn nodevss(&self) -> &Vec<Vss> {
        &self.nodevss
    }

    /// Returns Map collection of received shares from all each signers in Key Generation Protocol
    pub fn node_shared_secrets(&self) -> SharedSecretMap {
        let mut secret_shares = SharedSecretMap::new();
        for vss in &self.nodevss {
            secret_shares.insert(
                SignerID {
                    pubkey: vss.sender_public_key,
                },
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: ShamirSecretSharing {
                            threshold: (self.threshold - 1) as usize,
                            share_count: self.nodevss.len(),
                        },
                        commitments: vss
                            .positive_commitments
                            .iter()
                            .map(|i| i.to_point())
                            .collect(),
                    },
                    secret_share: vss.positive_secret,
                },
            );
        }
        secret_shares
    }

    /// Returns an aggregated share of the node.
    pub fn node_secret_share(&self) -> SharedKeys {
        let secret_shares = self.node_shared_secrets();

        let shared_keys =
            Sign::verify_vss_and_construct_key(&secret_shares, &(self.node_index() + 1))
                .expect("invalid vss");
        shared_keys
    }

    pub fn validate(&self) -> Result<(), Error> {
        // Check all sender is different.
        let signers = self.signers();
        let unique_set: HashSet<&SignerID> = signers.iter().collect();
        let is_overlap = unique_set.len() < signers.len();
        if is_overlap {
            return Err(Error::InvalidFederation(
                Some(self.block_height),
                "nodevss has overlapping sender vss.",
            ));
        }

        // Check all receiver is the node itself.
        if self
            .nodevss
            .iter()
            .any(|i| i.receiver_public_key != self.signer_id.pubkey)
        {
            return Err(Error::InvalidFederation(Some(self.block_height), "The nodevss has wrong receiver value. All VSS's receiver_public_key should be equal with publish key of the signer who runs the node."));
        }

        // Check all commitment length is correct.
        if self
            .nodevss
            .iter()
            .any(|vss| vss.positive_commitments.len() != self.threshold as usize)
        {
            return Err(Error::InvalidFederation(
                Some(self.block_height),
                "The nodevss has wrong vss which has wrong number of commitments.",
            ));
        }

        // verify each vss.
        if Sign::verify_vss_and_construct_key(&self.node_shared_secrets(), &(self.node_index() + 1))
            .is_err()
        {
            return Err(Error::InvalidFederation(
                Some(self.block_height),
                "The nodevss includes invalid share.",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::federation::{Federation, Federations};
    use crate::net::SignerID;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::node_vss::node_vss;
    use curv::elliptic::curves::traits::ECScalar;

    #[test]
    fn test_signers() {
        let federation = Federation::new(TEST_KEYS.pubkeys()[4], 0, 3, node_vss(0));

        let mut pubkeys = TEST_KEYS.pubkeys();
        pubkeys.sort_by(|a, b| {
            let a = a.key.serialize();
            let b = b.key.serialize();
            Ord::cmp(&a[..], &b[..])
        });
        let expected: Vec<SignerID> = pubkeys.into_iter().map(|i| SignerID::new(i)).collect();
        assert_eq!(expected, federation.signers());
    }

    fn valid_federation() -> Federation {
        Federation::new(TEST_KEYS.pubkeys()[4], 0, 3, node_vss(0))
    }

    #[test]
    fn test_federations_validate() {
        let federations = Federations::new(vec![valid_federation()]);
        assert!(federations.validate().is_ok());

        let federations = Federations::new(vec![]);
        match federations.validate() {
            Err(Error::InvalidFederation(_, m)) => {
                assert_eq!(m, "At least the node must have one federation")
            }
            _ => assert!(false, "it should error"),
        }
    }

    #[test]
    fn test_federation_validate() {
        let federation = valid_federation();
        assert!(federation.validate().is_ok());

        // federation has overlapped nodevss
        let mut federation = valid_federation();
        federation.nodevss.push(federation.nodevss[0].clone());
        match federation.validate() {
            Err(Error::InvalidFederation(_, m)) => {
                assert_eq!(m, "nodevss has overlapping sender vss.")
            }
            _ => assert!(false, "it should error"),
        }

        // federation has invalid vss whose receiver is not equal with the node itself.
        let mut federation = valid_federation();
        federation.nodevss[0].receiver_public_key = TEST_KEYS.pubkeys()[0];
        match federation.validate() {
            Err(Error::InvalidFederation(_, m)) => {
                assert_eq!(m, "The nodevss has wrong receiver value. All VSS's receiver_public_key should be equal with publish key of the signer who runs the node.")
            }
            _ => assert!(false, "it should error"),
        }

        // the federation has invalid number of commitment
        let mut federation = valid_federation();
        for i in federation.nodevss.iter_mut() {
            let commitments = &mut i.positive_commitments;
            commitments.drain(0..1);
        }
        match federation.validate() {
            Err(Error::InvalidFederation(_, m)) => assert_eq!(
                m,
                "The nodevss has wrong vss which has wrong number of commitments."
            ),
            _ => assert!(false, "it should error"),
        }

        // the federation has invalid secret share
        let mut federation = valid_federation();
        federation.nodevss[0].positive_secret = ECScalar::new_random();
        match federation.validate() {
            Err(Error::InvalidFederation(_, m)) => {
                assert_eq!(m, "The nodevss includes invalid share.")
            }
            _ => assert!(false, "it should error"),
        }
    }
}
