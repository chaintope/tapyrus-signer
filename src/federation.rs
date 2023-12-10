use crate::crypto::multi_party_schnorr::{SharedKeys, Signature};
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::SignerID;
use crate::sign::Sign;
use crate::signer_node::{SharedSecret, SharedSecretMap};
use crate::tapyrus::blockdata::block::XField;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use std::collections::HashSet;
use tapyrus::PublicKey;

#[derive(Debug, Clone)]
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

    pub fn get_by_block_height(&self, block_height: u32) -> &Federation {
        self.federations
            .iter()
            .filter(|f| f.block_height <= block_height)
            .last()
            .expect("Federations should not be empty.")
    }

    pub fn last(&self) -> &Federation {
        self.federations
            .last()
            .expect("Federations should not be empty.")
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

        // Check the block
        let unique_block_height: HashSet<u32> =
            self.federations.iter().map(|i| i.block_height).collect();
        if unique_block_height.len() != self.federations.len() {
            return Err(Error::InvalidFederation(
                None,
                "The federations include block height duplication. The block height in all federations should be unique.",
            ));
        }

        for federation in &self.federations {
            federation.validate()?;
        }

        Ok(())
    }

    /// Create Federations instance from:
    ///   * `pubkey` The public key of a signer who runs this node.
    ///   * `toml` toml string for federations.
    pub fn from_pubkey_and_toml(pubkey: &PublicKey, toml: &str) -> Result<Self, Error> {
        let ser: SerFederations = toml::from_str(toml)?;

        let vec: Vec<Federation> = ser
            .federation
            .into_iter()
            .map(|i| Federation::from(*pubkey, i))
            .collect::<Result<Vec<_>, _>>()?;

        let r = Federations::new(vec);
        r.validate()?;

        Ok(r)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Federation {
    /// The id of the signer who runs this node.
    signer_id: SignerID,
    /// The block height where the federation would try to get started at.
    /// If the block height is 100, the aggregated public key of this federation is set at 99 height
    /// block. Then from the next block which height is 100, Tapyrus network would get started to
    /// use new aggreted public key to verify blocks.
    block_height: u32,
    /// The threshold which is requirement number of signer's agreements to produce block signatures.
    /// This field must be None when the signer is not a member of the federation.
    threshold: Option<u8>,
    /// Verifiable Secret Share and commitments from all signers in the federation.
    /// This field must be None when the signer is not a member of the federation.
    nodevss: Option<Vec<Vss>>,
    /// The federation parameter
    /// aggregated public key / max block size
    xfield: XField,
    /// pubkey for signature verification
    pub verification_key: Option<PublicKey>,
    /// federation signature
    pub signature: Option<Signature>,
}

impl Federation {
    pub fn new(
        public_key: PublicKey,
        block_height: u32,
        threshold: Option<u8>,
        nodevss: Option<Vec<Vss>>,
        xfield: XField,
        verification_key: Option<PublicKey>,
        signature: Option<Signature>,
    ) -> Self {
        Self {
            signer_id: SignerID::new(public_key),
            block_height,
            threshold,
            nodevss,
            xfield,
            verification_key,
            signature,
        }
    }

    pub fn from(pubkey: PublicKey, ser: SerFederation) -> Result<Self, Error> {
        let xfield: XField = match (ser.aggregated_public_key, ser.max_block_size) {
            (Some(pubkey), None) => XField::AggregatePublicKey(pubkey),
            (None, Some(x)) => XField::MaxBlockSize(x),
            _ => {
                return Err(Error::InvalidFederation(
                    Some(ser.block_height),
                    "No xfield in federation. Aggregated pubkey or max block size is expected",
                ))
            }
        };
        let sig: Option<Signature> = match ser.block_height {
            0 => None,
            _ => {
                let signature_hex = ser.signature.clone().unwrap_or_else(|| {
                    format!("No signature in federation at height {}", ser.block_height)
                });

                match multi_party_signature_from_hex(signature_hex.as_str()) {
                    Ok(sig) => Some(sig),
                    Err(e) => return Err(e),
                }
            }
        };
        Ok(Self::new(
            pubkey,
            ser.block_height,
            ser.threshold,
            ser.nodevss,
            xfield,
            None,
            sig,
        ))
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
            .nodevss()
            .iter()
            .map(|i| SignerID::new(i.sender_public_key.clone()))
            .collect();
        signers.sort();
        signers
    }

    pub fn block_height(&self) -> u32 {
        self.block_height
    }
    pub fn threshold(&self) -> Option<u8> {
        self.threshold
    }
    pub fn nodevss(&self) -> &Vec<Vss> {
        self.nodevss
            .as_ref()
            .expect("The nodevss must not None, when it's used.")
    }
    pub fn xfield(&self) -> &XField {
        &self.xfield
    }

    pub fn aggregated_public_key(&self) -> Option<PublicKey> {
        match self.xfield {
            XField::AggregatePublicKey(x) => Some(x),
            _ => None,
        }
    }
    pub fn max_block_size(&self) -> Option<u32> {
        match self.xfield {
            XField::MaxBlockSize(x) => Some(x),
            _ => None,
        }
    }

    /// Returns Map collection of received shares from all each signers in Key Generation Protocol
    pub fn node_shared_secrets(&self) -> SharedSecretMap {
        let mut secret_shares = SharedSecretMap::new();
        if let Some(threshold) = self.threshold {
            for vss in self.nodevss() {
                secret_shares.insert(
                    SignerID {
                        pubkey: vss.sender_public_key,
                    },
                    SharedSecret {
                        vss: VerifiableSS {
                            parameters: ShamirSecretSharing {
                                threshold: (threshold - 1) as usize,
                                share_count: self.nodevss().len(),
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
        // Skip validation if the signer of the node is not a member of the federation.
        if self.threshold.is_none() && self.nodevss.is_none() {
            return Ok(());
        }

        if self.threshold.is_none() || self.nodevss.is_none() {
            return Err(Error::InvalidFederation(
                Some(self.block_height),
                "The threshold and the nodevss must be set if the signer of the node is a member of the federation. If it is not a member of federation, you must set neither the threshold nor the nodevss.",
            ));
        }

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
            .nodevss()
            .iter()
            .any(|i| i.receiver_public_key != self.signer_id.pubkey)
        {
            return Err(Error::InvalidFederation(Some(self.block_height), "The nodevss has wrong receiver value. All VSS's receiver_public_key should be equal with publish key of the signer who runs the node."));
        }

        // Check all commitment length is correct.
        if let Some(threshold) = self.threshold {
            if self
                .nodevss()
                .iter()
                .any(|vss| vss.positive_commitments.len() != threshold as usize)
            {
                return Err(Error::InvalidFederation(
                    Some(self.block_height),
                    "The nodevss has wrong vss which has wrong number of commitments.",
                ));
            }
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

    /// Returns whether the signer who hosts the node is a member of this federation.
    /// It is `true` if the signer is a member.
    pub fn is_member(&self) -> bool {
        self.threshold.is_some() && self.nodevss.is_some()
    }

    pub fn from_pubkey(
        pubkey: PublicKey,
        block_height: u32,
        threshold: u8,
        nodevss: Vec<Vss>,
        signature: Option<Signature>,
    ) -> Self {
        Self::new(
            pubkey,
            block_height,
            Some(threshold),
            Some(nodevss),
            XField::AggregatePublicKey(pubkey),
            None,
            signature,
        )
    }

    pub fn from_maxblocksize(
        pubkey: PublicKey,
        block_height: u32,
        maxblocksize: u32,
        signature: Option<Signature>,
    ) -> Self {
        Self::new(
            pubkey,
            block_height,
            None,
            None,
            XField::MaxBlockSize(maxblocksize),
            None,
            signature,
        )
    }

    pub fn to_ser(self) -> Result<SerFederation, Error> {
        let nodevss = self.nodevss.clone();
        let signature: String = Sign::format_signature(&self.signature.clone().unwrap());

        let federation = match self.xfield {
            XField::AggregatePublicKey(_) => SerFederation {
                block_height: self.block_height,
                threshold: self.threshold,
                nodevss: nodevss,
                signature: Some(signature),
                aggregated_public_key: self.aggregated_public_key(),
                max_block_size: None,
            },
            XField::MaxBlockSize(_) => SerFederation {
                block_height: self.block_height,
                threshold: self.threshold,
                nodevss: nodevss,
                signature: Some(signature),
                max_block_size: self.max_block_size(),
                aggregated_public_key: None,
            },
            _ => SerFederation {
                block_height: self.block_height,
                threshold: self.threshold,
                nodevss: nodevss,
                signature: Some(signature),
                max_block_size: None,
                aggregated_public_key: None,
            },
        };
        Ok(federation)
    }
}

pub fn multi_party_signature_from_hex(s: &str) -> Result<Signature, Error> {
    if s.len() != 128 {
        return Err(Error::InvalidSig);
    }

    let v_hex = &s[0..64];
    let sigma_hex = &s[64..128];

    let v_bytes = hex::decode(v_hex).map_err(|_| Error::InvalidSig)?;

    let v_ge = GE::from_bytes(&v_bytes).map_err(|_| Error::InvalidSig)?;

    let sigma = BigInt::from_str_radix(sigma_hex, 16).unwrap();
    let sigma_fe: FE = ECScalar::from(&sigma);

    Ok(Signature {
        sigma: sigma_fe,
        v: v_ge,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerFederations {
    federation: Vec<SerFederation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerFederation {
    #[serde(rename = "block-height")]
    block_height: u32,
    threshold: Option<u8>,
    #[serde(rename = "node-vss")]
    nodevss: Option<Vec<Vss>>,
    #[serde(rename = "aggregated-public-key")]
    aggregated_public_key: Option<PublicKey>,
    #[serde(rename = "max-block-size")]
    max_block_size: Option<u32>,
    #[serde(rename = "signature")]
    signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::crypto::multi_party_schnorr::Signature;
    use crate::errors::Error;
    use crate::federation::{Federation, Federations};
    use crate::hex::FromHex;
    use crate::net::SignerID;
    use crate::tapyrus::blockdata::block::XField;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::node_vss::node_vss;
    use curv::arithmetic::traits::Converter;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{BigInt, GE};
    use std::str::FromStr;
    use tapyrus::PublicKey;

    use super::SerFederation;

    #[test]
    fn test_get_by_block_height() {
        let federation0 = Federation::new(
            TEST_KEYS.pubkeys()[4],
            0,
            Some(3),
            Some(node_vss(0)),
            XField::AggregatePublicKey(TEST_KEYS.aggregated()),
            None,
            None,
        );
        let federation100 = Federation::new(
            TEST_KEYS.pubkeys()[4],
            100,
            Some(3),
            Some(node_vss(1)),
            XField::AggregatePublicKey(TEST_KEYS.aggregated()),
            None,
            None,
        );
        let federation200 = Federation::new(
            TEST_KEYS.pubkeys()[4],
            200,
            Some(4),
            Some(node_vss(2)),
            XField::AggregatePublicKey(TEST_KEYS.aggregated()),
            None,
            None,
        );
        let federations = Federations::new(vec![
            federation0.clone(),
            federation100.clone(),
            federation200.clone(),
        ]);
        assert_eq!(federations.get_by_block_height(99).clone(), federation0);
        assert_eq!(federations.get_by_block_height(100).clone(), federation100);
        assert_eq!(federations.get_by_block_height(101).clone(), federation100);
    }

    #[test]
    fn test_signers() {
        let federation = Federation::new(
            TEST_KEYS.pubkeys()[0],
            0,
            Some(3),
            Some(node_vss(0)),
            XField::AggregatePublicKey(TEST_KEYS.aggregated()),
            None,
            None,
        );

        let expected: Vec<SignerID> = TEST_KEYS
            .pubkeys()
            .into_iter()
            .map(|i| SignerID::new(i))
            .collect();
        assert_eq!(expected, federation.signers());
    }

    fn valid_federation() -> Federation {
        let sigma = ECScalar::from(
            &BigInt::from_str_radix(
                "16b63d6f3b5a88762d4477b843b857a3bf86677c7044db22a9aada2eb17d0641",
                16,
            )
            .expect("Failed to parse BigInt"),
        );

        let v_bytes =
            Vec::from_hex("dde06d981f17045b11c8db7b47846ceca4825f286756440ea158e0b2dba86028")
                .expect("Failed to decode hex string");
        let v = GE::from_bytes(&v_bytes).expect("Failed to create GE from bytes");

        let sig = Signature { sigma, v };

        Federation::new(
            TEST_KEYS.pubkeys()[0],
            10,
            Some(3),
            Some(node_vss(0)),
            XField::AggregatePublicKey(TEST_KEYS.aggregated()),
            None,
            Some(sig),
        )
    }

    fn valid_federation_maxblocksize() -> Federation {
        let mut federation = valid_federation();

        federation.xfield = XField::MaxBlockSize(400000);
        federation
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

        let federation = valid_federation();
        let federations = Federations::new(vec![federation.clone(), federation]);
        match federations.validate() {
            Err(Error::InvalidFederation(None, m)) => {
                assert_eq!(m, "The federations include block height duplication. The block height in all federations should be unique.")
            }
            _ => assert!(false, "it should error"),
        }

        let federations =
            Federations::new(vec![valid_federation(), valid_federation_maxblocksize()]);
        match federations.validate() {
            Err(Error::InvalidFederation(None, m)) => {
                assert_eq!(m, "The federations include block height duplication. The block height in all federations should be unique.")
            }
            _ => assert!(false, "it should error"),
        }
    }

    #[test]
    fn test_federation_validate() {
        let valid_federation_generators = [valid_federation, valid_federation_maxblocksize];

        for valid_federation_generator in valid_federation_generators {
            let federation = valid_federation_generator();
            assert!(federation.validate().is_ok());

            // federation has overlapped nodevss
            let mut federation = valid_federation_generator();
            let vss = federation.nodevss.as_ref().unwrap()[0].clone();
            federation.nodevss.as_mut().unwrap().push(vss);
            match federation.validate() {
                Err(Error::InvalidFederation(_, m)) => {
                    assert_eq!(m, "nodevss has overlapping sender vss.")
                }
                _ => assert!(false, "it should error"),
            }

            // federation has invalid vss whose receiver is not equal with the node itself.
            let mut federation = valid_federation_generator();
            federation.nodevss.as_mut().unwrap()[0].receiver_public_key = TEST_KEYS.pubkeys()[4];
            match federation.validate() {
                Err(Error::InvalidFederation(_, m)) => {
                    assert_eq!(m, "The nodevss has wrong receiver value. All VSS's receiver_public_key should be equal with publish key of the signer who runs the node.")
                }
                _ => assert!(false, "it should error"),
            }

            // the federation has invalid number of commitment
            let mut federation = valid_federation_generator();
            for i in federation.nodevss.as_mut().unwrap().iter_mut() {
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
            let mut federation = valid_federation_generator();

            federation.nodevss.as_mut().unwrap()[0].positive_secret =
                ECScalar::from(&BigInt::from_hex(
                    "9b77b12bf0ec14c6094be7657a3a3d473077bc3c8b694ead6c1b6d8c5b4e816c",
                ));
            match federation.validate() {
                Err(Error::InvalidFederation(_, m)) => {
                    assert_eq!(m, "The nodevss includes invalid share.")
                }
                _ => assert!(false, "it should error"),
            }
        }

        // Skip vss validation when the federation doesn't include the signer.
        let mut federation = valid_federation();
        federation.nodevss = None;
        federation.threshold = None;
        assert!(federation.validate().is_ok());

        // Error if the federation has threshold but not nodevss
        let mut federation = valid_federation();
        federation.nodevss = None;
        assert!(federation.validate().is_err());

        // Error if the federation has nodevss but not threshold
        let mut federation = valid_federation();
        federation.threshold = None;
        assert!(federation.validate().is_err());
    }

    #[test]
    fn test_serialize_deserialize() {
        let federation = valid_federation();

        let ser = federation.clone().to_ser().unwrap();
        let str = toml::to_string(&ser).unwrap();
        let deserialized =
            Federation::from(federation.signer_id.pubkey, toml::from_str(&str).unwrap()).unwrap();
        assert_eq!(federation, deserialized);

        let federation = valid_federation_maxblocksize();

        let ser = federation.clone().to_ser().unwrap();
        let str = toml::to_string(&ser).unwrap();
        let deserialized =
            Federation::from(federation.signer_id.pubkey, toml::from_str(&str).unwrap()).unwrap();
        assert_eq!(federation, deserialized);
    }

    #[test]
    fn test_from_pubkey_and_toml() {
        let pubkey = PublicKey::from_str(
            "0302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25",
        )
        .unwrap();

        // valid toml
        let toml = r#"
        [[federation]]
        block-height = 0
        threshold = 2
        aggregated-public-key = "02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"
        node-vss = [
            "021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da0302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a2500021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da7650c845ad480abe1a31a7d40815b7003b2cab562d22645980fd62b5fcaca5f6ce5946d3a138e4aef068730a987a2eb57bbfe02a83933a9f1865eed6b92814c08dc180ae7c0f0075c7645cb8cecf472069aa6cc10b8a1edc2623d4152fa3743b69fc0903900dc5727544c4c9cf1f40d12e8eda6d29f111216de58c5482354c161c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da7650c845ad480abe1a31a7d40815b7003b2cab562d22645980fd62b5fcaca5f6ce5946d3a138e4aef068730a987a2eb57bbfe02a83933a9f1865eed6b92814c08dc180ae7c0f0075c7645cb8cecf472069aa6cc10b8a1edc2623d4152fa3743b69fc0903900dc5727544c4c9cf1f40d12e8eda6d29f111216de58c5482354c16",
            "0302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a250302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25000202f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25ca08028df6f430f739d1c387a7b837ccad852e61a90c961c0a44f942ad127ec39a991401abf2e71cb8a0455c9b82542724eb2493f43558cd35a8a80eeeebf30b7531d698c1de7f199f8be4bdd265ef8f8950e2c8ba255718e2e847472d6411a5a8f697000faa20097baa0848d4945b5543dd0530108d2b1552940aa7785e427a02f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25ca08028df6f430f739d1c387a7b837ccad852e61a90c961c0a44f942ad127ec39a991401abf2e71cb8a0455c9b82542724eb2493f43558cd35a8a80eeeebf30b7531d698c1de7f199f8be4bdd265ef8f8950e2c8ba255718e2e847472d6411a5a8f697000faa20097baa0848d4945b5543dd0530108d2b1552940aa7785e427a",
            "0315d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25000215d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90081da2716d12495f6e83bbfde76a914fc6cfe72d1b229130295a83d7b8352f105ce821aefb02ed9bbada8355d3179ca4a8a392260db9c5d34e44006395256317b9b4bb48a435b9aa5d36fddab8d7bd764e27e0dfeeec273d3a635d2d53707a5600917878572511804651724a877d126452c33b7ea12df1318b1934c72d816b515d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90081da2716d12495f6e83bbfde76a914fc6cfe72d1b229130295a83d7b8352f105ce821aefb02ed9bbada8355d3179ca4a8a392260db9c5d34e44006395256317b9b4bb48a435b9aa5d36fddab8d7bd764e27e0dfeeec273d3a635d2d53707a5600917878572511804651724a877d126452c33b7ea12df1318b1934c72d816b5"
        ]
        [[federation]]
        block-height = 20
        threshold = 2
        aggregated-public-key = "0376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50"
        node-vss = [
           "0302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a250302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25000202f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25ca08028df6f430f739d1c387a7b837ccad852e61a90c961c0a44f942ad127ec33ecf34027b4922b3145e69a6006ca3414a7d6cb3ba888c4eadc546cd640f60b930f5d90d1bffafd82e57409e72d5170bd65317e5b87e17d61818546c95d5f35e951ff864871be49c79cfdd99ce8c3457324f446c272622ffafd57e7654f45ecc02f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25ca08028df6f430f739d1c387a7b837ccad852e61a90c961c0a44f942ad127ec33ecf34027b4922b3145e69a6006ca3414a7d6cb3ba888c4eadc546cd640f60b930f5d90d1bffafd82e57409e72d5170bd65317e5b87e17d61818546c95d5f35e951ff864871be49c79cfdd99ce8c3457324f446c272622ffafd57e7654f45ecc",
            "0315d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25000215d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90081da2716d12495f6e83bbfde76a914fc6cfe72d1b229130295a83d7b8352f1f960f10435a23ea5c590bb1e2271e130fe67d582926c534aa1331d1b84ce127df4ae07160b3ef4bfdcb0035aea945ceb4b2323975fd90789d20637fdac29479d8fd125986ab6b55c756dcd270268cc0f49b303ed438732b94773f7b64ed7df9715d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90081da2716d12495f6e83bbfde76a914fc6cfe72d1b229130295a83d7b8352f1f960f10435a23ea5c590bb1e2271e130fe67d582926c534aa1331d1b84ce127df4ae07160b3ef4bfdcb0035aea945ceb4b2323975fd90789d20637fdac29479d8fd125986ab6b55c756dcd270268cc0f49b303ed438732b94773f7b64ed7df97",
            "039af53a49a365576de41a2e70cc148353d7d1f4cad45f888fd8bc6d2c94a976570302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a2500029af53a49a365576de41a2e70cc148353d7d1f4cad45f888fd8bc6d2c94a976579fc4ac8cde7d898910cb47345069cfc6c086e767b8e90276551762478dfe20fb0af6b91228e3e520a02c8e96904cc6ea13e7e5752d2c25fc260586561934b8024613acba6b7f33498353f3ff136bad71648278b5ef245f9f04cf10657728e0283dd5f93cd4f175390d7396499e506a5afb47121eb0316e018426f74348b9a8ac9af53a49a365576de41a2e70cc148353d7d1f4cad45f888fd8bc6d2c94a976579fc4ac8cde7d898910cb47345069cfc6c086e767b8e90276551762478dfe20fb0af6b91228e3e520a02c8e96904cc6ea13e7e5752d2c25fc260586561934b8024613acba6b7f33498353f3ff136bad71648278b5ef245f9f04cf10657728e0283dd5f93cd4f175390d7396499e506a5afb47121eb0316e018426f74348b9a8ac"
        ]
        signature = "90c90936d44e75bf25f8a6d1c21020a8dc7ee7f4d62a3d7ae278d9ff6a74901f687eee4236a64805414a43c344d12882061518be61014e76027cf6b8fd845aa0"
        "#;

        let federations = Federations::from_pubkey_and_toml(&pubkey, toml).unwrap();
        assert_eq!(federations.len(), 2);

        // valid toml. It has a federation doesn't includes the node.
        let pubkey = PublicKey::from_str(
            "021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da",
        )
        .unwrap();

        let toml = r#"
        [[federation]]
        block-height = 0
        threshold = 2
        aggregated-public-key = "02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"
        node-vss = [
            "021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da00021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da7650c845ad480abe1a31a7d40815b7003b2cab562d22645980fd62b5fcaca5f6ce5946d3a138e4aef068730a987a2eb57bbfe02a83933a9f1865eed6b92814c08dc180ae7c0f0075c7645cb8cecf472069aa6cc10b8a1edc2623d4152fa3743be73faa937a3ee41f556ac4b37b79282af663e3bc4a361221f2911d947a06a8361c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da7650c845ad480abe1a31a7d40815b7003b2cab562d22645980fd62b5fcaca5f6ce5946d3a138e4aef068730a987a2eb57bbfe02a83933a9f1865eed6b92814c08dc180ae7c0f0075c7645cb8cecf472069aa6cc10b8a1edc2623d4152fa3743be73faa937a3ee41f556ac4b37b79282af663e3bc4a361221f2911d947a06a836",
            "0302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da000202f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25ca08028df6f430f739d1c387a7b837ccad852e61a90c961c0a44f942ad127ec39a991401abf2e71cb8a0455c9b82542724eb2493f43558cd35a8a80eeeebf30b7531d698c1de7f199f8be4bdd265ef8f8950e2c8ba255718e2e847472d6411a5fa80b0328e8d55b146e52bd32bf6e5b7148d3bd1436cf8a86ff3d5c25d457c5c02f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25ca08028df6f430f739d1c387a7b837ccad852e61a90c961c0a44f942ad127ec39a991401abf2e71cb8a0455c9b82542724eb2493f43558cd35a8a80eeeebf30b7531d698c1de7f199f8be4bdd265ef8f8950e2c8ba255718e2e847472d6411a5fa80b0328e8d55b146e52bd32bf6e5b7148d3bd1436cf8a86ff3d5c25d457c5c",
            "0315d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c9021c36ce51f73f01395af9f7955db0c99f8e34009ea1565679b851f19cba37a5da000215d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90081da2716d12495f6e83bbfde76a914fc6cfe72d1b229130295a83d7b8352f105ce821aefb02ed9bbada8355d3179ca4a8a392260db9c5d34e44006395256317b9b4bb48a435b9aa5d36fddab8d7bd764e27e0dfeeec273d3a635d2d53707a55c14102eb04e3d6928149560ed26c8cd0923317dee7aa1941b5a822fabfcd41115d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c90081da2716d12495f6e83bbfde76a914fc6cfe72d1b229130295a83d7b8352f105ce821aefb02ed9bbada8355d3179ca4a8a392260db9c5d34e44006395256317b9b4bb48a435b9aa5d36fddab8d7bd764e27e0dfeeec273d3a635d2d53707a55c14102eb04e3d6928149560ed26c8cd0923317dee7aa1941b5a822fabfcd411"
        ]
        [[federation]]
        block-height = 30
        aggregated-public-key = "0376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50"
        signature ="90c90936d44e75bf25f8a6d1c21020a8dc7ee7f4d62a3d7ae278d9ff6a74901f687eee4236a64805414a43c344d12882061518be61014e76027cf6b8fd845aa0"
        "#;

        let federations = Federations::from_pubkey_and_toml(&pubkey, toml).unwrap();
        assert_eq!(federations.len(), 2);

        // toml has federation item which dosen't have required item 'aggregated_public_key'.
        let toml = r#"
        [[federation]]
        block-height = 0
        threshold = 3
        aggregated-public-key = "030d856ac9f5871c3785a2d76e3a5d9eca6fcce70f4de63339671dfb9d1f33edb0"
        node-vss = [
          "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f5835f7638e641b55dba9c5711ba47d50b8e1eefcf06d42c71708ae28dd1a038b02651456363420d02dc28ef180b66e781413133effde76d7eb7a57cffe41de3e6537325720efa3c4a847f84e72830280f2ff37758c69ade23f45d9e8c2f28f7b92a984669067dd13ecd9789da097d76f3b9c9b179f9948025db5e2ae00522f55515126b42d8c99f0b72c28ad5bf95ee38f4154f37df7d4a621b68db4f9f5c8070b472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd739e10be2c059db79d50c629fe78a929d8458d064261aaa873a478ccb3b0c18f7df28e9bf75c9e4f8101b4bfb007c538499945ed651aea6122164ee9dcff02405b41ced6471dc0099a740921e10ba7d539e69153b25b2bb97257fa8dd5f0109aa52e94a550998d573aebced1eb10aaafbae5cbfb6413eed0c17f88204f2e4b13c7746199720b3bee5c3d50b9ca9e3c32e905d7058a3cb9ec899bf428ba2e0d9c7",
          "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a74bf633344275792c413aac61fb108ba49aacb935cc637833a3d5f8bbc412a4578eec59fd45330922725e96c6c8e65980e3f571a9e99c7ea80abaabbfcc7a8541ca3bb9fb3393e593db51bf5bee44181cdf4cb1d617c0ce63682d8559f1424897b90c6c5c2684dda9a0f592fdc159c6dc744465f6de103c2ffe012c9a839034ae04a12fc2cc261586bf6b5814b1742449544aec456524b30fd530db6a76459162d785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbe5e5c0c4374a92bff9f7b7328d3baeb061b738dce75093a7a941cce96c5daf18284364f8ebabd43d3439169e92b27699e20be185ce3fb0fe44abc08fac1e25f4d256e87497f82f367abc2225cfe7d171f528160e681ae6a14df51ffdded1e96da93cc0bc30c7af4d608c6e026ca9b51f6ec61ad548117d0b98f010f847b2907e21ed09bf936cb602babaa8b37fcda1d159b6dd756c483ce982d1541e1a9bac03",
          "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc82ef0de1465a7dc27596e2e97087c70743c9a3686ed25882f342ab43c01d243053231904aa20a48130ce3da8a6c9c1cb96e3abf13c7fc2bc6467ff859ea85c78e0bba3cb4d94e2ed91b73b7734bc77f5a9e59e4f5dfa0358fabc24f72b3766f926e8cfbe7135e85b9463e796725b6d35f66d28929d1eda1e447260aa716b09f4acedc39c6e379af7740e5daf14fb9664872a8c3eecab1d3cd68f7d1d460344c32ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672f24627e0a688cd54fb215fef833a804ad996f9f375f049e607bb739054b6d2cf43fcba949dd1cfa0f09b21873b445536717763e09e17383c8045e95917764c5bffccad34e90d7b469cdcc73bf2897af89b2f9171561143d12fd8996bf39d1bb20b4881975fef44f40ba71f14d827f3d2f26bc6182d5341189fefe308174a542ccb96b7a0ac351921d4efea5b01362c3d6bf8e815898e699ff4b2c6ac84d18d7",
          "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3cb1e1ab71073241af34aabcee036dbb020b36121aebc19731ca3abeb3bbd19d9e1a7baec1441d10b7f1fbd182a4e53f9acc6f4de22485ceffe1254a77b10e9bf0a7d42cccac1043afccfd198b3cd1a0e498ece3a8f3b181f7ae3c3eb2c918e022f1502cf7a4cc817babde2cbd7f080c887ee2a4900355dcb716400a00620afc19776f6a43ba14206db88b85b80f5a3781bdfde64627b8c1ff7228b73626a648c66f3707fc6985b9b775144308ea347c7fc38099240ce9165bdbc9c5ffb5b71050d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c4e1e548ef8cdbe50cb554311fc9244fdf4c9ede5143e68ce35c5414b442e5e9128297089d43e94c182266476a1831e5eaa6668f1e00f9071df751e832475372f7c5e5ce7ecc7afd96d5feecfb8a0a28e602aea7040966c03a270aba823ea4277db9cd2bbb6f6017d04cecbcd41e758ebfd84d114b19279f867bd66ff5cd6615184dda648750e0152256f04cd7cc28d792daf3178267c6f443615b9a03d489ab3864c0d8af03257c52bd8199a308f51c114ee51d37f7033760a14253fdf76c29d",
          "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed306ae393ff8268523f6f4051a407c2e0164e14245b9499e714dd1691a5df832f1bcdd4c55bc2b958eea7b5f0de006bf6340d7ebc3de27fde6c0d639ce41f8af83f8a2f6b9f8d5dac2f971bf0f2ace4acc9ed2c70c617302755abd213421e7a1ccde12d18e5426de47339824faa5b40c307294d6835a92fa8e89ed6c1be85e9f9fd0ccd8f2fc4e0a1e5db88c74fd8a25b73076af74333671b84240b2d91d78303c831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c531a03ee21b178dd7fef9cb537d477705f48051f94363ceae0aec0a49b1e5460a47b2bf5fbacff69679a6ba3a839a36ef9e9ab7e4efdfad4dc6903e0af9df74c67a8d43ebc28d5acce6c2531d08b144fa2a06718eede8fd855aa7970c353d7ad833fa7f087bf2d00617549ef3da4f9986955f35e98b0c9db18021c853a2ddde4c52dfd720dd715403bdb22751217d54a58d0377f4ccc0723cab9a25b9587662e"
        ]
        [[federation]]
        block-height = 100
        threshold = 2
        node-vss = [
          "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f58df14e215a3883ff8c8def6bdce4d9d80282749b8056ec72373a246b3de5aa120b336d88a9b977a2f2ff5f26a1633f70f2d776363c495a02617bb7a88a2fea285a0a0e33e16dd90acb06b22fc70086f7eb12cdfeb7eb622d8a455de1f448fd30a472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd761c1af39b4fcbe4e3a240848bc90f41681ec105286684d4832efdc5b96a0e027286d9f7d22ad52194da7d522e5586ce268c7fde21220aca78e21d1d1a5d69f2468fff1b0f8a3a142cf0e1c7d29cbe3e509c437cd680ab21715cb5c1844d2eff8",
          "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc81f4be7002fae5b70835ee7e51893f76dd840ea64010504b8c66197d9cad767236a786cc7b91146df5e8d1ff73ad220b3578359eda61c341a8b5c41de6b068f73696b619f9213a550d0bc159ba1ff43c4e90c85930904a6f7f582b52074e3d965ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672ad0d285c094287a3e2cc42d88e0736a1e238f33cde1ef9bd1cd9a0e8fe4a37dec94b7927535da68f388e4d5f07e838b71c742302476336b68f47b2e802b8c88a0fd87b9acc67ab564501a9777cf6081f50798b2ae8f2dff8a5190a27cfaf0e3",
          "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed35b71e1d42c2b7755bc33a7408032915da2a640b1b4227e13cd28efafc9e4af50fa777e082bd1afc64a4c2a67379df5a49233b6f003b96625f25f8dbe14fc7478fb75efb0cbcf147375065344b5c5f802bcd9057740983297749375b21d876d26831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c8f2a6c11c0fa9382aff7496614860f05779d3a0c5e6813db99d4b53417ac77c624171c6f14d272660f2556c9db9e3cca3e05a814a09fd5952dac72e18c7851c518063e5896e261aef163636449d673aba880160e57b5beee92362d74b5eb71dd"
        ]
        signature="90c90936d44e75bf25f8a6d1c21020a8dc7ee7f4d62a3d7ae278d9ff6a74901f687eee4236a64805414a43c344d12882061518be61014e76027cf6b8fd845aa0"
        "#;

        match Federations::from_pubkey_and_toml(&pubkey, toml) {
            Err(Error::InvalidFederation(height, err)) => {
                assert_eq!(height.unwrap(), 100);
                assert_eq!(
                    err,
                    "No xfield in federation. Aggregated pubkey or max block size is expected"
                )
            }
            _ => assert!(false, "it should error"),
        }

        // toml has federation item whose nodevss has invalid vss
        let toml = r#"
        [[federation]]
        block-height = 0
        threshold = 3
        aggregated-public-key = "030d856ac9f5871c3785a2d76e3a5d9eca6fcce70f4de63339671dfb9d1f33edb0"
        node-vss = [
          "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f58df14e215a3883ff8c8def6bdce4d9d80282749b8056ec72373a246b3de5aa120b336d88a9b977a2f2ff5f26a1633f70f2d776363c495a02617bb7a88a2fea285a0a0e33e16dd90acb06b22fc70086f7eb12cdfeb7eb622d8a455de1f448fd30a472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd761c1af39b4fcbe4e3a240848bc90f41681ec105286684d4832efdc5b96a0e027286d9f7d22ad52194da7d522e5586ce268c7fde21220aca78e21d1d1a5d69f2468fff1b0f8a3a142cf0e1c7d29cbe3e509c437cd680ab21715cb5c1844d2eff8",
          "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a74bf633344275792c413aac61fb108ba49aacb935cc637833a3d5f8bbc412a4578eec59fd45330922725e96c6c8e65980e3f571a9e99c7ea80abaabbfcc7a8541ca3bb9fb3393e593db51bf5bee44181cdf4cb1d617c0ce63682d8559f1424897b90c6c5c2684dda9a0f592fdc159c6dc744465f6de103c2ffe012c9a839034ae04a12fc2cc261586bf6b5814b1742449544aec456524b30fd530db6a76459162d785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbe5e5c0c4374a92bff9f7b7328d3baeb061b738dce75093a7a941cce96c5daf18284364f8ebabd43d3439169e92b27699e20be185ce3fb0fe44abc08fac1e25f4d256e87497f82f367abc2225cfe7d171f528160e681ae6a14df51ffdded1e96da93cc0bc30c7af4d608c6e026ca9b51f6ec61ad548117d0b98f010f847b2907e21ed09bf936cb602babaa8b37fcda1d159b6dd756c483ce982d1541e1a9bac03",
          "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc82ef0de1465a7dc27596e2e97087c70743c9a3686ed25882f342ab43c01d243053231904aa20a48130ce3da8a6c9c1cb96e3abf13c7fc2bc6467ff859ea85c78e0bba3cb4d94e2ed91b73b7734bc77f5a9e59e4f5dfa0358fabc24f72b3766f926e8cfbe7135e85b9463e796725b6d35f66d28929d1eda1e447260aa716b09f4acedc39c6e379af7740e5daf14fb9664872a8c3eecab1d3cd68f7d1d460344c32ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672f24627e0a688cd54fb215fef833a804ad996f9f375f049e607bb739054b6d2cf43fcba949dd1cfa0f09b21873b445536717763e09e17383c8045e95917764c5bffccad34e90d7b469cdcc73bf2897af89b2f9171561143d12fd8996bf39d1bb20b4881975fef44f40ba71f14d827f3d2f26bc6182d5341189fefe308174a542ccb96b7a0ac351921d4efea5b01362c3d6bf8e815898e699ff4b2c6ac84d18d7",
          "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3cb1e1ab71073241af34aabcee036dbb020b36121aebc19731ca3abeb3bbd19d9e1a7baec1441d10b7f1fbd182a4e53f9acc6f4de22485ceffe1254a77b10e9bf0a7d42cccac1043afccfd198b3cd1a0e498ece3a8f3b181f7ae3c3eb2c918e022f1502cf7a4cc817babde2cbd7f080c887ee2a4900355dcb716400a00620afc19776f6a43ba14206db88b85b80f5a3781bdfde64627b8c1ff7228b73626a648c66f3707fc6985b9b775144308ea347c7fc38099240ce9165bdbc9c5ffb5b71050d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c4e1e548ef8cdbe50cb554311fc9244fdf4c9ede5143e68ce35c5414b442e5e9128297089d43e94c182266476a1831e5eaa6668f1e00f9071df751e832475372f7c5e5ce7ecc7afd96d5feecfb8a0a28e602aea7040966c03a270aba823ea4277db9cd2bbb6f6017d04cecbcd41e758ebfd84d114b19279f867bd66ff5cd6615184dda648750e0152256f04cd7cc28d792daf3178267c6f443615b9a03d489ab3864c0d8af03257c52bd8199a308f51c114ee51d37f7033760a14253fdf76c29d",
          "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed306ae393ff8268523f6f4051a407c2e0164e14245b9499e714dd1691a5df832f1bcdd4c55bc2b958eea7b5f0de006bf6340d7ebc3de27fde6c0d639ce41f8af83f8a2f6b9f8d5dac2f971bf0f2ace4acc9ed2c70c617302755abd213421e7a1ccde12d18e5426de47339824faa5b40c307294d6835a92fa8e89ed6c1be85e9f9fd0ccd8f2fc4e0a1e5db88c74fd8a25b73076af74333671b84240b2d91d78303c831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c531a03ee21b178dd7fef9cb537d477705f48051f94363ceae0aec0a49b1e5460a47b2bf5fbacff69679a6ba3a839a36ef9e9ab7e4efdfad4dc6903e0af9df74c67a8d43ebc28d5acce6c2531d08b144fa2a06718eede8fd855aa7970c353d7ad833fa7f087bf2d00617549ef3da4f9986955f35e98b0c9db18021c853a2ddde4c52dfd720dd715403bdb22751217d54a58d0377f4ccc0723cab9a25b9587662e"
        ]
        [[federation]]
        block-height = 200
        signature="90c90936d44e75bf25f8a6d1c21020a8dc7ee7f4d62a3d7ae278d9ff6a74901f687eee4236a64805414a43c344d12882061518be61014e76027cf6b8fd845aa0"
        "#;

        match Federations::from_pubkey_and_toml(&pubkey, toml) {
            Err(Error::InvalidFederation(height, err)) => {
                assert_eq!(height.unwrap(), 200);
                assert_eq!(
                    err,
                    "No xfield in federation. Aggregated pubkey or max block size is expected"
                )
            }
            _ => assert!(false, "it should error"),
        }
    }
}
