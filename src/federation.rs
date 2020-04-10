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

    pub fn get_by_block_height(&self, block_height: u64) -> &Federation {
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
        let unique_block_height: HashSet<u64> =
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
            .collect();

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
    block_height: u64,
    /// The theshold which is requirement number of signer's agreements to produce block signatures.
    /// This field may be None when the signer is not a member of the federation.
    threshold: Option<u8>,
    /// Verifiable Secre Share and commitments from all signers in the federation.
    /// This field may be empty when the signer is not a member of the federation.
    nodevss: Vec<Vss>,
    /// The aggregated public key
    aggregated_public_key: PublicKey,
}

impl Federation {
    pub fn new(
        public_key: PublicKey,
        block_height: u64,
        threshold: Option<u8>,
        nodevss: Vec<Vss>,
        aggregated_public_key: PublicKey,
    ) -> Self {
        Self {
            signer_id: SignerID::new(public_key),
            block_height,
            threshold,
            nodevss,
            aggregated_public_key,
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
    pub fn threshold(&self) -> Option<u8> {
        self.threshold
    }
    pub fn nodevss(&self) -> &Vec<Vss> {
        &self.nodevss
    }
    pub fn aggregated_public_key(&self) -> PublicKey {
        self.aggregated_public_key
    }

    /// Returns Map collection of received shares from all each signers in Key Generation Protocol
    pub fn node_shared_secrets(&self) -> SharedSecretMap {
        let mut secret_shares = SharedSecretMap::new();
        if let Some(threshold) = self.threshold {
            for vss in &self.nodevss {
                secret_shares.insert(
                    SignerID {
                        pubkey: vss.sender_public_key,
                    },
                    SharedSecret {
                        vss: VerifiableSS {
                            parameters: ShamirSecretSharing {
                                threshold: (threshold - 1) as usize,
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
        if let Some(threshold) = self.threshold {
            if self
                .nodevss
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

    pub fn from(pubkey: PublicKey, ser: SerFederation) -> Self {
        Self::new(
            pubkey,
            ser.block_height,
            ser.threshold,
            ser.nodevss,
            ser.aggregated_public_key,
        )
    }

    pub fn to_ser(self) -> SerFederation {
        SerFederation {
            block_height: self.block_height,
            threshold: self.threshold,
            nodevss: self.nodevss,
            aggregated_public_key: self.aggregated_public_key,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerFederations {
    federation: Vec<SerFederation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerFederation {
    #[serde(rename = "block-height")]
    block_height: u64,
    threshold: Option<u8>,
    #[serde(rename = "node-vss")]
    nodevss: Vec<Vss>,
    #[serde(rename = "aggregated-public-key")]
    aggregated_public_key: PublicKey,
}

#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::federation::{Federation, Federations};
    use crate::net::SignerID;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::node_vss::node_vss;
    use bitcoin::PublicKey;
    use curv::arithmetic::traits::Converter;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::BigInt;
    use std::str::FromStr;

    #[test]
    fn test_get_by_block_height() {
        let federation0 = Federation::new(
            TEST_KEYS.pubkeys()[4],
            0,
            Some(3),
            node_vss(0),
            TEST_KEYS.aggregated(),
        );
        let federation100 = Federation::new(
            TEST_KEYS.pubkeys()[4],
            100,
            Some(3),
            node_vss(1),
            TEST_KEYS.aggregated(),
        );
        let federation200 = Federation::new(
            TEST_KEYS.pubkeys()[4],
            200,
            Some(4),
            node_vss(2),
            TEST_KEYS.aggregated(),
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
            TEST_KEYS.pubkeys()[4],
            0,
            Some(3),
            node_vss(0),
            TEST_KEYS.aggregated(),
        );

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
        Federation::new(
            TEST_KEYS.pubkeys()[4],
            0,
            Some(3),
            node_vss(0),
            TEST_KEYS.aggregated(),
        )
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

        federation.nodevss[0].positive_secret = ECScalar::from(&BigInt::from_hex(
            "9b77b12bf0ec14c6094be7657a3a3d473077bc3c8b694ead6c1b6d8c5b4e816c",
        ));
        match federation.validate() {
            Err(Error::InvalidFederation(_, m)) => {
                assert_eq!(m, "The nodevss includes invalid share.")
            }
            _ => assert!(false, "it should error"),
        }
    }

    #[test]
    fn test_serialize_deserialize() {
        let federation = valid_federation();

        let ser = federation.clone().to_ser();
        let str = toml::to_string(&ser).unwrap();
        println!("{}", str);
        let deserialized =
            Federation::from(federation.signer_id.pubkey, toml::from_str(&str).unwrap());
        assert_eq!(federation, deserialized);
    }

    #[test]
    fn test_from_pubkey_and_toml() {
        let pubkey = PublicKey::from_str(
            "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
        )
        .unwrap();

        // valid toml
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
        aggregated-public-key = "030acd6af981c498ebf2ffd9a341d2a96bde5832c150e7d300fa3583eee0f964fe"
        node-vss = [
          "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f58df14e215a3883ff8c8def6bdce4d9d80282749b8056ec72373a246b3de5aa120b336d88a9b977a2f2ff5f26a1633f70f2d776363c495a02617bb7a88a2fea285a0a0e33e16dd90acb06b22fc70086f7eb12cdfeb7eb622d8a455de1f448fd30a472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd761c1af39b4fcbe4e3a240848bc90f41681ec105286684d4832efdc5b96a0e027286d9f7d22ad52194da7d522e5586ce268c7fde21220aca78e21d1d1a5d69f2468fff1b0f8a3a142cf0e1c7d29cbe3e509c437cd680ab21715cb5c1844d2eff8",
          "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc81f4be7002fae5b70835ee7e51893f76dd840ea64010504b8c66197d9cad767236a786cc7b91146df5e8d1ff73ad220b3578359eda61c341a8b5c41de6b068f73696b619f9213a550d0bc159ba1ff43c4e90c85930904a6f7f582b52074e3d965ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672ad0d285c094287a3e2cc42d88e0736a1e238f33cde1ef9bd1cd9a0e8fe4a37dec94b7927535da68f388e4d5f07e838b71c742302476336b68f47b2e802b8c88a0fd87b9acc67ab564501a9777cf6081f50798b2ae8f2dff8a5190a27cfaf0e3",
          "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed35b71e1d42c2b7755bc33a7408032915da2a640b1b4227e13cd28efafc9e4af50fa777e082bd1afc64a4c2a67379df5a49233b6f003b96625f25f8dbe14fc7478fb75efb0cbcf147375065344b5c5f802bcd9057740983297749375b21d876d26831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c8f2a6c11c0fa9382aff7496614860f05779d3a0c5e6813db99d4b53417ac77c624171c6f14d272660f2556c9db9e3cca3e05a814a09fd5952dac72e18c7851c518063e5896e261aef163636449d673aba880160e57b5beee92362d74b5eb71dd"
        ]
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
        "#;

        match Federations::from_pubkey_and_toml(&pubkey, toml) {
            Err(Error::InvalidTomlFormat(_)) => assert!(true),
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
        block-height = 100
        threshold = 2
        aggregated-public-key = "030acd6af981c498ebf2ffd9a341d2a96bde5832c150e7d300fa3583eee0f964fe"
        node-vss = [
          "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f58df14e215a3883ff8c8def6bdce4d9d80282749b8056ec72373a246b3de5aa120b336d88a9b977a2f2ff5f26a1633f70f2d776363c495a02617bb7a88a2fea285a0a0e33e16dd90acb06b22fc70086f7eb12cdfeb7eb622d8a455de1f448fd30a472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd761c1af39b4fcbe4e3a240848bc90f41681ec105286684d4832efdc5b96a0e027286d9f7d22ad52194da7d522e5586ce268c7fde21220aca78e21d1d1a5d69f2468fff1b0f8a3a142cf0e1c7d29cbe3e509c437cd680ab21715cb5c1844d2eff8",
          "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc81f4be7002fae5b70835ee7e51893f76dd840ea64010504b8c66197d9cad767236a786cc7b91146df5e8d1ff73ad220b3578359eda61c341a8b5c41de6b068f73696b619f9213a550d0bc159ba1ff43c4e90c85930904a6f7f582b52074e3d965ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672ad0d285c094287a3e2cc42d88e0736a1e238f33cde1ef9bd1cd9a0e8fe4a37dec94b7927535da68f388e4d5f07e838b71c742302476336b68f47b2e802b8c88a0fd87b9acc67ab564501a9777cf6081f50798b2ae8f2dff8a5190a27cfaf0e3",
          "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060002831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed35b71e1d42c2b7755bc33a7408032915da2a640b1b4227e13cd28efafc9e4af50fa777e082bd1afc64a4c2a67379df5a49233b6f003b96625f25f8dbe14fc7478fb75efb0cbcf147375065344b5c5f802bcd9057740983297749375b21d876d26831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c8f2a6c11c0fa9382aff7496614860f05779d3a0c5e6813db99d4b53417ac77c624171c6f14d272660f2556c9db9e3cca3e05a814a09fd5952dac72e18c7851c518063e5896e261aef163636449d673aba880160e57b5beee92362d74b5eb71dd"
        ]
        "#;

        match Federations::from_pubkey_and_toml(&pubkey, toml) {
            Err(Error::InvalidFederation(_, _)) => assert!(true),
            _ => assert!(false, "it should error"),
        }
    }
}
