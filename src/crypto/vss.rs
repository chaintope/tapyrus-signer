use crate::crypto::multi_party_schnorr::Keys;
use crate::errors::Error;
use crate::serialize::HexStrVisitor;
use crate::sign::Sign;
use bitcoin::consensus::encode::{self, *};
use bitcoin::{PrivateKey, PublicKey};
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io;
use std::str::FromStr;

// | name                 | size      | explaination                                                                                      |
// | -------------------- | --------- | ------------------------------------------------------------------------------------------------- |
// | sender_public_key    | 33        | indicates the signer who sends the vss                                                            |
// | receiver_public_key  | 33        | indicates the signer to be received the vss                                                       |
// | positive commitments | 64 \* len | commitments for secret value for r . an array of the points on the elliptic curve secp256k1.      |
// | positive secret      | 32        | secret value for r to perform secret sharing scheme                                               |
// | negative commitments | 64 \* len | commitments for secret value for (n - r). an array of the points on the elliptic curve secp256k1. |
// | negative secret      | 32        | secret value for (n - r) to perform secret sharing scheme                                         |
#[derive(Clone, Debug)]
pub struct Vss {
    pub sender_public_key: PublicKey,
    pub receiver_public_key: PublicKey,
    pub positive_commitments: Vec<Commitment>,
    pub positive_secret: FE,
    pub negative_commitments: Vec<Commitment>,
    pub negative_secret: FE,
}

impl Vss {
    pub fn new(
        sender_public_key: PublicKey,
        receiver_public_key: PublicKey,
        positive_commitments: Vec<Commitment>,
        positive_secret: FE,
        negative_commitments: Vec<Commitment>,
        negative_secret: FE,
    ) -> Self {
        assert_eq!(positive_commitments.len(), negative_commitments.len());
        Vss {
            sender_public_key: sender_public_key,
            receiver_public_key: receiver_public_key,
            positive_commitments: positive_commitments,
            positive_secret: positive_secret,
            negative_commitments: negative_commitments,
            negative_secret: negative_secret,
        }
    }

    pub fn create_node_shares(
        private_key: &PrivateKey,
        threshold: usize,
        share_count: usize,
    ) -> (VerifiableSS, Vec<FE>) {
        assert!(
            share_count >= threshold,
            "share count should be greater or equal to threshold. share_count: {}, threshold: {}",
            share_count,
            threshold
        );
        let key_as_int =
            Sign::private_key_to_big_int(private_key.key).expect("failed to parse private_key");
        let secret = ECScalar::from(&key_as_int);
        let parties = (0..share_count).map(|i| i + 1).collect::<Vec<usize>>();
        VerifiableSS::share_at_indices(threshold - 1, share_count, &secret, &parties)
    }

    pub fn create_block_shares(
        key: &Keys,
        threshold: usize,
        share_count: usize,
    ) -> (VerifiableSS, Vec<FE>, VerifiableSS, Vec<FE>) {
        assert!(
            share_count >= threshold,
            "share count should be greater or equal to threshold. share_count: {}, threshold: {}",
            share_count,
            threshold
        );
        let parties = (0..share_count).map(|i| i + 1).collect::<Vec<usize>>();

        let (vss_scheme_for_positive, secret_shares_for_positive) =
            VerifiableSS::share_at_indices(threshold - 1, share_count, &key.u_i, &parties);

        let order: BigInt = FE::q();
        let (vss_scheme_for_negative, secret_shares_for_negative) = VerifiableSS::share_at_indices(
            threshold - 1,
            share_count,
            &(ECScalar::from(&(order - key.u_i.to_big_int()))),
            &parties,
        );
        (
            vss_scheme_for_positive,
            secret_shares_for_positive,
            vss_scheme_for_negative,
            secret_shares_for_negative,
        )
    }
}

#[derive(Clone)]
pub struct Commitment {
    x: BigInt,
    y: BigInt,
}

impl Commitment {
    pub fn new(x: BigInt, y: BigInt) -> Self {
        Commitment { x: x, y: y }
    }

    pub fn from(p: &GE) -> Self {
        let x = p.x_coor().expect("invalid x-coordinate");
        let y = p.y_coor().expect("invalid y-coordinate");
        Commitment::new(x, y)
    }

    pub fn to_point(&self) -> GE {
        ECPoint::from_coor(&self.x, &self.y)
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.x.to_hex(), self.y.to_hex())
    }
}

impl FromStr for Vss {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let hex = hex::decode(s).map_err(|_| Error::InvalidArgs("failed parse hex".to_string()))?;
        Ok(deserialize::<Vss>(&hex[..]).expect("failed parse hex"))
    }
}

impl Serialize for Vss {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let serialized = hex::encode(&serialize(self));
        serializer.serialize_str(&serialized)
    }
}

impl<'de> Deserialize<'de> for Vss {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = deserializer.deserialize_str(HexStrVisitor::new())?;
        let hex = hex::encode(&vec[..]);
        Vss::from_str(&hex).map_err(de::Error::custom)
    }
}

impl Encodable for Vss {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        let mut size = 0;

        let mut pk = [0u8; 33];
        pk.copy_from_slice(&self.sender_public_key.to_bytes()[..]);
        size += pk.consensus_encode(&mut s)?;

        let mut pk = [0u8; 33];
        pk.copy_from_slice(&self.receiver_public_key.to_bytes()[..]);
        size += pk.consensus_encode(&mut s)?;

        let len = self.positive_commitments.len() as u16;
        let mut x = [0u8; 2];
        x.copy_from_slice(
            &hex::decode(format!("{:0>4x}", len)).map_err(|_| encode::Error::ParseFailed("len"))?,
        );
        size += x.consensus_encode(&mut s)?;

        for c in &self.positive_commitments {
            size += c.consensus_encode(&mut s)?;
        }
        let mut secret = [0u8; 32];
        let hex = format!("{:0>64}", self.positive_secret.to_big_int().to_hex());
        secret.copy_from_slice(
            &hex::decode(hex).map_err(|_| encode::Error::ParseFailed("positive_secret"))?[..],
        );
        size += secret.consensus_encode(&mut s)?;

        for c in &self.negative_commitments {
            size += c.consensus_encode(&mut s)?;
        }
        let mut secret = [0u8; 32];
        let hex = format!("{:0>64}", self.negative_secret.to_big_int().to_hex());
        secret.copy_from_slice(
            &hex::decode(hex).map_err(|_| encode::Error::ParseFailed("positive_secret"))?[..],
        );
        size += secret.consensus_encode(&mut s)?;

        Ok(size)
    }
}

impl Decodable for Vss {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Vss, encode::Error> {
        let bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let sender_public_key = PublicKey::from_slice(&bytes[..])
            .map_err(|_| encode::Error::ParseFailed("sender_public_key"))?;

        let bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let receiver_public_key = PublicKey::from_slice(&bytes[..])
            .map_err(|_| encode::Error::ParseFailed("receiver_public_key"))?;

        let bytes: [u8; 2] = Decodable::consensus_decode(&mut d)?;
        let length: u16 = ((bytes[0] as u16) << 8) + (bytes[1] as u16);

        let positive_commitments: Vec<Commitment> = (0..length)
            .flat_map(|_| Decodable::consensus_decode(&mut d))
            .collect::<Vec<Commitment>>();

        let bytes: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let positive_secret = ECScalar::from(&BigInt::from(&bytes[..]));
        let negative_commitments: Vec<Commitment> = (0..length)
            .flat_map(|_| Decodable::consensus_decode(&mut d))
            .collect::<Vec<Commitment>>();

        let bytes: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let negative_secret = ECScalar::from(&BigInt::from(&bytes[..]));
        Ok(Vss::new(
            sender_public_key,
            receiver_public_key,
            positive_commitments,
            positive_secret,
            negative_commitments,
            negative_secret,
        ))
    }
}

impl Encodable for Commitment {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        let mut x = [0u8; 32];
        x.copy_from_slice(
            &hex::decode(format!("{:0>64}", self.x.to_hex()))
                .map_err(|_| encode::Error::ParseFailed("x"))?,
        );
        x.consensus_encode(&mut s)?;

        let mut y = [0u8; 32];
        y.copy_from_slice(
            &hex::decode(format!("{:0>64}", self.y.to_hex()))
                .map_err(|_| encode::Error::ParseFailed("y"))?,
        );
        y.consensus_encode(&mut s)?;
        Ok(64)
    }
}

impl Decodable for Commitment {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Commitment, encode::Error> {
        let x: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let y: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        Ok(Commitment::new(BigInt::from(&x[..]), BigInt::from(&y[..])))
    }
}

impl fmt::Display for Vss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = serialize(self);
        write!(f, "{}", hex::encode(encoded))
    }
}

impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = serialize(self);
        write!(f, "{}", hex::encode(encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_support() {
        let vss_str = "\"03842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca203e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee100014f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b37163967359e69f3af7b7e1b3e3a294ab81a2c5b02658b8deee2008aa39eff6bf55742900000000000000000000000000000000000000000000000000000000000000014f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b37163968ca61960c508481e4c1c5d6b547e5d3a4fd9a7472111dff755c6100840aa88060000000000000000000000000000000000000000000000000000000000000002\"";
        let vss: Vss = serde_json::from_str(&vss_str).unwrap();
        assert_eq!(serde_json::to_string(&vss).unwrap(), vss_str);
    }

    #[test]
    fn test_decode_commitment() {
        let s = "842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2c89314bbafe84e0a29be49397843808ab8d94118dcc1bdf619d04fee039ccd9f";
        let hex = hex::decode(s).unwrap();
        let c: Commitment = deserialize::<Commitment>(&hex[..]).unwrap();
        assert_eq!(
            c.x,
            BigInt::from_str_radix(
                "842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2",
                16
            )
            .unwrap()
        );
        assert_eq!(
            c.y,
            BigInt::from_str_radix(
                "c89314bbafe84e0a29be49397843808ab8d94118dcc1bdf619d04fee039ccd9f",
                16
            )
            .unwrap()
        );
    }

    #[test]
    fn test_encode_commitment() {
        let x = BigInt::from_str_radix(
            "842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2",
            16,
        )
        .unwrap();
        let y = BigInt::from_str_radix(
            "c89314bbafe84e0a29be49397843808ab8d94118dcc1bdf619d04fee039ccd9f",
            16,
        )
        .unwrap();
        let commitment = Commitment::new(x, y);
        assert_eq!(format!("{}", commitment), "842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2c89314bbafe84e0a29be49397843808ab8d94118dcc1bdf619d04fee039ccd9f");
    }

    #[test]
    fn test_decode_vss() {
        let s = "03842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca203e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee100014f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b37163967359e69f3af7b7e1b3e3a294ab81a2c5b02658b8deee2008aa39eff6bf55742900000000000000000000000000000000000000000000000000000000000000014f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b37163968ca61960c508481e4c1c5d6b547e5d3a4fd9a7472111dff755c6100840aa88060000000000000000000000000000000000000000000000000000000000000002";
        let vss = Vss::from_str(s).unwrap();
        assert_eq!(
            vss.sender_public_key,
            PublicKey::from_str(
                "03842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2"
            )
            .unwrap()
        );
        assert_eq!(
            vss.receiver_public_key,
            PublicKey::from_str(
                "03e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee1"
            )
            .unwrap()
        );

        assert_eq!(vss.positive_secret, ECScalar::from(&BigInt::from(1)));
        assert_eq!(vss.negative_secret, ECScalar::from(&BigInt::from(2)));
    }

    #[test]
    fn test_encode_vss() {
        let p1 = Commitment::new(
            BigInt::from_str_radix(
                "4f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b3716396",
                16,
            )
            .unwrap(),
            BigInt::from_str_radix(
                "7359e69f3af7b7e1b3e3a294ab81a2c5b02658b8deee2008aa39eff6bf557429",
                16,
            )
            .unwrap(),
        );
        let p2 = Commitment::new(
            BigInt::from_str_radix(
                "4f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b3716396",
                16,
            )
            .unwrap(),
            BigInt::from_str_radix(
                "8ca61960c508481e4c1c5d6b547e5d3a4fd9a7472111dff755c6100840aa8806",
                16,
            )
            .unwrap(),
        );
        let vss = Vss {
            sender_public_key: PublicKey::from_str(
                "03842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca2",
            )
            .unwrap(),
            receiver_public_key: PublicKey::from_str(
                "03e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee1",
            )
            .unwrap(),
            positive_commitments: vec![p1],
            positive_secret: ECScalar::from(&BigInt::from(1)),
            negative_commitments: vec![p2],
            negative_secret: ECScalar::from(&BigInt::from(2)),
        };
        assert_eq!(format!("{}", vss), "03842d51608d08bee79587fb3b54ea68f5279e13fac7d72515a7205e6672858ca203e568e3a5641ac21930b51f92fb6dd201fb46faae560b108cf3a96380da08dee100014f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b37163967359e69f3af7b7e1b3e3a294ab81a2c5b02658b8deee2008aa39eff6bf55742900000000000000000000000000000000000000000000000000000000000000014f8f2711cfcf76a4d3cb350b5cd59906685dc7fbb320541e7e1f7885b37163968ca61960c508481e4c1c5d6b547e5d3a4fd9a7472111dff755c6100840aa88060000000000000000000000000000000000000000000000000000000000000002")
    }

    #[test]
    fn test_create_node_shares() {
        let private_key =
            PrivateKey::from_wif("L4MmwZ4nSacs186WzVfxyuryUUbnfE7PivJBj3GT2a3n5itSudZg").unwrap();
        let (vss, shares) = Vss::create_node_shares(&private_key, 2, 3);
        assert_eq!(vss.commitments.len(), 2);
        assert_eq!(shares.len(), 3);
    }

    #[test]
    #[should_panic(expected = "share count should be greater or equal to threshold")]
    fn test_create_node_shares_invalid_large_threshold() {
        let private_key =
            PrivateKey::from_wif("L4MmwZ4nSacs186WzVfxyuryUUbnfE7PivJBj3GT2a3n5itSudZg").unwrap();
        Vss::create_node_shares(&private_key, 4, 3);
    }

    #[test]
    fn test_create_block_shares() {
        let private_key =
            PrivateKey::from_wif("L4MmwZ4nSacs186WzVfxyuryUUbnfE7PivJBj3GT2a3n5itSudZg").unwrap();
        let pk = Sign::private_key_to_big_int(private_key.key);
        let key = Sign::create_key(1, pk);

        let (vss_for_pos, shares_for_pos, vss_for_neg, shares_for_neg) =
            Vss::create_block_shares(&key, 2, 3);
        assert_eq!(vss_for_pos.commitments.len(), 2);
        assert_eq!(shares_for_pos.len(), 3);
        assert_eq!(vss_for_neg.commitments.len(), 2);
        assert_eq!(shares_for_neg.len(), 3);
    }

    #[test]
    #[should_panic(expected = "share count should be greater or equal to threshold")]
    fn test_create_block_shares_invalid_large_threshold() {
        let private_key =
            PrivateKey::from_wif("L4MmwZ4nSacs186WzVfxyuryUUbnfE7PivJBj3GT2a3n5itSudZg").unwrap();
        let pk = Sign::private_key_to_big_int(private_key.key);
        let key = Sign::create_key(1, pk);

        Vss::create_block_shares(&key, 4, 3);
    }
}
