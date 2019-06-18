use serde::de::{Visitor, SeqAccess, Error};
use std::fmt;

pub struct ByteBufVisitor;

/// refer to https://github.com/baidu/rust-sgx-sdk/blob/9d4fa0f603e44bb82efae9d913c586a498b7d9da/third_party/serde-rs/serde/test_suite/tests/bytes/mod.rs
impl<'de> Visitor<'de> for ByteBufVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("byte array")
    }

    fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
        where
            V: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = visitor.next_element()? {
            values.push(value);
        }
        Ok(values)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
    {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
    {
        Ok(v)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
    {
        Ok(v.as_bytes().to_vec())
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: Error,
    {
        Ok(v.into_bytes())
    }
}