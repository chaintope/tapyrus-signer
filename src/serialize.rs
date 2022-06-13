// Copyright (c) 2019 Chaintope Inc.

use serde::de;
use serde::de::{Error, SeqAccess, Unexpected, Visitor};
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

pub struct HexStrVisitor {
    /// Bytes size of a input. If this field is set None, it allows variable size.
    static_size: Option<usize>,
}

impl HexStrVisitor {
    pub fn new() -> Self {
        HexStrVisitor { static_size: None }
    }

    pub fn with_size(s: usize) -> Self {
        HexStrVisitor {
            static_size: Some(s),
        }
    }
}

impl<'de> Visitor<'de> for HexStrVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string should be a hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match hex::decode(s) {
            Ok(v) => {
                if self.static_size.is_none() || self.static_size.unwrap() == v.len() {
                    Ok(v)
                } else {
                    Err(de::Error::invalid_length(v.len(), &self))
                }
            }
            Err(_) => Err(de::Error::invalid_value(Unexpected::Str(s), &self)),
        }
    }
}
