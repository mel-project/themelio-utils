use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use bincode::Options;
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub mod asstr;
pub mod hex;
pub mod hex32;
pub mod hexvec;
pub mod try_asstr;

/// A wrapper that serializes whatever's wrapped inside with its [Display] and [FromStr] implementations.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
#[serde(transparent)]
pub struct SerializeAsString<T: Display + FromStr + Serialize + DeserializeOwned>(
    #[serde(with = "crate::asstr")] pub T,
)
where
    T::Err: Debug;

/// Safe deserialize that prevents DoS attacks.
pub fn deserialize<T: DeserializeOwned>(bts: &[u8]) -> bincode::Result<T> {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .reject_trailing_bytes()
        .with_limit(bts.len() as u64)
        .deserialize(bts)
}

/// Serialize the stuff
pub fn serialize<T: Serialize>(v: &T) -> bincode::Result<Vec<u8>> {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .reject_trailing_bytes()
        .serialize(v)
}

/// An extension trait for all stdcode-serializable stuff.
pub trait StdcodeSerializeExt: Serialize + Sized {
    fn stdcode(&self) -> Vec<u8> {
        serialize(self).unwrap()
    }
}

impl<T: Serialize + Sized> StdcodeSerializeExt for T {}

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
#[repr(transparent)]
/// A bytevector that serializes as a bytevector for binary formats (like stdcode), but as hex for string formats (like JSON).
///
/// Does not have an ergonomic interface for using directly. Instead, use [HexBytes], which is a [serde_with] adapter.
pub struct HexBytesInner(#[serde(with = "crate::hex")] Vec<u8>);

impl<T: AsRef<[u8]>> From<T> for HexBytesInner {
    fn from(s: T) -> Self {
        HexBytesInner(s.as_ref().to_vec())
    }
}

impl From<HexBytesInner> for Vec<u8> {
    fn from(t: HexBytesInner) -> Self {
        t.0
    }
}

impl From<HexBytesInner> for Bytes {
    fn from(t: HexBytesInner) -> Self {
        t.0.into()
    }
}

/// A type, similar to [serde_with::Bytes], except using hex encoding for text formats.
pub type HexBytes = serde_with::FromInto<HexBytesInner>;
