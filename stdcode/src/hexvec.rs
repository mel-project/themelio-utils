use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

use crate::HexBytesInner;

pub fn serialize<S>(bytes: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // SAFETY: relies on repr(transparent)
    let casted: &[HexBytesInner] = unsafe { std::mem::transmute(bytes) };
    casted.serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let lala: Vec<HexBytesInner> = Deserialize::deserialize(deserializer)?;
    Ok(unsafe { std::mem::transmute(lala) })
}
