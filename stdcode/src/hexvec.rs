use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

pub fn serialize<S>(bytes: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // SAFETY: relies on repr(transparent)
    let casted: &[HexBytes] = unsafe { std::mem::transmute(bytes) };
    casted.serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let lala: Vec<HexBytes> = Deserialize::deserialize(deserializer)?;
    Ok(unsafe { std::mem::transmute(lala) })
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
struct HexBytes(#[serde(with = "crate::hex")] pub Vec<u8>);
