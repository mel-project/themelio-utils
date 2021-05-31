use std::str::FromStr;

use serde::Deserialize;
use serde::{Deserializer, Serialize, Serializer};

pub fn serialize<T: ToString + Serialize, S>(val: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&val.to_string())
    } else {
        val.serialize(serializer)
    }
}

pub fn deserialize<'de, T: FromStr + Deserialize<'de>, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s = <&str>::deserialize(deserializer)?;
        s.parse()
            .map_err(|_| serde::de::Error::custom("FromStr parsing error"))
    } else {
        T::deserialize(deserializer)
    }
    // let s = <&str>::deserialize(deserializer)?;
    // base64::decode(s).map_err(de::Error::custom)
}
