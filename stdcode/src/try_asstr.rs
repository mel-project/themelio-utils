use std::{fmt::Debug, str::FromStr};

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
    <T as std::str::FromStr>::Err: Debug,
{
    if deserializer.is_human_readable() {
        let s = MaybeString::deserialize(deserializer)?;
        match s {
            MaybeString::String(s) => s
                .parse()
                .map_err(|e| serde::de::Error::custom(format!("FromStr parsing error {:?}", e))),
            MaybeString::Tee(t) => Ok(t),
        }
    } else {
        T::deserialize(deserializer)
    }
    // let s = <&str>::deserialize(deserializer)?;
    // base64::decode(s).map_err(de::Error::custom)
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum MaybeString<T> {
    String(String),
    Tee(T),
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, str::FromStr};

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Debug)]
    struct Inner {
        laboo: String,
    }

    impl FromStr for Inner {
        type Err = Infallible;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(Self {
                laboo: s.to_string(),
            })
        }
    }

    #[derive(Deserialize, PartialEq, PartialOrd, Ord, Eq, Debug)]
    struct Test {
        #[serde(with = "crate::try_asstr")]
        hello: Inner,
    }

    #[test]
    fn try_asstr() {
        let tt: Test = serde_json::from_str(dbg!("{\"hello\": \"world\"}")).unwrap();
        let ttt: Test = serde_json::from_str(dbg!("{\"hello\": {\"laboo\": \"world\"}}")).unwrap();
        assert_eq!(tt, ttt)
    }
}
