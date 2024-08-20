use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const KEY: &str = "secret";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    sub: String,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
}

impl Claims {
    fn new(aud: String, sub: String, exp: OffsetDateTime) -> anyhow::Result<Self> {
        let exp = exp
            .date()
            .with_hms_milli(exp.hour(), exp.minute(), exp.second(), 0)?
            .assume_utc();
        Ok(Self { aud, sub, exp })
    }
}

mod jwt_numeric_date {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}

pub fn process_jwt_sign(aud: &str, sub: &str, exp: OffsetDateTime) -> anyhow::Result<String> {
    let key = KEY.as_bytes();
    let my_claims = Claims::new(aud.to_string(), sub.to_string(), exp)?;
    let token = encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(key),
    )?;
    Ok(token)
}

pub fn process_jwt_verify(token: &str, aud: &[&str]) -> anyhow::Result<bool> {
    let key = KEY.as_bytes();
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(aud);
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(key), &validation)?;
    let now = OffsetDateTime::now_utc();
    if now > token_data.claims.exp {
        return Err(anyhow::anyhow!("Token expired"));
    }
    // println!("{:?}", token_data.claims);
    Ok(true)
}
