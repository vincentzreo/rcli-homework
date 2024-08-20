use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    sub: String,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
}

impl Claims {
    pub fn new(aud: String, sub: String, exp: OffsetDateTime) -> anyhow::Result<Self> {
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

fn main() -> anyhow::Result<()> {
    let key = b"secret";
    let iat = OffsetDateTime::now_utc();
    let exp = iat + Duration::days(1);
    let my_claims = Claims::new("me".to_string(), "b@b.com".to_string(), exp)?;
    let token = encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(key),
    )?;
    println!("{}", token);
    let mut validation = Validation::new(Algorithm::HS256);
    validation.sub = Some("b@b.com".to_string());
    validation.set_audience(&["me"]);
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    let token_data = match decode::<Claims>(&token, &DecodingKey::from_secret(key), &validation) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
            _ => panic!("Some other errors"),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
    Ok(())
}
