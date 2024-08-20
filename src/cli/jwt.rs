use crate::{process_jwt_sign, process_jwt_verify, CmdExecutor};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum JwtSubCommand {
    #[command(name = "sign", about = "Sign a JWT")]
    Sign(JwtSignOpts),
    #[command(name = "verify", about = "Verify a JWT")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
    #[arg(short, long, default_value = "")]
    pub aud: String,
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(long, default_value = "")]
    pub sub: String,
    #[arg(long, default_value = "")]
    pub aud: String,
    #[arg(long, value_parser=parse_jwt_date)]
    pub exp: OffsetDateTime,
}

fn parse_jwt_date(format: &str) -> Result<OffsetDateTime, anyhow::Error> {
    let iat = OffsetDateTime::now_utc();
    let format = format.to_lowercase();
    let times = &format[..format.len() - 1];
    let time = times.parse::<i64>()?;
    let flag_date = format.chars().last().unwrap();
    let exp = match flag_date {
        's' => iat + Duration::seconds(time),
        'm' => iat + Duration::minutes(time),
        'h' => iat + Duration::hours(time),
        'd' => iat + Duration::days(time),
        'w' => iat + Duration::weeks(time),
        _ => iat + Duration::seconds(time),
    };
    Ok(exp)
}

impl CmdExecutor for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        // println!("Verify JWT: {}", self.token);
        let is_val = process_jwt_verify(&self.token, &[&self.aud])?;
        if is_val {
            println!("Token is valid");
        } else {
            println!("Token is invalid");
        }
        Ok(())
    }
}

impl CmdExecutor for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(&self.aud, &self.sub, self.exp)?;
        println!("{}", token);
        Ok(())
    }
}
