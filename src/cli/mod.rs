mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;

use std::path::{Path, PathBuf};

use clap::Parser;
use enum_dispatch::enum_dispatch;

pub use self::{base64::*, csv::*, genpass::*, http::*, jwt::*, text::*};

// rcli csv -i input.csv -o output.csv --header -d ','
#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about=None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}
#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum SubCommand {
    #[command(name = "csv", about = "SHow CSV, or Convert CSV to other formats")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand, about = "Base64 encode or decode")]
    Base64(Base64SubCommand),
    #[command(subcommand, about = "Text signing and verification")]
    Text(TextSubCommand),
    #[command(subcommand, about = "HTTP server")]
    Http(HttpSubCommand),
    #[command(subcommand, about = "JWT signing and verification")]
    Jwt(JwtSubCommand),
}

fn verify_file(filename: &str) -> Result<String, String> {
    if Path::new(filename).exists() || filename == "-" {
        Ok(filename.into())
    } else {
        Err("File does not exist".into())
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_input_file() {
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("File does not exist".into()));
        assert_eq!(
            verify_file("non-existent-file"),
            Err("File does not exist".into())
        );
    }
}
