use clap::Parser;

use rcli::CmdExecutor;
use rcli::Opts;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    opts.cmd.execute().await?;
    Ok(())
}
