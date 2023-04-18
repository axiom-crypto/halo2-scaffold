use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Subcommand)]
pub enum SnarkCmd {
    /// Run the mock prover
    Mock,
    /// Generate new proving & verifying keys
    Keygen,
    /// Generate a new proof
    Prove,
    /// Verify a proof
    Verify,
}

impl std::fmt::Display for SnarkCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mock => write!(f, "mock"),
            Self::Keygen => write!(f, "keygen"),
            Self::Prove => write!(f, "prove"),
            Self::Verify => write!(f, "verify"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// Command-line helper for various steps in ZK proving.
pub struct Cli {
    #[command(subcommand)]
    pub command: SnarkCmd,
    #[arg(short, long = "name")]
    pub name: String,
    #[arg(short = 'k', long = "degree")]
    pub degree: u32,
    #[arg(short, long = "input")]
    pub input_path: Option<PathBuf>,
    #[arg(long = "create-contract")]
    pub create_contract: bool,
    #[arg(short, long = "config-path")]
    pub config_path: Option<PathBuf>,
    #[arg(short, long = "data-path")]
    pub data_path: Option<PathBuf>,
}
