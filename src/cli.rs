use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize configuration file
    Init,
    
    /// Distribute a file across the blockchain using steganography
    Distribute(DistributeArgs),
    
    /// Retrieve a file from the blockchain using a manifest
    Retrieve(RetrieveArgs),
    
    /// Generate test wallets for development
    GenerateWallets {
        /// Number of wallets to generate
        count: usize,
    },
    
    /// Check wallet funding status
    CheckFunding {
        /// Master seed for wallet generation
        #[arg(short, long)]
        seed: String,
        
        /// Number of wallets to check
        #[arg(short, long, default_value = "10")]
        count: usize,
    },
}

#[derive(Parser)]
pub struct DistributeArgs {
    /// File to distribute
    #[arg(short, long)]
    pub file: PathBuf,
    
    /// Output manifest file path
    #[arg(short, long, default_value = "manifest.json")]
    pub output: PathBuf,
    
    /// Master seed for wallet generation
    #[arg(short, long)]
    pub seed: String,
    
    /// Passphrase for encryption
    #[arg(short, long)]
    pub passphrase: String,
    
    /// Maximum chunk size in bytes
    #[arg(long, default_value = "32")]
    pub chunk_size: usize,
    
    /// Dummy transaction ratio (0.0-1.0)
    #[arg(long, default_value = "0.65")]
    pub dummy_ratio: f64,
    
    /// Number of decoy wallets
    #[arg(long, default_value = "20")]
    pub decoy_wallets: usize,
}

#[derive(Parser)]
pub struct RetrieveArgs {
    /// Manifest file containing distribution metadata
    #[arg(short, long)]
    pub manifest: PathBuf,
    
    /// Output file path for retrieved file
    #[arg(short, long)]
    pub output: PathBuf,
    
    /// Master seed for wallet generation (must match distribution)
    #[arg(short, long)]
    pub seed: String,
    
    /// Passphrase for decryption (must match distribution)
    #[arg(short, long)]
    pub passphrase: String,
}
