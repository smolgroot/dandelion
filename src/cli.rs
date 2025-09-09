use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "A steganographic file distributor for Ethereum/EVM networks")]
pub struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
    
    /// RPC endpoint URL (e.g., https://polygon-rpc.com)
    #[arg(short, long)]
    pub rpc_url: Option<String>,
    
    /// Network chain ID (137 for Polygon, 8453 for Base)
    #[arg(short, long, default_value = "137")]
    pub chain_id: u64,
    
    #[command(subcommand)]
    pub command: Commands,
}

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
        /// Master seed for wallet generation
        #[arg(short, long)]
        seed: String,
        
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
    
    /// Generate master wallet address for funding
    MasterWallet {
        /// Master seed for wallet generation
        #[arg(short, long)]
        seed: String,
    },
    
    /// Fund derived wallets from master wallet
    FundWallets {
        /// Master seed for wallet generation
        #[arg(short, long)]
        seed: String,
        
        /// Number of wallets to fund
        #[arg(short, long, default_value = "10")]
        count: usize,
        
        /// Amount to fund each wallet (in ETH)
        #[arg(short, long, default_value = "0.005")]
        amount: f64,
    },
    
    /// Check master wallet balance
    CheckMaster {
        /// Master seed for wallet generation
        #[arg(short, long)]
        seed: String,
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
    
    /// Number of wallets to use for distribution (fixed for consistency)
    #[arg(long, default_value = "10")]
    pub wallet_count: usize,
    
    /// Auto-fund derived wallets from master wallet
    #[arg(long, default_value_t = true)]
    pub auto_fund: bool,
    
    /// Amount to fund each derived wallet (in ETH)
    #[arg(long, default_value = "0.005")]
    pub fund_amount: f64,
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
