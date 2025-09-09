use clap::Parser;
use anyhow::Result;
use tracing::{info, error};

mod distributor;
mod crypto;
mod steganography;
mod cli;

use distributor::SteganographicDistributor;
use cli::{Commands, DistributeArgs, RetrieveArgs};

#[derive(Parser)]
#[command(name = "dandelion")]
#[command(about = "A steganographic file distributor for Ethereum/EVM networks")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// RPC endpoint URL (e.g., https://polygon-rpc.com)
    #[arg(short, long)]
    rpc_url: Option<String>,
    
    /// Network chain ID (137 for Polygon, 8453 for Base)
    #[arg(short, long, default_value = "137")]
    chain_id: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();
    
    info!("🌻 Dandelion - Steganographic File Distributor");
    info!("Chain ID: {}", cli.chain_id);
    
    // Get RPC URL
    let rpc_url = cli.rpc_url.unwrap_or_else(|| {
        match cli.chain_id {
            137 => "https://polygon-rpc.com".to_string(),
            8453 => "https://mainnet.base.org".to_string(),
            _ => {
                error!("Please provide RPC URL for chain ID {}", cli.chain_id);
                std::process::exit(1);
            }
        }
    });
    
    info!("Using RPC: {}", rpc_url);
    
    // Execute command
    match cli.command {
        Commands::Distribute(args) => {
            info!("📤 Distributing file: {}", args.file.display());
            distribute_file(args, &rpc_url).await?;
        }
        Commands::Retrieve(args) => {
            info!("📥 Retrieving file from manifest: {}", args.manifest.display());
            retrieve_file(args, &rpc_url).await?;
        }
        Commands::GenerateWallets { count } => {
            info!("🔑 Generating {} wallets", count);
            generate_wallets(count).await?;
        }
    }
    
    Ok(())
}

async fn distribute_file(args: DistributeArgs, rpc_url: &str) -> Result<()> {
    let distributor = SteganographicDistributor::new(rpc_url, &args.seed).await?;
    
    // Read file
    let file_data = std::fs::read(&args.file)?;
    info!("File size: {} bytes", file_data.len());
    
    // Prepare steganographic chunks
    let (chunks, master_integrity) = distributor.prepare_steganographic_file(&file_data, &args.passphrase)?;
    info!("Created {} chunks", chunks.len());
    
    // Distribute across network
    let manifest = distributor.distribute_with_steganography(chunks, vec![], &args.passphrase).await?;
    
    // Save manifest
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&args.output, manifest_json)?;
    
    info!("✅ File distributed successfully!");
    info!("📋 Manifest saved to: {}", args.output.display());
    info!("🔒 Master integrity: {}", hex::encode(master_integrity));
    
    Ok(())
}

async fn retrieve_file(args: RetrieveArgs, rpc_url: &str) -> Result<()> {
    let distributor = SteganographicDistributor::new(rpc_url, &args.seed).await?;
    
    // Load manifest
    let manifest_json = std::fs::read_to_string(&args.manifest)?;
    let manifest = serde_json::from_str(&manifest_json)?;
    
    // Retrieve file
    let file_data = distributor.retrieve_steganographic_file(&manifest, &args.passphrase).await?;
    
    // Save retrieved file
    std::fs::write(&args.output, file_data)?;
    
    info!("✅ File retrieved successfully!");
    info!("💾 Saved to: {}", args.output.display());
    
    Ok(())
}

async fn generate_wallets(count: usize) -> Result<()> {
    use ethers::prelude::*;
    use rand::RngCore;
    
    println!("🔑 Generated Wallets:");
    println!("{:-<80}", "");
    
    for i in 0..count {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        
        let wallet = LocalWallet::from_bytes(&seed)?;
        println!("Wallet #{:02}: {}", i + 1, wallet.address());
        println!("Private Key: 0x{}", hex::encode(wallet.signer().to_bytes()));
        println!();
    }
    
    Ok(())
}
