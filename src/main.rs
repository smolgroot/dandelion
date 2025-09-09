use clap::Parser;
use anyhow::Result;
use tracing::{info, error};

mod distributor;
mod crypto;
mod steganography;
mod cli;
mod config;

use distributor::SteganographicDistributor;
use cli::{Commands, DistributeArgs, RetrieveArgs};
use config::DandelionConfig;

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
    
    // Load configuration
    let config = DandelionConfig::load_or_default()?;
    
    // Override config with CLI parameters
    let (rpc_url, chain_id) = if let Some(url) = cli.rpc_url {
        (url, cli.chain_id)
    } else {
        config.get_network_info()
    };
    
    info!("Chain ID: {}", chain_id);
    info!("Using RPC: {}", rpc_url);
    
    // Execute command
    match cli.command {
        Commands::Init => {
            DandelionConfig::init_default_config()?;
        }
        Commands::Distribute(args) => {
            info!("📤 Distributing file: {}", args.file.display());
            distribute_file(args, &rpc_url, &config).await?;
        }
        Commands::Retrieve(args) => {
            info!("📥 Retrieving file from manifest: {}", args.manifest.display());
            retrieve_file(args, &rpc_url, &config).await?;
        }
        Commands::GenerateWallets { count } => {
            info!("🔑 Generating {} wallets", count);
            generate_wallets(count).await?;
        }
        Commands::CheckFunding { seed, count } => {
            info!("💰 Checking funding for {} wallets", count);
            check_wallet_funding(&seed, count, &rpc_url).await?;
        }
    }
    
    Ok(())
}

async fn distribute_file(args: DistributeArgs, rpc_url: &str, config: &DandelionConfig) -> Result<()> {
    let distributor = SteganographicDistributor::new(rpc_url, &args.seed, config.clone()).await?;
    
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

async fn retrieve_file(args: RetrieveArgs, rpc_url: &str, config: &DandelionConfig) -> Result<()> {
    let distributor = SteganographicDistributor::new(rpc_url, &args.seed, config.clone()).await?;
    
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

async fn check_wallet_funding(seed: &str, count: usize, rpc_url: &str) -> Result<()> {
    use ethers::prelude::*;
    use rand::{RngCore, SeedableRng};
    use sha2::{Sha256, Digest};
    
    // Connect to network
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?;
    info!("🌐 Connected to chain ID: {}", chain_id);
    
    // Derive master seed
    let mut hasher = Sha256::new();
    hasher.update(b"DANDELION_STEG_V1");
    hasher.update(seed.as_bytes());
    let master_seed: [u8; 32] = hasher.finalize().into();
    
    // Generate wallets
    let mut wallets = Vec::new();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(master_seed);
    
    for i in 0..count {
        let mut wallet_seed = [0u8; 32];
        rng.fill_bytes(&mut wallet_seed);
        
        // Mix in salt and index
        for (j, &byte) in seed.as_bytes().iter().enumerate() {
            if j < 32 { wallet_seed[j] ^= byte; }
        }
        wallet_seed[0] ^= (i & 0xFF) as u8;
        wallet_seed[1] ^= ((i >> 8) & 0xFF) as u8;
        
        let wallet = LocalWallet::from_bytes(&wallet_seed)?;
        wallets.push(wallet);
    }
    
    // Check funding
    let mut total_balance = U256::zero();
    let min_required = U256::from(1_000_000_000_000_000u64); // 0.001 ETH minimum
    let mut funded_count = 0;
    
    println!("💰 Wallet Funding Status:");
    println!("{:-<80}", "");
    
    for (i, wallet) in wallets.iter().enumerate() {
        let balance = provider.get_balance(wallet.address(), None).await.unwrap_or(U256::zero());
        let balance_eth = ethers::utils::format_ether(balance);
        
        let status = if balance >= min_required {
            funded_count += 1;
            "✅ FUNDED"
        } else {
            "❌ NEEDS FUNDING"
        };
        
        println!("Wallet #{:02}: {} | {} ETH | {}", 
            i + 1, wallet.address(), balance_eth, status);
        
        total_balance += balance;
    }
    
    println!("{:-<80}", "");
    println!("📊 Summary:");
    println!("  Total wallets: {}", count);
    println!("  Funded wallets: {}", funded_count);
    println!("  Total balance: {} ETH", ethers::utils::format_ether(total_balance));
    println!("  Minimum required per wallet: {} ETH", ethers::utils::format_ether(min_required));
    
    if funded_count == 0 {
        println!("\n🚨 No wallets have funding! You need to send ETH to these addresses to use Dandelion.");
        
        // Provide network-specific guidance
        let config = DandelionConfig::load_or_default()?;
        match config.network.chain_id {
            10143 => println!("💡 For Monad Testnet, visit https://testnet.monadexplorer.com for testnet resources."),
            84532 => println!("💡 For Base Sepolia testnet, get free ETH from: https://faucet.quicknode.com/base/sepolia"),
            80001 => println!("💡 For Polygon Mumbai testnet, get free MATIC from: https://faucet.polygon.technology/"),
            _ => println!("💡 Check the network's documentation for testnet faucets."),
        }
    } else if funded_count < count {
        println!("\n⚠️  Only {}/{} wallets are funded. Consider funding more for better obfuscation.", funded_count, count);
    } else {
        println!("\n🎉 All wallets are funded and ready for steganographic distribution!");
    }
    
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
