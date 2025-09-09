use clap::Parser;
use anyhow::Result;
use tracing::{info, error};
use rand::SeedableRng;

mod distributor;
mod crypto;
mod steganography;
mod cli;
mod config;

use distributor::SteganographicDistributor;
use cli::{Commands, DistributeArgs, RetrieveArgs, Cli};
use config::DandelionConfig;
use ethers::prelude::*;

async fn generate_wallets(seed: &str, count: usize) -> Result<()> {
    use sha2::{Sha256, Digest};
    use rand::{SeedableRng, RngCore};
    
    // Create deterministic seed from the input string (same as check-funding)
    let mut hasher = Sha256::new();
    hasher.update(b"DANDELION_STEG_V1");
    hasher.update(seed.as_bytes());
    let master_seed: [u8; 32] = hasher.finalize().into();
    
    println!("🔑 Generated Wallets:");
    println!("{:-<80}", "");
    
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(master_seed);
    
    for i in 0..count {
        let mut wallet_seed = [0u8; 32];
        rng.fill_bytes(&mut wallet_seed);
        
        // Mix in salt and index (same as check-funding)
        for (j, &byte) in seed.as_bytes().iter().enumerate() {
            if j < 32 { wallet_seed[j] ^= byte; }
        }
        wallet_seed[0] ^= (i & 0xFF) as u8;
        wallet_seed[1] ^= ((i >> 8) & 0xFF) as u8;
        
        let wallet = LocalWallet::from_bytes(&wallet_seed)?;
        println!("Wallet #{:02}: 0x{:x}", i + 1, wallet.address());
        println!("Private Key: 0x{}", hex::encode(wallet.signer().to_bytes()));
        println!();
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();
    
    info!(" Dandelion - Steganographic File Distributor");
    
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
        Commands::GenerateWallets { seed, count } => {
            info!("🔑 Generating {} wallets", count);
            generate_wallets(&seed, count).await?;
        }
        Commands::CheckFunding { seed, count } => {
            info!("💰 Checking funding for {} wallets", count);
            check_wallet_funding(&seed, count, &rpc_url).await?;
        }
        Commands::MasterWallet { seed } => {
            info!("🏦 Getting master wallet address");
            show_master_wallet(&seed).await?;
        }
        Commands::FundWallets { seed, count, amount } => {
            info!("💸 Funding {} wallets with {} ETH each", count, amount);
            fund_derived_wallets(&seed, count, amount, &rpc_url).await?;
        }
        Commands::CheckMaster { seed } => {
            info!("💰 Checking master wallet balance");
            check_master_wallet_balance(&seed, &rpc_url).await?;
        }
    }
    
    Ok(())
}

async fn distribute_file(args: DistributeArgs, rpc_url: &str, config: &DandelionConfig) -> Result<()> {
    // Auto-fund wallets if requested
    if args.auto_fund {
        info!("🏦 Auto-funding enabled - checking and funding wallets...");
        
        // Check if wallets need funding
        let funding_check = check_wallet_funding_internal(&args.seed, args.wallet_count, rpc_url).await;
        match funding_check {
            Ok(false) => {
                info!("💰 Wallets need funding - attempting auto-fund...");
                fund_derived_wallets(&args.seed, args.wallet_count, args.fund_amount, rpc_url).await?;
            }
            Ok(true) => {
                info!("✅ Wallets already funded");
            }
            Err(e) => {
                return Err(anyhow::anyhow!("❌ Failed to check wallet funding: {}", e));
            }
        }
    }
    
    let distributor = SteganographicDistributor::new(rpc_url, &args.seed, config.clone()).await?;
    
    // Read file
    let file_data = std::fs::read(&args.file)?;
    info!("File size: {} bytes", file_data.len());
    
    // Prepare steganographic chunks
    let (chunks, master_integrity) = distributor.prepare_steganographic_file(&file_data, &args.passphrase)?;
    info!("Created {} chunks", chunks.len());
    
    // Distribute across network with fixed wallet count
    let mut manifest = distributor.distribute_with_steganography_fixed_wallets(
        chunks, 
        vec![], 
        &args.passphrase,
        args.wallet_count
    ).await?;
    
    // Set the master integrity
    manifest.master_integrity = hex::encode(master_integrity);
    
    // Save manifest
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&args.output, manifest_json)?;
    
    info!("✅ File distributed successfully!");
    info!("📋 Manifest saved to: {}", args.output.display());
    info!("🔒 Master integrity: {}", hex::encode(master_integrity));
    info!("🏦 Used {} wallets for distribution", args.wallet_count);
    
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
        
        println!("Wallet #{:02}: 0x{:x} | {} ETH | {}", 
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

async fn show_master_wallet(seed: &str) -> Result<()> {
    use sha2::{Sha256, Digest};
    
    // Create master wallet from seed
    let mut hasher = Sha256::new();
    hasher.update(b"DANDELION_MASTER_V1");
    hasher.update(seed.as_bytes());
    let master_seed: [u8; 32] = hasher.finalize().into();
    
    let master_wallet = LocalWallet::from_bytes(&master_seed)?;
    
    println!("🏦 Master Wallet Information:");
    println!("{:-<80}", "");
    println!("Master Address: 0x{:x}", master_wallet.address());
    println!("Private Key: 0x{}", hex::encode(master_wallet.signer().to_bytes()));
    println!();
    println!("💡 Fund this address and use 'fund-wallets' to distribute to derived wallets");
    println!("🌐 For Monad Testnet, visit https://testnet.monadexplorer.com for testnet resources");
    
    Ok(())
}

async fn fund_derived_wallets(seed: &str, count: usize, amount_eth: f64, rpc_url: &str) -> Result<()> {
    use ethers::prelude::*;
    use ethers::types::transaction::eip2718::TypedTransaction;
    use sha2::{Sha256, Digest};
    use rand::{SeedableRng, RngCore};
    
    // Connect to network
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?;
    info!("🌐 Connected to chain ID: {}", chain_id);
    
    // Create master wallet
    let mut hasher = Sha256::new();
    hasher.update(b"DANDELION_MASTER_V1");
    hasher.update(seed.as_bytes());
    let master_seed: [u8; 32] = hasher.finalize().into();
    let master_wallet = LocalWallet::from_bytes(&master_seed)?.with_chain_id(chain_id.as_u64());
    
    // Check master wallet balance
    let master_balance = provider.get_balance(master_wallet.address(), None).await?;
    let amount_wei = ethers::utils::parse_ether(amount_eth)?;
    let total_needed = amount_wei * U256::from(count);
    
    println!("🏦 Master Wallet: 0x{:x}", master_wallet.address());
    println!("💰 Balance: {} ETH", ethers::utils::format_ether(master_balance));
    println!("💸 Total needed: {} ETH ({} wallets × {} ETH)", 
        ethers::utils::format_ether(total_needed), count, amount_eth);
    
    if master_balance < total_needed {
        return Err(anyhow::anyhow!(
            "❌ Insufficient master wallet balance! Need {} ETH, have {} ETH",
            ethers::utils::format_ether(total_needed),
            ethers::utils::format_ether(master_balance)
        ));
    }
    
    // Generate derived wallets (same derivation as other commands)
    let mut derived_hasher = Sha256::new();
    derived_hasher.update(b"DANDELION_STEG_V1");
    derived_hasher.update(seed.as_bytes());
    let derived_master_seed: [u8; 32] = derived_hasher.finalize().into();
    
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(derived_master_seed);
    let mut wallets = Vec::new();
    
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
    
    println!("🚀 Starting wallet funding...");
    println!();
    
    // Fund each wallet
    for (i, wallet) in wallets.iter().enumerate() {
        println!("💸 Funding wallet #{:02}: 0x{:x}", i + 1, wallet.address());
        
        // Create transaction
        let tx = TransactionRequest::new()
            .to(wallet.address())
            .value(amount_wei)
            .gas(21000);
        
        // Get gas price and nonce
        let gas_price = provider.get_gas_price().await?;
        let nonce = provider.get_transaction_count(master_wallet.address(), None).await?;
        
        // Build transaction
        let tx = tx.gas_price(gas_price).nonce(nonce);
        
        // Sign and send transaction
        let typed_tx: TypedTransaction = tx.into();
        let signature = master_wallet.sign_transaction(&typed_tx).await?;
        let signed_tx = typed_tx.rlp_signed(&signature);
        let pending_tx = provider.send_raw_transaction(signed_tx).await?;
        let receipt = pending_tx.await?;
        
        if let Some(receipt) = receipt {
            println!("✅ Success! Tx: 0x{:x}", receipt.transaction_hash);
        } else {
            println!("⚠️  Transaction sent but receipt not available");
        }
    }
    
    println!();
    println!("🎉 All wallets funded successfully!");
    println!("💡 Run 'check-funding' to verify balances");
    
    Ok(())
}

async fn check_wallet_funding_internal(seed: &str, count: usize, rpc_url: &str) -> Result<bool> {
    use ethers::prelude::*;
    use rand::{RngCore, SeedableRng};
    use sha2::{Sha256, Digest};
    
    // Connect to network
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    // Derive master seed (same as other functions)
    let mut hasher = Sha256::new();
    hasher.update(b"DANDELION_STEG_V1");
    hasher.update(seed.as_bytes());
    let master_seed: [u8; 32] = hasher.finalize().into();
    
    // Generate wallets
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(master_seed);
    let min_required = ethers::utils::parse_ether(0.001)?; // 0.001 ETH minimum
    
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
        let balance = provider.get_balance(wallet.address(), None).await?;
        
        if balance < min_required {
            return Ok(false); // At least one wallet needs funding
        }
    }
    
    Ok(true) // All wallets are funded
}

async fn check_master_wallet_balance(seed: &str, rpc_url: &str) -> Result<()> {
    use ethers::prelude::*;
    use sha2::{Sha256, Digest};
    
    // Connect to network
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    // Generate master wallet (same derivation as in show_master_wallet)
    let mut hasher = Sha256::new();
    hasher.update(b"DANDELION_MASTER_V1");
    hasher.update(seed.as_bytes());
    let master_seed: [u8; 32] = hasher.finalize().into();
    let master_wallet = LocalWallet::from_bytes(&master_seed)?;
    
    // Get balance
    let balance = provider.get_balance(master_wallet.address(), None).await?;
    let balance_eth = ethers::utils::format_ether(balance);
    
    println!("💰 Master Wallet Balance Information:");
    println!("--------------------------------------------------------------------------------");
    println!("Master Address: 0x{:x}", master_wallet.address());
    println!("Balance: {} ETH", balance_eth);
    println!("Balance (Wei): {}", balance);
    
    if balance.is_zero() {
        println!();
        println!("⚠️  Master wallet has no funds!");
        println!("💡 Fund this address before using 'fund-wallets' command");
        println!("🌐 For Monad Testnet, visit https://testnet.monadexplorer.com for testnet resources");
    } else {
        println!();
        println!("✅ Master wallet is funded and ready to distribute to derived wallets");
    }
    
    Ok(())
}
