use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DandelionConfig {
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub performance: PerformanceConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub network_name: String,
    pub gas_price_multiplier: f64,
    pub confirmation_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub dummy_transaction_ratio: f64,
    pub timing_jitter_ms: (u64, u64),
    pub chunk_size_range: (usize, usize),
    pub decoy_wallets: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_concurrent_transactions: usize,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                rpc_url: "https://testnet-rpc.monad.xyz".to_string(),
                chain_id: 10143, // Monad Testnet
                network_name: "Monad Testnet".to_string(),
                gas_price_multiplier: 1.1,
                confirmation_blocks: 1,
            },
            security: SecurityConfig {
                dummy_transaction_ratio: 0.65,
                timing_jitter_ms: (500, 3000),
                chunk_size_range: (16, 48),
                decoy_wallets: 20,
            },
            performance: PerformanceConfig {
                max_concurrent_transactions: 5,
                retry_attempts: 3,
                retry_delay_ms: 1000,
            },
            logging: LoggingConfig {
                log_level: "info".to_string(),
            },
        }
    }
}

impl DandelionConfig {
    pub fn load_or_default() -> Result<Self> {
        if Path::new("dandelion.toml").exists() {
            Self::load_from_file("dandelion.toml")
        } else {
            Ok(Self::default())
        }
    }
    
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: DandelionConfig = toml::from_str(&content)?;
        Ok(config)
    }
    
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    pub fn init_default_config() -> Result<()> {
        let config = Self::default();
        config.save_to_file("dandelion.toml")?;
        
        println!("Dandelion configuration initialized!");
        println!("📁 Config file created: dandelion.toml");
        println!("🌐 Default network: {} (Chain ID: {})", 
            config.network.network_name, config.network.chain_id);
        println!("🔧 Edit dandelion.toml to customize settings");
        
        Ok(())
    }
    
    pub fn get_network_info(&self) -> (String, u64) {
        (self.network.rpc_url.clone(), self.network.chain_id)
    }
}

// Predefined network configurations
impl DandelionConfig {
    pub fn monad_testnet() -> Self {
        let mut config = Self::default();
        config.network = NetworkConfig {
            rpc_url: "https://testnet-rpc.monad.xyz".to_string(),
            chain_id: 10143,
            network_name: "Monad Testnet".to_string(),
            gas_price_multiplier: 1.1,
            confirmation_blocks: 1,
        };
        config
    }

    pub fn base_sepolia() -> Self {
        let mut config = Self::default();
        config.network = NetworkConfig {
            rpc_url: "https://sepolia.base.org".to_string(),
            chain_id: 84532,
            network_name: "Base Sepolia".to_string(),
            gas_price_multiplier: 1.1,
            confirmation_blocks: 1,
        };
        config
    }
    
    pub fn base_mainnet() -> Self {
        let mut config = Self::default();
        config.network = NetworkConfig {
            rpc_url: "https://mainnet.base.org".to_string(),
            chain_id: 8453,
            network_name: "Base Mainnet".to_string(),
            gas_price_multiplier: 1.2,
            confirmation_blocks: 3,
        };
        config
    }
    
    pub fn polygon_mumbai() -> Self {
        let mut config = Self::default();
        config.network = NetworkConfig {
            rpc_url: "https://rpc-mumbai.maticvigil.com".to_string(),
            chain_id: 80001,
            network_name: "Polygon Mumbai".to_string(),
            gas_price_multiplier: 1.1,
            confirmation_blocks: 1,
        };
        config
    }
    
    pub fn polygon_mainnet() -> Self {
        let mut config = Self::default();
        config.network = NetworkConfig {
            rpc_url: "https://polygon-rpc.com".to_string(),
            chain_id: 137,
            network_name: "Polygon Mainnet".to_string(),
            gas_price_multiplier: 1.2,
            confirmation_blocks: 3,
        };
        config
    }
}
