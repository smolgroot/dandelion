# Dandelion

**Advanced Steganographic File Distributor for Ethereum/EVM Networks**

Dandelion is a sophisticated cryptographic tool that enables secure, decentralized file distribution by hiding encrypted file chunks within blockchain transactions using advanced steganographic techniques. It combines strong encryption with blockchain steganography to create an undetectable file distribution system.

## ✨ Features

- **Encryption**: AES-256-GCM with HMAC-SHA256 integrity verification
- **Advanced Steganography**: Hide data within transaction values, input data, and timing patterns
- **Multi-Network Support**: Monad, Base, Polygon, Ethereum, and any EVM-compatible network
- **Traffic Obfuscation**: Configurable dummy transaction ratio (default 65%) with realistic decoys
- **Variable Chunking**: Adaptive chunk sizes (16-48 bytes) to obscure file characteristics
- **Multi-Layer Security**: File-level and chunk-level integrity verification
- **User-Friendly CLI**: Intuitive command-line interface with progress indicators
- **Auto-Funding**: Automatic wallet funding from master wallet
- **Configurable Logging**: Control verbosity from error-only to full debug traces

## 🚀 Quick Start Guide

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/smolgroot/dandelion.git
cd dandelion

# Build optimized release
cargo build --release
```

### 2. Initialize Configuration

```bash
# Create default configuration (Monad Testnet)
./target/release/dandelion init
```

This creates `dandelion.toml` with default settings for Monad Testnet.

### 3. Create Master Wallet

```bash
# Generate master wallet address for funding
./target/release/dandelion master-wallet --seed "your-secure-master-seed-phrase"
```

**Example output:**
```
🏦 Master Wallet Address: 0x742d35Cc6635C0532925a3b8D0715b32c4e9f5A1
💡 Send ETH to this address to fund distribution wallets automatically
```

### 4. Fund Master Wallet

Send ETH to the master wallet address from your regular wallet or faucet.

### 5. Check Master Wallet Balance

```bash
./target/release/dandelion check-master --seed "your-secure-master-seed-phrase"
```

### 6. Distribute a File

```bash
./target/release/dandelion distribute \
  --file ./secret-document.pdf \
  --seed "your-secure-master-seed-phrase" \
  --passphrase "strong-encryption-passphrase" \
  --output distribution-manifest.json
```

**Example output:**
```
🌼 Dandelion - Steganographic File Distributor
🔐 Preparing file for steganographic distribution...
✅ File prepared: 15 chunks created
🏦 Auto-funding 10 derived wallets from master...
💰 Funding wallets: 10/10 wallets funded successfully
🎭 Distributing with steganography...
📦 Distribution Progress: [████████████████████] 100% (23/23 transactions)
✅ Distribution complete! Manifest saved to: distribution-manifest.json
```

### 7. Retrieve the File

```bash
./target/release/dandelion retrieve \
  --manifest distribution-manifest.json \
  --seed "your-secure-master-seed-phrase" \
  --passphrase "strong-encryption-passphrase" \
  --output retrieved-document.pdf
```

**Example output:**
```
🔍 Retrieving file from blockchain...
📦 Processing chunks: [████████████████████] 100% (15/15)
🔐 Decrypting and reassembling file...
✅ File retrieved successfully: retrieved-document.pdf
🛡️ Integrity verification: PASSED
```

## 🔧 Configuration

### Configuration File (dandelion.toml)

```toml
[network]
rpc_url = "https://testnet-rpc.monad.xyz"
chain_id = 10143
network_name = "Monad Testnet"
gas_price_multiplier = 1.1
confirmation_blocks = 1

[security]
dummy_transaction_ratio = 0.65
timing_jitter_ms = [500, 3000]
chunk_size_range = [16, 48]
decoy_wallets = 20

[performance]
max_concurrent_transactions = 5
retry_attempts = 3
retry_delay_ms = 1000

[logging]
log_level = "info"  # Options: error, warn, info, debug, trace
```

### Supported Networks

| Network | Chain ID | RPC URL | Status |
|---------|----------|---------|--------|
| **Monad Testnet** | 10143 | `https://testnet-rpc.monad.xyz` | ✅ Default |
| **Base Sepolia** | 84532 | `https://sepolia.base.org` | ✅ Tested |
| **Polygon** | 137 | `https://polygon-rpc.com` | ✅ Tested |
| **Base Mainnet** | 8453 | `https://mainnet.base.org` | ✅ Production |
| **Ethereum** | 1 | `https://eth-mainnet.public.blastapi.io` | ⚠️ High Gas |

### Advanced Commands

#### Check Wallet Funding Status
```bash
./target/release/dandelion check-funding \
  --seed "your-master-seed" \
  --count 15
```

#### Manual Wallet Funding
```bash
./target/release/dandelion fund-wallets \
  --seed "your-master-seed" \
  --count 10 \
  --amount 0.005
```

#### Generate Test Wallets (Development)
```bash
./target/release/dandelion generate-wallets \
  --seed "test-seed-phrase" \
  10
```

## 🏗️ Architecture Overview

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Interface │◄──►│ SteganographicDistributor │◄──►│ Configuration   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                   ┌────────────┼────────────┐
                   ▼            ▼            ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │CryptoEngine │ │SteganographyEngine│ │EthereumProvider│
            └─────────────┘ └─────────────┘ └─────────────┘
```

1. **SteganographicDistributor**: Orchestrates the entire distribution process
2. **CryptoEngine**: Handles AES-256-GCM encryption and HMAC integrity
3. **SteganographyEngine**: Manages steganographic encoding within transactions
4. **CLI Interface**: User-friendly command-line interface

### Security Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│Master Seed  │───▶│Key Derivation│───▶│Encryption   │
│+ Passphrase │    │(SHA256-HMAC) │    │Keys         │
└─────────────┘    └──────────────┘    └─────────────┘
                                              │
                                              ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│File Chunks  │◀───│Variable      │◀───│AES-256-GCM  │
│w/ Integrity │    │Chunking      │    │Encryption   │
└─────────────┘    └──────────────┘    └─────────────┘
```

### Steganographic Techniques

#### 1. Transaction Value Steganography
- **Method**: Encode chunk metadata in transaction value's least significant digits
- **Capacity**: 4 digits (0000-9999) encoding chunk_id and total_chunks
- **Detection Resistance**: Values appear as normal micro-transactions

#### 2. Input Data Steganography
- **Method**: Hide encrypted chunks within fake contract call data
- **Structure**: `[function_selector][padding][metadata][chunk_data][integrity][steg_key][padding]`
- **Obfuscation**: Mimics legitimate ERC-20 transfer or DeFi interactions

#### 3. Timing Pattern Obfuscation
- **Method**: Random delays between transactions (500-3000ms)
- **Purpose**: Prevent timing analysis attacks
- **Dummy Ratio**: 65% decoy transactions to obscure real data patterns

## 📊 Protocol Workflow

```
[Original File] ──┐
                  │
[User Passphrase]─┼──► [Key Derivation] ──► [AES-256-GCM Encryption]
                  │         │                        │
[Master Seed] ────┘         │                        ▼
                            │              [Encrypted File Data]
                            │                        │
                            ▼                        ▼
                [Steganographic Keys] ◄── [Variable Chunking]
                            │                        │
                            │                        ▼
                            │              [Encrypted Chunks]
                            │                        │
                            ▼                        ▼
                [Wallet Generation] ◄──── [Transaction Creation]
                            │                        │
                            ▼                        ▼
                [Auto-Funding] ──────────► [Blockchain Distribution]
                                                     │
                                                     ▼
                                          [Transaction Manifest]
```

### Chunk Structure Deep Dive

```rust
pub struct EncryptedChunk {
    pub chunk_id: u16,             // Sequential identifier (0-65535)
    pub total_chunks: u16,         // Total number of chunks in file
    pub data: Vec<u8>,            // Encrypted chunk data (16-48 bytes)
    pub checksum: [u8; 4],        // SHA256 checksum (first 4 bytes)
    pub integrity_proof: [u8; 8], // HMAC-SHA256 proof (first 8 bytes)
    pub sequence_hint: u64,        // Deterministic ordering hint
    pub steganographic_key: [u8; 16], // Unique extraction key per chunk
    pub master_integrity: [u8; 32],   // File-level HMAC for verification
}
```

### Transaction Encoding Format

```
Transaction Value (Wei):
├── Base Value: 100,000 - 1,000,000 (random)
└── Steganographic Data: Last 4 digits
    ├── chunk_id: Upper 16 bits → Last 2 digits  
    └── total_chunks: Lower 16 bits → First 2 digits

Transaction Input Data:
├── Function Selector: [4 bytes] (fake ERC-20 transfer)
├── Random Padding: [32-64 bytes] (realistic parameter data)
├── Chunk Metadata: [12 bytes]
│   ├── chunk_id: [2 bytes]
│   ├── total_chunks: [2 bytes]
│   └── sequence_hint: [8 bytes]
├── Encrypted Chunk Data: [16-48 bytes]
├── Integrity Components: [12 bytes]
│   ├── Checksum: [4 bytes]
│   └── Integrity Proof: [8 bytes]
├── Steganographic Key: [16 bytes]
└── Trailing Padding: [16-32 bytes] (obfuscation)
```

## 🛡️ Security Features

### Cryptographic Security
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: SHA256-based with salt (master_seed + passphrase)
- **Integrity**: HMAC-SHA256 at file and chunk levels
- **Nonces**: Cryptographically secure random nonces per encryption

### Steganographic Security
- **Variable Chunking**: Adaptive sizes prevent pattern analysis
- **Dummy Transactions**: 65% decoy ratio obscures real data
- **Timing Jitter**: Random delays prevent timing correlation
- **Address Rotation**: Unpredictable wallet usage patterns

### Operational Security
- **Master Seed Derivation**: `SHA256("DANDELION_STEG_V1" + user_seed)`
- **Wallet Generation**: Deterministic HD wallet derivation
- **Auto-Funding**: Automatic distribution wallet funding
- **Manifest Protection**: Critical retrieval information isolation

## 🧪 Testing & Validation

### Run Test Suite
```bash
# Full test suite
cargo test

# Verbose output with logs
cargo test -- --nocapture

# Specific module tests
cargo test crypto::tests
cargo test steganography::tests
cargo test distributor::tests
```

### Integration Testing
```bash
# Test with small file
echo "Secret message" > test.txt
./target/release/dandelion distribute --file test.txt --seed "test123" --passphrase "pass123" --output test-manifest.json
./target/release/dandelion retrieve --manifest test-manifest.json --seed "test123" --passphrase "pass123" --output retrieved.txt
diff test.txt retrieved.txt  # Should be identical
```

### Performance Benchmarks
- **Small Files** (< 1KB): ~30 seconds for complete cycle
- **Medium Files** (1-10KB): ~2-5 minutes depending on chunk count
- **Large Files** (> 10KB): Use Layer 2 networks for cost efficiency

## 🚨 Security Considerations

### Best Practices

1. **Strong Seed Phrases**: Use 12+ words from BIP39 wordlist
2. **High-Entropy Passphrases**: Minimum 12 characters with mixed case/symbols
3. **Secure Storage**: Keep seeds offline in hardware wallets or paper backups
4. **Network Privacy**: Use VPN/Tor for enhanced anonymity
5. **Manifest Security**: Encrypt manifest files separately if needed

### Known Limitations

1. **Gas Costs**: Larger files require more transactions (prefer Layer 2)
2. **Timing Analysis**: Very large files may show patterns despite obfuscation
3. **Manifest Dependency**: Loss of manifest makes retrieval impossible
4. **Network Analysis**: Repeated usage patterns may be detectable
5. **Quantum Resistance**: AES-256 provides ~128-bit post-quantum security

### Threat Model

- ✅ **Passive Network Monitoring**: Resistant via steganography
- ✅ **Transaction Analysis**: Resistant via dummy transactions
- ✅ **Timing Correlation**: Resistant via jitter and decoys
- ⚠️ **Targeted Investigation**: May reveal patterns with extensive resources
- ❌ **Quantum Attacks**: Will require post-quantum crypto upgrade
- ❌ **Manifest Compromise**: Exposes file retrieval capability

## 📈 Performance & Costs

### Network Comparison (Est. costs for 1KB file)

| Network | Gas Price | Est. Cost | Confirmation Time |
|---------|-----------|-----------|-------------------|
| Monad Testnet | Free | $0.00 | ~2 seconds |
| Base | Low | $0.50-2.00 | ~10 seconds |
| Polygon | Very Low | $0.10-0.50 | ~30 seconds |
| Ethereum | High | $15-50 | ~2 minutes |

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/yourusername/dandelion.git
cd dandelion
cargo build
cargo test
```

### Contribution Guidelines
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new functionality
4. Ensure `cargo test` passes
5. Update documentation as needed
6. Commit changes (`git commit -m 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open Pull Request

### Code Standards
- **Rust**: Follow `rustfmt` and `clippy` recommendations
- **Security**: All crypto operations must be reviewed
- **Testing**: Minimum 80% code coverage for new features
- **Documentation**: All public APIs must be documented

## ⚖️ Legal & Ethical Considerations

### Intended Use Cases
- ✅ Personal data backup and recovery
- ✅ Secure document distribution in hostile environments
- ✅ Privacy research and education
- ✅ Anti-censorship applications
- ✅ Academic cryptography research

### Prohibited Uses
- ❌ Illegal content distribution
- ❌ Violation of local encryption laws
- ❌ Copyright infringement
- ❌ Malware or exploit distribution

### Compliance Notes
- **US**: Subject to EAR/ITAR export regulations for encryption
- **EU**: Compliant with GDPR for personal data processing
- **China**: May be restricted under local encryption laws
- **Russia**: Subject to SORM monitoring requirements

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[ethers-rs](https://github.com/gakonst/ethers-rs)**: Ethereum integration
- **[aes-gcm](https://crates.io/crates/aes-gcm)**: Authenticated encryption
- **[clap](https://crates.io/crates/clap)**: CLI argument parsing
- **[tokio](https://tokio.rs)**: Async runtime
- **[tracing](https://crates.io/crates/tracing)**: Structured logging

---

**⚠️ Disclaimer**: This software is experimental and provided for educational purposes. Users are solely responsible for compliance with applicable laws and regulations. The authors assume no liability for misuse or legal consequences.
