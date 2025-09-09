#  Dandelion

**Steganographic File Distributor for Ethereum/EVM Networks**

Dandelion is a sophisticated tool that enables secure, decentralized file distribution by hiding encrypted file chunks within blockchain transactions using advanced steganographic techniques.

## ✨ Features

- **Advanced Encryption**: AES-256-GCM encryption with HMAC integrity verification
- **Steganographic Obfuscation**: Hide data within transaction values and input data
- **Multi-Network Support**: Works with Monad, Base, Polygon, and other EVM-compatible networks
- **Traffic Obfuscation**: Dummy transactions and variable timing to hide patterns
- **Variable Chunking**: Non-uniform chunk sizes to obscure file characteristics
- **Integrity Verification**: Multi-layer integrity checks for data authenticity
- **CLI Interface**: Easy-to-use command-line interface

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/smolgroot/dandelion.git
cd dandelion

# Build the project
cargo build --release
```

### Basic Usage

#### Initialize Configuration

```bash
# Create default configuration file (uses Monad Testnet by default)
./target/release/dandelion init
```

#### Check Wallet Funding

```bash
# Check if wallets have sufficient funding
./target/release/dandelion check-funding \
  --seed "your-master-seed-phrase" \
  --count 10
```

#### Distribute a File

```bash
./target/release/dandelion distribute \
  --file ./secret.txt \
  --seed "your-master-seed-phrase" \
  --passphrase "encryption-passphrase" \
  --output manifest.json \
  --rpc-url https://testnet-rpc.monad.xyz \
  --chain-id 10143
```

#### Retrieve a File

```bash
./target/release/dandelion retrieve \
  --manifest manifest.json \
  --seed "your-master-seed-phrase" \
  --passphrase "encryption-passphrase" \
  --output retrieved-secret.txt \
  --rpc-url https://polygon-rpc.com
```

#### Generate Test Wallets

```bash
./target/release/dandelion generate-wallets 10
```

## 🔧 Configuration

### Environment Variables

```bash
export RPC_URL="https://polygon-rpc.com"
export CHAIN_ID="137"
```

### Supported Networks

- **Monad Testnet** (Chain ID: 10143) - `https://testnet-rpc.monad.xyz` [Default]
- **Base Sepolia** (Chain ID: 84532) - `https://sepolia.base.org`
- **Polygon** (Chain ID: 137) - `https://polygon-rpc.com`
- **Base** (Chain ID: 8453) - `https://mainnet.base.org`
- **Custom EVM** - Provide your own RPC URL

## 🏗️ Architecture

### Core Components

1. **SteganographicDistributor** - Main orchestrator for file distribution
2. **CryptoEngine** - Handles encryption, decryption, and integrity verification
3. **SteganographyEngine** - Manages steganographic encoding/decoding
4. **CLI Interface** - Command-line interface for user interaction

### Security Features

- **Key Derivation**: Secure key derivation from master seed and passphrase
- **Variable Chunking**: Random chunk sizes (16-48 bytes) to hide file patterns
- **Dummy Transactions**: 65% dummy transaction ratio for traffic obfuscation
- **Timing Obfuscation**: Random delays between transactions
- **Multi-layer Integrity**: File-level and chunk-level HMAC verification

### Steganographic Techniques

1. **Transaction Value Encoding**: Metadata hidden in least significant digits
2. **Input Data Obfuscation**: Chunks hidden within fake contract call data
3. **Address Pattern Masking**: Unpredictable wallet usage patterns
4. **Decoy Generation**: Realistic dummy transactions

## 📊 Example Workflow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ Original    │───▶│ Encrypt &    │───▶│ Variable    │
│ File        │    │ Fragment     │    │ Chunks      │
└─────────────┘    └──────────────┘    └─────────────┘
                                              │
                                              ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ Manifest    │◀───│ Steganographic│◀───│ Generate    │
│ File        │    │ Distribution  │    │ Wallets     │
└─────────────┘    └──────────────┘    └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ Blockchain  │
                   │ Transactions│
                   └─────────────┘
```

## 🔬 Technical Details

### Chunk Structure

```rust
pub struct EncryptedChunk {
    pub chunk_id: u16,           // Sequential identifier
    pub total_chunks: u16,       // Total number of chunks
    pub data: Vec<u8>,          // Encrypted chunk data
    pub checksum: [u8; 4],      // SHA256 checksum (truncated)
    pub integrity_proof: [u8; 8], // HMAC proof (truncated)
    pub sequence_hint: u64,      // Ordering hint
    pub steganographic_key: [u8; 16], // Extraction key
    pub master_integrity: [u8; 32],   // File-level integrity
}
```

### Transaction Encoding

- **Value**: Metadata encoded in last 4 digits
- **Input Data**: Chunk data hidden between random padding
- **Gas Limit**: Calculated based on actual data size

## 🛡️ Security Considerations

### Best Practices

1. **Strong Passphrases**: Use high-entropy passphrases
2. **Secure Seed Storage**: Keep master seeds in secure locations
3. **Network Privacy**: Use VPNs or Tor for enhanced privacy
4. **Manifest Security**: Protect manifest files as they contain retrieval information

### Limitations

- **Gas Costs**: Larger files require more transactions (use Layer 2 networks)
- **Timing Analysis**: Large files may still be detectable through timing patterns
- **Manifest Dependency**: Loss of manifest makes file retrieval impossible

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Test specific module
cargo test crypto::tests
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚖️ Legal Notice

This tool is for educational and research purposes. Users are responsible for compliance with local laws and regulations regarding cryptography and blockchain usage.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Ethers.rs](https://github.com/gakonst/ethers-rs) - Ethereum library for Rust
- [AES-GCM](https://crates.io/crates/aes-gcm) - Authenticated encryption
- [Clap](https://crates.io/crates/clap) - Command line argument parsing

---

**⚠️ Disclaimer**: This software is experimental. Use at your own risk and ensure compliance with applicable laws and regulations.
