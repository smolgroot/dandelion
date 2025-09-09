# 🌻 Dandelion Usage Examples

## Basic File Distribution Example

### 1. Create a Test File
```bash
echo "This is a secret message that will be distributed across the blockchain!" > secret.txt
```

### 2. Initialize Configuration (Optional)
```bash
# Create default configuration with Monad Testnet
./target/release/dandelion init
```

### 3. Check Wallet Funding
```bash
./target/release/dandelion check-funding \
  --seed "my-super-secret-seed-phrase-2024" \
  --count 10
```

### 4. Distribute the File
```bash
./target/release/dandelion distribute \
  --file secret.txt \
  --seed "my-super-secret-seed-phrase-2024" \
  --passphrase "encryption-password-123" \
  --output distribution-manifest.json \
  --rpc-url https://testnet-rpc.monad.xyz \
  --chain-id 10143 \
  --verbose
```

### 5. Retrieve the File
```bash
./target/release/dandelion retrieve \
  --manifest distribution-manifest.json \
  --seed "my-super-secret-seed-phrase-2024" \
  --passphrase "encryption-password-123" \
  --output retrieved-secret.txt \
  --rpc-url https://testnet-rpc.monad.xyz \
  --verbose
```

### 4. Verify the Files Match
```bash
diff secret.txt retrieved-secret.txt
echo $? # Should print 0 if files are identical
```

## Generate Test Wallets
```bash
./target/release/dandelion generate-wallets --count 5
```

## Advanced Usage

### Using Base Network
```bash
./target/release/dandelion distribute \
  --file important-document.pdf \
  --seed "base-network-seed-2024" \
  --passphrase "strong-passphrase-456" \
  --output base-manifest.json \
  --rpc-url https://mainnet.base.org \
  --chain-id 8453
```

### Custom RPC Endpoint
```bash
./target/release/dandelion distribute \
  --file data.json \
  --seed "custom-rpc-seed" \
  --passphrase "my-password" \
  --output custom-manifest.json \
  --rpc-url https://your-custom-rpc-endpoint.com
```

## Environment Variables

You can also set common parameters using environment variables:

```bash
export RPC_URL="https://polygon-rpc.com"
export CHAIN_ID="137"

./target/release/dandelion distribute --file secret.txt --seed "my-seed" --passphrase "my-pass"
```

## Important Notes

1. **Seed Security**: Keep your seed phrase extremely secure - it's needed for retrieval
2. **Passphrase Security**: The passphrase encrypts your file - without it, retrieval is impossible
3. **Manifest Protection**: The manifest file contains transaction pointers - back it up safely
4. **Gas Costs**: Larger files require more transactions - consider using Layer 2 networks
5. **Network Choice**: Use testnets for experimentation, mainnet for production

## Troubleshooting

### Common Issues

1. **RPC Connection Errors**: Verify your RPC URL is correct and accessible
2. **Gas Estimation Failures**: Ensure you have sufficient ETH for transaction fees
3. **Manifest Not Found**: Check the manifest file path and permissions
4. **Wrong Seed/Passphrase**: Verify exactly the same seed and passphrase used for distribution

### Debug Mode
Add `--verbose` flag to any command for detailed logging:
```bash
./target/release/dandelion distribute --file test.txt --seed "test" --passphrase "test" --verbose
```
