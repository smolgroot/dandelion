use ethers::prelude::*;
use rand::{RngCore, SeedableRng, Rng};
use sha2::Digest;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use tracing::{debug, info};

use crate::crypto::EncryptedChunk;
use crate::distributor::ChunkMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegTransaction {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: U256,
}

#[derive(Debug)]
pub struct SteganographyEngine {
    master_seed: [u8; 32],
}

impl SteganographyEngine {
    pub fn new(master_seed: [u8; 32]) -> Self {
        Self { master_seed }
    }
    
    pub fn create_steganographic_transaction(&self,
        sender: &LocalWallet,
        receiver: &LocalWallet,
        chunk: &EncryptedChunk,
        chunk_idx: usize,
        passphrase: &str
    ) -> Result<StegTransaction> {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(self.master_seed);
        
        // Steganographic value encoding
        let base_value = rng.gen_range(100_000..1_000_000); // Random base value in wei
        let steg_value = self.encode_steganographic_value(base_value, chunk)?;
        
        // Create steganographic transaction data
        let steg_data = self.encode_steganographic_data(&chunk.data, chunk, chunk_idx)?;
        
        let transaction = StegTransaction {
            to: receiver.address(),
            value: U256::from(steg_value),
            data: steg_data,
            gas_limit: U256::from(21000 + (chunk.data.len() * 16) as u64),
        };
        
        Ok(transaction)
    }
    
    pub async fn decode_steganographic_data(&self, 
        tx_hash: &str,
        steganographic_key: &str, 
        chunk_metadata: &ChunkMetadata,
        total_chunks: u16,
        provider: &Provider<Http>
    ) -> Result<Vec<u8>> {
        debug!("Decoding steganographic data from tx: {}", tx_hash);
        debug!("Using steganographic key: {}", steganographic_key);
        
        // Get the actual transaction from the blockchain
        let tx_hash = H256::from_slice(&hex::decode(&tx_hash[2..])?);
        let tx = provider.get_transaction(tx_hash)
            .await?
            .ok_or_else(|| anyhow!("Transaction not found"))?;
        
        // Extract the actual chunk data from transaction input
        let input_data = tx.input.to_vec();
        debug!("Transaction input length: {} bytes", input_data.len());
        debug!("Transaction input (first 100 bytes): {}", hex::encode(&input_data[..std::cmp::min(100, input_data.len())]));
        
        // Skip function selector (first 4 bytes) and extract embedded data
        if input_data.len() < 4 {
            return Err(anyhow!("Transaction input too short"));
        }
        
        // For now, let's extract the chunk data from the transaction input
        // The actual chunk should be embedded in the transaction data
        let embedded_data = &input_data[4..]; // Skip function selector
        
        // The steganographic key should help us locate the actual chunk data
        let key_bytes = hex::decode(steganographic_key)?;
        if key_bytes.len() != 16 {
            return Err(anyhow!("Invalid steganographic key length"));
        }
        let key_array: [u8; 16] = key_bytes.try_into().unwrap();
        
        // Find and extract the actual chunk data
        let result = self.extract_chunk_from_transaction_data(embedded_data, &key_array, chunk_metadata, total_chunks)?;
        debug!("Extracted chunk length: {} bytes", result.len());
        debug!("Extracted chunk (first 50 bytes): {}", hex::encode(&result[..std::cmp::min(50, result.len())]));
        
        Ok(result)
    }
    
    // Encode chunk metadata into transaction value's least significant digits
    fn encode_steganographic_value(&self, base_value: u64, chunk: &EncryptedChunk) -> Result<u64> {
        // Use last 4 digits for steganography (allows values up to 9999)
        let steg_data = ((chunk.chunk_id as u64) << 16) | (chunk.total_chunks as u64);
        let encoded_value = (base_value / 10000) * 10000 + (steg_data % 10000);
        Ok(encoded_value)
    }
    
    pub fn encode_chunk_data(&self, chunk_data: &[u8], chunk: &EncryptedChunk) -> Result<Bytes> {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(self.master_seed);
        
        // Create realistic-looking contract call data
        let fake_function_selector = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256) selector
        let mut encoded_data = fake_function_selector.to_vec();
        
        // Add random padding to look like function arguments
        let padding_size = rng.gen_range(32..64);
        let mut padding = vec![0u8; padding_size];
        rng.fill_bytes(&mut padding);
        encoded_data.extend_from_slice(&padding);
        
        // Embed chunk metadata
        encoded_data.extend_from_slice(&chunk.chunk_id.to_le_bytes());
        encoded_data.extend_from_slice(&chunk.total_chunks.to_le_bytes());
        encoded_data.extend_from_slice(&chunk.sequence_hint.to_le_bytes());
        
        // Embed actual chunk data
        encoded_data.extend_from_slice(chunk_data);
        
        // Add integrity markers
        encoded_data.extend_from_slice(&chunk.checksum);
        encoded_data.extend_from_slice(&chunk.integrity_proof);
        
        // Add steganographic key
        encoded_data.extend_from_slice(&chunk.steganographic_key);
        
        // More random padding to obfuscate actual data size
        let trailing_padding = rng.gen_range(16..32);
        let mut trailing = vec![0u8; trailing_padding];
        rng.fill_bytes(&mut trailing);
        encoded_data.extend_from_slice(&trailing);
        
        Ok(Bytes::from(encoded_data))
    }

    pub fn encode_steganographic_data(&self, chunk_data: &[u8], chunk: &EncryptedChunk, _chunk_idx: usize) -> Result<Bytes> {
        self.encode_chunk_data(chunk_data, chunk)
    }
    
    pub fn decode_steganographic_value(&self, value: U256) -> Result<(u16, u16)> {
        let value_u64 = value.as_u64();
        let steg_data = value_u64 % 10000;
        let chunk_id = (steg_data >> 16) as u16;
        let total_chunks = (steg_data & 0xFFFF) as u16;
        Ok((chunk_id, total_chunks))
    }
    
    pub fn extract_chunk_from_transaction_data(&self, 
        input_data: &[u8], 
        steganographic_key: &[u8; 16],
        chunk_metadata: &ChunkMetadata,
        total_chunks: u16
    ) -> Result<Vec<u8>> {
        debug!("Transaction input length: {} bytes", input_data.len());
        debug!("Transaction input hex: {}", hex::encode(input_data));
        debug!("Transaction input (first 100 bytes): {}", 
            hex::encode(&input_data[..std::cmp::min(100, input_data.len())]));
        debug!("Steganographic key to find: {}", hex::encode(steganographic_key));
        
        // Find the steganographic key position
        let steg_key_pos = input_data.windows(16)
            .position(|window| window == steganographic_key)
            .ok_or_else(|| anyhow!("Steganographic key not found in transaction data"))?;
        
        debug!("Found steganographic key at position: {}", steg_key_pos);
        
        // Look for chunk metadata pattern preceding the steganographic key
        // The structure is: [padding] + [metadata 12] + [chunk data] + [checksum 4] + [integrity_proof 8] + [steg_key 16] + [trailing]
        // Metadata format: chunk_id (u16, 2 bytes) + total_chunks (u16, 2 bytes) + sequence_hint (u64, 8 bytes) = 12 bytes total
        
        let metadata_search_start = if steg_key_pos >= 100 { steg_key_pos - 100 } else { 4 };
        let metadata_search_end = if steg_key_pos >= 24 { steg_key_pos - 24 } else { 4 };
        
        let mut metadata_pos = None;
        
        // Search for metadata pattern (chunk_id as u16, total_chunks as u16)
        for pos in metadata_search_start..metadata_search_end {
            if pos + 12 <= input_data.len() {
                let chunk_id = u16::from_le_bytes([
                    input_data[pos], input_data[pos + 1]
                ]);
                let total_chunks_read = u16::from_le_bytes([
                    input_data[pos + 2], input_data[pos + 3]
                ]);
                
                debug!("Checking position {}: chunk_id={}, total_chunks={}", pos, chunk_id, total_chunks_read);
                
                // Reasonable bounds check for chunk metadata
                if chunk_id < 1000 && total_chunks_read > 0 && total_chunks_read < 1000 {
                    // Additional validation: check if the expected sequence_hint matches
                    let sequence_hint = u64::from_le_bytes([
                        input_data[pos + 4], input_data[pos + 5], input_data[pos + 6], input_data[pos + 7],
                        input_data[pos + 8], input_data[pos + 9], input_data[pos + 10], input_data[pos + 11]
                    ]);
                    
                    debug!("Position {}: chunk_id={}, total_chunks={}, sequence_hint={}", 
                        pos, chunk_id, total_chunks_read, sequence_hint);
                    
                    // Match against expected metadata
                    if chunk_id == chunk_metadata.chunk_id as u16 && 
                       total_chunks_read == total_chunks && // Compare against actual total_chunks
                       sequence_hint == chunk_metadata.sequence_hint {
                        metadata_pos = Some(pos);
                        debug!("Found matching chunk metadata at position: {}", pos);
                        break;
                    }
                }
            }
        }
        
        let metadata_position = metadata_pos.ok_or_else(|| 
            anyhow!("Could not locate chunk metadata in transaction data"))?;
        
        // Extract chunk data between metadata and steganographic components
        // Structure: [metadata 12] + [chunk data] + [checksum 4] + [integrity_proof 8] + [steg_key 16]
        let chunk_data_start = metadata_position + 12; // After 12 bytes of metadata  
        let chunk_data_end = steg_key_pos - 12; // Before checksum(4) + integrity_proof(8) = 12 bytes total
        
        if chunk_data_start >= chunk_data_end {
            return Err(anyhow!("Invalid chunk data boundaries: start={}, end={}", 
                chunk_data_start, chunk_data_end));
        }
        
        let chunk_data = input_data[chunk_data_start..chunk_data_end].to_vec();
        
        debug!("Extracted chunk data: {} bytes (positions {}-{})", 
            chunk_data.len(), chunk_data_start, chunk_data_end - 1);
        debug!("Extracted chunk length: {} bytes", chunk_data.len());
        debug!("Extracted chunk (first 50 bytes): {}", 
            hex::encode(&chunk_data[..std::cmp::min(50, chunk_data.len())]));
        
        // EXPERIMENTAL: Check if we need to include nonce from padding
        // For a 5-byte file, we expect 33 total bytes (12 nonce + 21 ciphertext+auth)
        // We're getting 21 or 22 bytes, so we might need to find the 12-byte nonce separately
        // NOTE: Skip this for multi-chunk files since nonce is already in first chunk
        // DISABLED: This logic conflicts with multi-chunk scenarios
        if false && (chunk_data.len() == 21 || chunk_data.len() == 22) {
            debug!("Chunk data is {} bytes - might be missing 12-byte nonce", chunk_data.len());
            debug!("Searching for nonce in padding section...");
            
            // Try to find nonce in the padding before metadata
            let padding_end = metadata_position;
            if padding_end >= 12 {
                // Try the last 12 bytes of padding as potential nonce
                let potential_nonce = &input_data[padding_end-12..padding_end];
                debug!("Potential nonce from padding: {}", hex::encode(potential_nonce));
                
                // If we have 22 bytes, try removing the first byte to get 21
                let adjusted_chunk_data = if chunk_data.len() == 22 {
                    debug!("Removing extra byte from start of chunk data");
                    &chunk_data[1..]
                } else {
                    &chunk_data[..]
                };
                
                // Reconstruct full encrypted data: nonce + chunk_data
                let mut full_encrypted = potential_nonce.to_vec();
                full_encrypted.extend_from_slice(adjusted_chunk_data);
                
                debug!("Reconstructed encrypted data: {} bytes", full_encrypted.len());
                debug!("Full encrypted: {}", hex::encode(&full_encrypted[..std::cmp::min(50, full_encrypted.len())]));
                
                return Ok(full_encrypted);
            }
        }
        
        Ok(chunk_data)
    }
}
