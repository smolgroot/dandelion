use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, AeadCore};
use aes_gcm::aead::Aead;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rand::{SeedableRng, Rng};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    pub chunk_id: u16,
    pub total_chunks: u16,
    pub data: Vec<u8>,
    pub checksum: [u8; 4],
    pub integrity_proof: [u8; 8],
    pub sequence_hint: u64,
    pub steganographic_key: [u8; 16],
    pub master_integrity: [u8; 32],
}

#[derive(Debug)]
pub struct CryptoEngine {
    master_seed: [u8; 32],
}

impl CryptoEngine {
    pub fn new(master_seed: [u8; 32]) -> Self {
        Self { master_seed }
    }
    
    pub fn encrypt_and_chunk(&self, file_data: &[u8], passphrase: &str) -> Result<(Vec<EncryptedChunk>, [u8; 32])> {
        // Derive keys
        let (encryption_key, integrity_key) = self.derive_keys(passphrase);
        
        // Calculate master integrity
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&integrity_key)
            .map_err(|e| anyhow!("HMAC key error: {}", e))?;
        mac.update(file_data);
        let master_integrity: [u8; 32] = mac.finalize().into_bytes().into();
        
        // Encrypt file
        let cipher = Aes256Gcm::new(&encryption_key);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
        let encrypted_data = cipher.encrypt(&nonce, file_data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        
        // Variable-size chunking for obfuscation
        let chunks = self.create_variable_chunks(&encrypted_data, &integrity_key, passphrase, master_integrity)?;
        
        Ok((chunks, master_integrity))
    }
    
    pub fn decrypt_file(&self, encrypted_data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
        let (encryption_key, _) = self.derive_keys(passphrase);
        let cipher = Aes256Gcm::new(&encryption_key);
        
        // For simplicity, we'll extract nonce from the first 12 bytes of encrypted data
        if encrypted_data.len() < 12 {
            return Err(anyhow!("Encrypted data too short"));
        }
        
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];
        
        let decrypted = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        
        Ok(decrypted)
    }
    
    pub fn compute_file_integrity(&self, file_data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
        let (_, integrity_key) = self.derive_keys(passphrase);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&integrity_key)
            .map_err(|e| anyhow!("HMAC key error: {}", e))?;
        mac.update(file_data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
    
    fn derive_keys(&self, passphrase: &str) -> (Key<Aes256Gcm>, [u8; 32]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_seed);
        hasher.update(passphrase.as_bytes());
        hasher.update(b"ENCRYPTION");
        let encryption_hash = hasher.finalize();
        let encryption_key = Key::<Aes256Gcm>::from_slice(&encryption_hash);
        
        let mut hasher = Sha256::new();
        hasher.update(&self.master_seed);
        hasher.update(passphrase.as_bytes());
        hasher.update(b"INTEGRITY");
        let integrity_key: [u8; 32] = hasher.finalize().into();
        
        (*encryption_key, integrity_key)
    }
    
    // Remove the derive_nonce function since we'll use random nonces
    
    fn create_variable_chunks(&self, 
        data: &[u8], 
        integrity_key: &[u8], 
        passphrase: &str,
        master_integrity: [u8; 32]
    ) -> Result<Vec<EncryptedChunk>> {
        let mut chunks = Vec::new();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(self.master_seed);
        let mut offset = 0;
        let total_size = data.len();
        let chunk_size_range = (16, 48);
        
        while offset < total_size {
            // Variable chunk size for obfuscation
            let chunk_size = rng.gen_range(chunk_size_range.0..=chunk_size_range.1)
                .min(total_size - offset);
            
            let chunk_data = &data[offset..offset + chunk_size];
            
            // Create integrity proof for this chunk
            let mut mac = <HmacSha256 as KeyInit>::new_from_slice(integrity_key)
                .map_err(|e| anyhow!("HMAC key error: {}", e))?;
            mac.update(&(chunks.len() as u32).to_le_bytes());
            mac.update(chunk_data);
            let integrity_proof = mac.finalize().into_bytes();
            
            // Generate sequence hint for ordering
            let sequence_hint = self.generate_sequence_hint(chunks.len(), passphrase);
            
            // Generate steganographic key for this chunk
            let steganographic_key = self.derive_steganographic_key(chunks.len(), passphrase);
            
            let chunk = EncryptedChunk {
                chunk_id: chunks.len() as u16,
                total_chunks: 0, // Will be filled later
                data: chunk_data.to_vec(),
                checksum: Sha256::digest(chunk_data)[..4].try_into().unwrap(),
                integrity_proof: integrity_proof[..8].try_into().unwrap(),
                sequence_hint,
                steganographic_key,
                master_integrity,
            };
            
            chunks.push(chunk);
            offset += chunk_size;
        }
        
        // Update total_chunks
        let total = chunks.len() as u16;
        for chunk in &mut chunks {
            chunk.total_chunks = total;
        }
        
        Ok(chunks)
    }
    
    fn generate_sequence_hint(&self, index: usize, passphrase: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_seed);
        hasher.update(passphrase.as_bytes());
        hasher.update(&index.to_le_bytes());
        hasher.update(b"SEQUENCE");
        let hash = hasher.finalize();
        u64::from_le_bytes(hash[..8].try_into().unwrap())
    }
    
    fn derive_steganographic_key(&self, chunk_idx: usize, passphrase: &str) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_seed);
        hasher.update(passphrase.as_bytes());
        hasher.update(&(chunk_idx as u32).to_le_bytes());
        hasher.update(b"STEG_KEY");
        let hash = hasher.finalize();
        hash[..16].try_into().unwrap()
    }
}
