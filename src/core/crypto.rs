use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng}, AeadCore, Aes256Gcm, Nonce
};

use argon2::{
    Argon2, Params,
    password_hash::{PasswordHasher, SaltString},
};

use once_cell::sync::Lazy;
use thiserror::Error;
use zeroize::Zeroize;

use std::fmt;

// =============================================================================
// CONSTANTS
// =============================================================================

// Default Argon2 parameters for key derivation.
const ARGON2_M_COST: u32 = 131072; // 128 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 1; // 1 thread
const ARGON2_OUTPUT_LEN: usize = 32;

/// Default Argon2 parameters for key derivation.
static ARGON2_INSTANCE: Lazy<Argon2<'static>> = Lazy::new(|| {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .expect("Hardcoded Argon2 params are valid");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
});

/// Size of the nonce in bytes for AES-GCM encryption.
/// AES-GCM standard specifies a 96-bit (12-byte) nonce for optimal security and performance.
const NONCE_SIZE: usize = 12;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Comprehensive error types for cryptographic operations.
///
/// This enum encompasses all possible errors that can occur during
/// cryptographic operations in this module.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Error during Argon2 password hashing or key derivation.
    ///
    /// This typically occurs when:
    /// - Invalid parameters are provided to Argon2
    /// - Memory allocation fails during hashing
    /// - Salt format is invalid
    #[error("Key derivation error: {0}")]
    Argon2( argon2::password_hash::Error),

    /// Error during AES-GCM encryption or decryption.
    ///
    /// This typically occurs when:
    /// - Decryption fails due to wrong key
    /// - Authentication tag verification fails (data tampering)
    /// - Invalid nonce size
    #[error("Encryption/Decryption Error")]
    Aes(aes_gcm::Error),

    /// Error due to invalid data format.
    ///
    /// This occurs when:
    /// - Encrypted data is too short to contain a nonce
    /// - Salt string format is invalid
    /// - Input data format doesn't match expected structure
    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    /// Error due to invalid key length for AES-256 operations.
    #[error("Invalid key length for AES-256 GCM encryption/decryption")]
    InvalidKeyLength,

    /// Placeholder for functionality not yet implemented.
    ///
    /// Used during development to mark incomplete functions.
    #[error("The {0} functionality is not yet implemented.")]
    NotImplemented(String),
}


// =============================================================================
// SECURE KEY WRAPPER
// =============================================================================

/// Secure wrapper for cryptographic keys that automatically clears memory on drop.
///
/// This struct ensures that cryptographic key material is properly zeroized
/// when it goes out of scope, preventing sensitive data from lingering in memory.
pub struct SecureKey(Vec<u8>);

impl SecureKey {
    /// Creates a new SecureKey wrapper around the provided key bytes.
    pub fn new(key: Vec<u8>) -> Self {
        SecureKey(key)
    }

    /// Returns a reference to the key bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    
    pub fn split_into_keys(&self,mid:usize)->(SecureKey,SecureKey){
        let (left,right)= self.0.split_at(mid);
        (
            SecureKey::new(left.to_vec()),
            SecureKey::new(right.to_vec())
        )
    }
}

impl AsRef<[u8]> for SecureKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecureKey {
    /// Automatically zeroizes the key material when the SecureKey is dropped.
    ///
    /// This ensures that cryptographic keys are not left in memory after use,
    /// which is critical for security in cryptographic applications.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// =============================================================================
// KEY DERIVATION FUNCTIONS
// =============================================================================
fn derive_key_with_argon2(password: &[u8], salt: &SaltString) -> Result<SecureKey, CryptoError> {
    // Configure Argon2 to output exactly 32 bytes for AES-256
    let argon2 = &*ARGON2_INSTANCE;

    // Hash the password with the salt
    let hashed_password = argon2
        .hash_password(password, salt)
        .map_err(CryptoError::Argon2)?; // Fixed: construct the enum variant with the error

    // Extract the hash from the PasswordHash object and convert it to a vector of u8s
    let key = hashed_password
        .hash
        .ok_or_else(|| CryptoError::Argon2(argon2::password_hash::Error::Crypto))?
        .as_bytes()
        .to_vec();
    Ok(SecureKey::new(key))
}

/// Derives a new cryptographic key from a password using Argon2.
///
/// This function generates a new random salt and uses the Argon2 password hashing
/// algorithm to derive a cryptographic key suitable for AES-256 encryption.
/// Each call produces a unique salt and derived key, even with the same password.
///
/// # Arguments
///
/// * `password` - A string slice containing the user's password. Should be
///                sufficiently strong (recommended: at least 12 characters with
///                mixed case, numbers, and symbols)
///
/// # Returns
///
/// * `Ok((String, SecureKey))` - A tuple containing:
///   - `String`: Base64-encoded salt for storage (safe to store publicly)
///   - `SecureKey`: The derived key bytes (32 bytes for AES-256) wrapped in a SecureKey struct
/// * `Err(CryptoError::Argon2)` - If key derivation fails
///
/// # Security Notes
///
/// - The derived key should NEVER be stored persistently
/// - The key should be cleared from memory when no longer needed
/// - The salt is safe to store and is required for password verification
/// - Uses Argon2id variant with secure default parameters
///
/// # Performance
///
/// This function is intentionally slow (computational cost ~100ms) to resist
/// brute force attacks. The time cost is balanced for security vs usability.
pub fn derive_new_key(password: &str) -> Result<(String, SecureKey), CryptoError> {
    // Generate new random salt
    let salt = SaltString::generate(&mut OsRng);

    // Fixed: Handle the Result properly without unwrap
    let secure_key = derive_key_with_argon2(password.as_bytes(), &salt)?;

    Ok((salt.to_string(), secure_key))
}

/// Verifies a password and derives the corresponding cryptographic key.
///
/// This function takes a password and its previously generated salt,
/// then derives the same cryptographic key that would have been generated
/// during the original `derive_new_key` call. This is used to reconstruct
/// the key needed for decryption when the user provides their password.
///
/// # Arguments
///
/// * `password` - A string slice containing the user's password (same as used
///                in `derive_new_key`)
/// * `salt` - A string slice containing the Base64-encoded salt that was
///            returned by `derive_new_key` and stored
///
/// # Returns
///
/// * `Ok(SecureKey)` - A secure wrapper containing the derived key bytes
///                     (32 bytes for AES-256), identical to what `derive_new_key`
///                     would produce with the same password and salt
/// * `Err(CryptoError::Argon2)` - If key derivation fails due to:
///   - Invalid Argon2 parameters
///   - Memory allocation failure during hashing
///   - Internal Argon2 operation failure
/// * `Err(CryptoError::InvalidFormat)` - If the salt format is invalid:
///   - Salt is not valid Base64
///   - Salt has incorrect length
///   - Salt contains invalid characters
///
/// # Security Notes
///
/// - The derived key is automatically cleared from memory when `SecureKey` is dropped
/// - This function has the same computational cost as `derive_new_key` (~100ms)
/// - Password verification is implicit: if decryption succeeds with the
///   derived key, the password was correct
/// - Uses the same Argon2id parameters as `derive_new_key` for consistency
/// - The salt can be safely stored in plaintext (databases, config files)
///
/// # Typical Workflow
///
/// 1. User provides password for decryption
/// 2. Load the salt from storage (database, config file, etc.)
/// 3. Call this function to derive the key
/// 4. Attempt to decrypt the protected data
/// 5. If decryption succeeds, password was correct
/// 6. If decryption fails, password was wrong or data is corrupted
///
/// # Performance
///
/// This function is intentionally slow to resist brute force attacks.
/// It uses the same computational parameters as `derive_new_key`:
/// - Memory cost: ~128 MiB
/// - Time cost: 3 iterations
/// - Parallelism: 1 thread
/// - Expected duration: 50-150ms depending on hardware
pub fn derive_key_from_password_and_salt(
    password: &str,
    salt: &str,
) -> Result<SecureKey, CryptoError> {
    // Parse the salt from its Base64 representation
    let salt = SaltString::from_b64(salt).map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;

    let key = derive_key_with_argon2(password.as_bytes(), &salt)?;

    Ok(key)
}

pub fn generate_dek()->Result<SecureKey,CryptoError>{
    let mut dek=[0u8;64];
    OsRng.try_fill_bytes(&mut dek).unwrap();
    let master_dek:Vec<u8>=dek.to_vec();
    Ok(SecureKey::new(master_dek))
}


// =============================================================================
// ENCRYPTION/DECRYPTION FUNCTIONS
// =============================================================================

/// Encrypts data using AES-256-GCM with authenticated encryption.
///
/// This function provides both confidentiality and authenticity by using
/// AES-256 in Galois/Counter Mode (GCM). Each encryption operation uses a
/// fresh random nonce, ensuring that encrypting the same data multiple times
/// produces different ciphertexts.
///
/// # Arguments
///
/// * `data` - A byte slice containing the plaintext data to encrypt.
///            Can be any binary data (text, files, etc.)
/// * `key` - A SecureKey containing the 32-byte AES-256 encryption key.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data structured as:
///   - Bytes 0-11: Random nonce (12 bytes)
///   - Bytes 12 to len-16: Encrypted data (same length as input)
///   - Last 16 bytes: Authentication tag for integrity verification
/// * `Err(CryptoError::InvalidKeyLength)` - If key is not exactly 32 bytes
/// * `Err(CryptoError::Aes)` - If encryption fails (rare, usually indicates
///                             hardware/memory issues)
///
/// # Security Guarantees
///
/// - **Confidentiality**: Data is encrypted with AES-256
/// - **Authenticity**: GCM mode provides authentication tag
/// - **Integrity**: Any tampering will be detected during decryption
/// - **Semantic Security**: Same plaintext produces different ciphertexts due to random nonce
///
/// # Performance
///
/// AES-256-GCM is hardware-accelerated on most modern processors, providing
/// excellent performance. Typical throughput: 1-10 GB/s depending on hardware.
pub fn encrypt(data: &[u8], key: &SecureKey) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.as_ref()).map_err(|_| CryptoError::InvalidKeyLength)?;

    // Generate a random nonce with size NONCE_SIZE
    // Nonces are needed for adding randomness to the same file encrypted with the same key
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the data. This function handles both the encryption and the generation of the tag.
    let encrypted_data = cipher.encrypt(&nonce, data).map_err(CryptoError::Aes)?;

    // Prepend the nonce to the encrypted data for storage.
    // This will be required during decryption, and is not secret.
    let mut result = Vec::with_capacity(NONCE_SIZE + encrypted_data.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

/// Decrypts data that was encrypted using the `encrypt` function.
///
/// This function reverses the encryption process, extracting the nonce from
/// the encrypted data and using it along with the key to decrypt and verify
/// the data integrity. The authentication tag is automatically verified during
/// decryption.
///
/// # Arguments
///
/// * `encrypted_data` - A byte slice containing the complete encrypted data
///                      as produced by the `encrypt` function, including:
///                      nonce (12 bytes) + ciphertext + auth tag (16 bytes)
/// * `key` - A SecureKey containing the same 32-byte AES-256 key that was
///           used for encryption.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decrypted plaintext data, identical to the original
///                   input to `encrypt`
/// * `Err(CryptoError::InvalidFormat)` - If encrypted_data is too short to
///                                       contain a nonce (< 12 bytes)
/// * `Err(CryptoError::InvalidKeyLength)` - If key is not exactly 32 bytes
/// * `Err(CryptoError::Aes)` - If decryption fails, which occurs when:
///   - Wrong decryption key is used
///   - Data has been tampered with (authentication failure)
///   - Corrupted ciphertext or nonce
///
/// # Security Notes
///
/// - **Authentication**: Tampering with any part of the encrypted data
///   (nonce, ciphertext, or auth tag) will cause decryption to fail
/// - **Key Verification**: Using the wrong key will cause decryption to fail
/// - **No Partial Decryption**: Either the entire message decrypts successfully
///   or the operation fails completely
///
/// # Error Handling
///
/// - **Wrong Password**: Results in `CryptoError::Aes` - this is the primary
///   mechanism for password verification in the application
/// - **Data Corruption**: Also results in `CryptoError::Aes`
/// - **Malformed Data**: Results in `CryptoError::InvalidFormat`
///
/// # Performance
///
/// Decryption performance matches encryption performance. The authentication
/// verification adds minimal overhead compared to the decryption itself.
pub fn decrypt(encrypted_data: &[u8], key: &SecureKey) -> Result<Vec<u8>, CryptoError> {
    if encrypted_data.len() < NONCE_SIZE {
        return Err(CryptoError::InvalidFormat(
            "The encrypted data provided was too short to have a nonce.".to_string(),
        ));
    }

    // Extract the nonce from the encrypted data + tag
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(&key.as_ref()).map_err(|_| CryptoError::InvalidKeyLength)?;

    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .map_err(CryptoError::Aes)?;

    Ok(decrypted_data)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test Constants
    const TEST_PASSWORD: &str = "a-very-STRONG-and-SECRET-password-!@#$";
    const WRONG_PASSWORD: &str = "a-very-WRONG-PASSWORD-which-is-ALSO-STRONG-!@#$";
    const TEST_DATA: &[u8] = b"God, give me grace to accept with serenity the things that cannot be changed, Courage to change the things which should be changed, and the Wisdom to distinguish the one from the other.";
    const GCM_TAG_SIZE: usize = 16;

    // =============================================================================
    // KEY DERIVATION TESTS
    // =============================================================================

    /// Tests that key derivation produces unique results each time.
    ///
    /// Even with the same password, each call to derive_new_key should
    /// produce a different salt and key due to random salt generation.
    /// This prevents rainbow table attacks.
    #[test]
    fn test_derive_new_key_produces_unique_results() {
        let (salt1, key1) = derive_new_key(TEST_PASSWORD).expect("Failed to derive first key");
        let (salt2, key2) = derive_new_key(TEST_PASSWORD).expect("Failed to derive second key");

        assert_ne!(
            salt1, salt2,
            "Salt should be unique for each key derivation"
        );
        assert_ne!(
            key1.as_ref(),
            key2.as_ref(),
            "Key should be unique for each key derivation"
        );
    }

    /// Tests the derive_key_from_password_and_salt function.
    ///
    /// This test verifies that:
    /// - A key can be derived from a password and stored salt
    /// - The derived key matches the original key from derive_new_key
    /// - The SecureKey wrapper functions correctly
    /// - Encryption/decryption works with the derived key
    ///
    /// This is crucial for the password verification workflow where:
    /// 1. User registers with a password -> derive_new_key generates key + salt
    /// 2. Salt is stored, key is discarded
    /// 3. User logs in with password -> derive_key_from_password_and_salt recreates key
    /// 4. Key is used to decrypt user's data
    #[test]
    fn test_derive_key_from_password_and_salt() {
        // Step 1: Simulate user registration initial key derivation
        let (salt, original_key) =
            derive_new_key(TEST_PASSWORD).expect("Failed to derive original key");

        // Step 2: Store the salt (in practice, this would be saved to the config file of the vault)
        let stored_salt = salt;

        // Step 3: Simulate user login and key derivation
        let derived_key = derive_key_from_password_and_salt(TEST_PASSWORD, &stored_salt)
            .expect("Failed to derive key from password and salt");

        // Step 4: Ensure the derived key matches the original key
        assert_eq!(
            original_key.as_ref(),
            derived_key.as_ref(),
            "Derived key does not match original key"
        );

        // Step 5: Test that the derived key works for encryption/decryption
        let encrypted_data =
            encrypt(TEST_DATA, &derived_key).expect("Failed to encrypt with derived key");

        let decrypted_data =
            decrypt(&encrypted_data, &derived_key).expect("Failed to decrypt with derived key");

        assert_eq!(
            decrypted_data, TEST_DATA,
            "Decrypted data should match original data"
        );

        // Step 6: Test that encryption with original key can be decrypted with derived key
        let encrypted_with_original =
            encrypt(TEST_DATA, &original_key).expect("Failed to encrypt with original key");

        let decrypted_with_derived = decrypt(&encrypted_with_original, &derived_key)
            .expect("Failed to decrypt original encryption with derived key");

        assert_eq!(
            decrypted_with_derived, TEST_DATA,
            "Data encrypted with original key should decrypt with derived key"
        );
    }

    /// Tests that derive_key_from_password_and_salt fails with invalid salt.
    #[test]
    fn test_derive_key_with_invalid_salt_fails() {
        // A string that is not valid Base64
        let invalid_salt = "this-is-not-base64!";

        let result = derive_key_from_password_and_salt(TEST_PASSWORD, invalid_salt);

        assert!(
            matches!(result, Err(CryptoError::InvalidFormat(_))),
            "Should fail with InvalidFormat for a non-Base64 salt"
        );
    }

    // =============================================================================
    // ENCRYPTION/DECRYPTION SUCCESS TESTS
    // =============================================================================

    /// Tests the complete encryption-decryption cycle with correct key.
    ///
    /// Verifies that:
    /// - Key derivation succeeds
    /// - Encryption produces different output than input
    /// - Encrypted data has expected size (original + nonce + tag)
    /// - Decryption with correct key recovers original data
    #[test]
    fn test_full_encryption_decryption_cycle() {
        let (_salt, key) = derive_new_key(TEST_PASSWORD).expect("Failed to derive key");

        let encrypted_data = encrypt(TEST_DATA, &key).expect("Failed to encrypt data");

        assert_ne!(encrypted_data, TEST_DATA);
        assert_eq!(
            encrypted_data.len(),
            TEST_DATA.len() + GCM_TAG_SIZE + NONCE_SIZE
        );

        let decrypted_data = decrypt(&encrypted_data, &key).expect("Failed to decrypt data");

        assert_eq!(decrypted_data, TEST_DATA);
    }

    /// Tests that encryption is non-deterministic.
    ///
    /// Encrypting the same data with the same key should produce different
    /// results due to random nonce generation. This prevents pattern analysis
    /// and ensures semantic security.
    #[test]
    fn test_same_data_encrypted_with_same_key_produces_different_results() {
        let (_salt, key) = derive_new_key(TEST_PASSWORD).expect("Failed to derive key");

        let encrypted_data1 = encrypt(TEST_DATA, &key).expect("Failed to encrypt data first time");
        let encrypted_data2 = encrypt(TEST_DATA, &key).expect("Failed to encrypt data second time");

        assert_ne!(
            encrypted_data1, encrypted_data2,
            "Same data encrypted with same key should produce different results due to nonce"
        );
    }

    /// Tests encryption and decryption of empty data.
    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let (_salt, key) = derive_new_key(TEST_PASSWORD).unwrap();
        let empty_data: &[u8] = b"";

        let encrypted_data =
            encrypt(empty_data, &key).expect("Encryption of empty data should succeed");

        // The result should only contain the nonce and the authentication tag
        assert_eq!(encrypted_data.len(), NONCE_SIZE + GCM_TAG_SIZE);

        let decrypted_data =
            decrypt(&encrypted_data, &key).expect("Decryption of empty data should succeed");

        assert_eq!(decrypted_data.len(), 0, "Decrypted data should be empty");
        assert_eq!(decrypted_data, empty_data);
    }

    // =============================================================================
    // AUTHENTICATION AND SECURITY TESTS
    // =============================================================================

    /// Tests that decryption fails when using wrong key.
    ///
    /// This is crucial for password verification: if someone provides
    /// the wrong password, the derived key will be different and
    /// decryption should fail with an AES error.
    #[test]
    fn test_decryption_with_wrong_key_fails() {
        let (_salt, correct_key) = derive_new_key(TEST_PASSWORD).expect("Failed to derive key");
        let (_wrong_salt, wrong_key) =
            derive_new_key(WRONG_PASSWORD).expect("Failed to derive wrong key");

        let encrypted_data = encrypt(TEST_DATA, &correct_key).expect("Failed to encrypt data");

        let decrypted_data =
            decrypt(&encrypted_data, &wrong_key).expect_err("Decryption with wrong key succeeded");

        assert!(matches!(decrypted_data, CryptoError::Aes(_)));
    }

    /// Tests that decryption fails when data has been tampered with.
    ///
    /// This verifies the authentication property of AES-GCM: any
    /// modification to the encrypted data should be detected and
    /// cause decryption to fail.
    #[test]
    fn test_decryption_with_tampered_data_fails() {
        let (_salt, key) = derive_new_key(TEST_PASSWORD).expect("Failed to derive key");

        let mut encrypted_data = encrypt(TEST_DATA, &key).expect("Failed to encrypt data");

        // Tamper with the data by flipping bits in the ciphertext
        let tamper_index = encrypted_data.len() - 5;
        encrypted_data[tamper_index] ^= 0xFF; // Flip bits

        let decrypted_data =
            decrypt(&encrypted_data, &key).expect_err("Decryption with tampered data succeeded");

        assert!(matches!(decrypted_data, CryptoError::Aes(_)));
    }

    /// Tests that decryption fails when the nonce has been tampered with.
    #[test]
    fn test_decryption_with_tampered_nonce_fails() {
        let (_salt, key) = derive_new_key(TEST_PASSWORD).unwrap();

        let mut encrypted_data = encrypt(TEST_DATA, &key).expect("Failed to encrypt data");

        // Tamper with the nonce (the first 12 bytes)
        encrypted_data[0] ^= 0xFF; // Flip the first byte of the nonce

        let result = decrypt(&encrypted_data, &key);

        assert!(
            matches!(result, Err(CryptoError::Aes(_))),
            "Decryption should fail with an AES error if the nonce is tampered"
        );
    }

    // =============================================================================
    // ERROR HANDLING TESTS
    // =============================================================================

    /// Tests that decryption fails when data is too short to contain a nonce.
    #[test]
    fn test_decrypt_with_data_too_short_fails() {
        let (_salt, key) = derive_new_key(TEST_PASSWORD).unwrap();

        // Create data that is shorter than the 12-byte nonce
        let short_data = vec![1, 2, 3, 4, 5];

        let result = decrypt(&short_data, &key);

        assert!(
            matches!(result, Err(CryptoError::InvalidFormat(_))),
            "Should fail with InvalidFormat for data shorter than a nonce"
        );

        // Check the specific error message
        if let Err(CryptoError::InvalidFormat(msg)) = result {
            assert!(msg.contains("too short to have a nonce"));
        }
    }
}
