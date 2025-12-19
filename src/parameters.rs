//! Lelantus protocol parameters

use serde::{Deserialize, Serialize};
use crate::errors::{LelantusError, Result};

/// Privacy level for Lelantus transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Standard privacy (default)
    Standard,
    /// Enhanced privacy with larger anonymity set
    Enhanced,
    /// Maximum privacy with largest anonymity set
    Maximum,
}

impl PrivacyLevel {
    /// Get anonymity set size for this privacy level
    pub fn anonymity_set_size(&self) -> usize {
        match self {
            PrivacyLevel::Standard => 64,
            PrivacyLevel::Enhanced => 256,
            PrivacyLevel::Maximum => 1024,
        }
    }
    
    /// Get proof size in bytes for this privacy level
    pub fn proof_size(&self) -> usize {
        match self {
            PrivacyLevel::Standard => 2048,
            PrivacyLevel::Enhanced => 4096,
            PrivacyLevel::Maximum => 8192,
        }
    }
}

/// Lelantus protocol parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LelantusParameters {
    /// Privacy level
    pub privacy_level: PrivacyLevel,
    
    /// Accumulator modulus bit length
    pub accumulator_modulus_bits: usize,
    
    /// Commitment randomness bit length
    pub randomness_bits: usize,
    
    /// Range proof bit length
    pub range_proof_bits: usize,
    
    /// Maximum coin value (in satoshis)
    pub max_coin_value: u64,
    
    /// Minimum coin value (in satoshis)
    pub min_coin_value: u64,
    
    /// Accumulator base
    pub accumulator_base: Vec<u8>,
    
    /// Generator point for commitments
    pub generator: Vec<u8>,
    
    /// Hash function identifier
    pub hash_function: String,
    
    /// Proof system identifier
    pub proof_system: String,
}

impl Default for LelantusParameters {
    fn default() -> Self {
        Self {
            privacy_level: PrivacyLevel::Standard,
            accumulator_modulus_bits: 2048,
            randomness_bits: 256,
            range_proof_bits: 64,
            max_coin_value: 21_000_000 * 100_000_000, // 21M BTC in satoshis
            min_coin_value: 1,
            accumulator_base: vec![2; 256],
            generator: vec![3; 256],
            hash_function: "blake3".to_string(),
            proof_system: "bulletproofs".to_string(),
        }
    }
}

impl LelantusParameters {
    /// Create parameters with specified privacy level
    pub fn with_privacy_level(privacy_level: PrivacyLevel) -> Self {
        Self {
            privacy_level,
            ..Default::default()
        }
    }
    
    /// Validate parameters
    pub fn validate(&self) -> Result<()> {
        if self.accumulator_modulus_bits < 1024 {
            return Err(LelantusError::InvalidParameter);
        }
        
        if self.randomness_bits < 128 {
            return Err(LelantusError::InvalidParameter);
        }
        
        if self.range_proof_bits < 32 {
            return Err(LelantusError::InvalidParameter);
        }
        
        if self.max_coin_value <= self.min_coin_value {
            return Err(LelantusError::InvalidParameter);
        }
        
        if self.accumulator_base.is_empty() || self.generator.is_empty() {
            return Err(LelantusError::InvalidParameter);
        }
        
        Ok(())
    }
    
    /// Get anonymity set size
    pub fn anonymity_set_size(&self) -> usize {
        self.privacy_level.anonymity_set_size()
    }
    
    /// Get proof size
    pub fn proof_size(&self) -> usize {
        self.privacy_level.proof_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_parameters() {
        let params = LelantusParameters::default();
        assert_eq!(params.privacy_level, PrivacyLevel::Standard);
        assert!(params.validate().is_ok());
    }
    
    #[test]
    fn test_privacy_levels() {
        assert_eq!(PrivacyLevel::Standard.anonymity_set_size(), 64);
        assert_eq!(PrivacyLevel::Enhanced.anonymity_set_size(), 256);
        assert_eq!(PrivacyLevel::Maximum.anonymity_set_size(), 1024);
    }
    
    #[test]
    fn test_parameter_validation() {
        let mut params = LelantusParameters::default();
        assert!(params.validate().is_ok());
        
        params.accumulator_modulus_bits = 512;
        assert!(params.validate().is_err());
    }
}
