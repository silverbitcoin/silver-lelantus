//! Commitment scheme for Lelantus

use serde::{Deserialize, Serialize};
use sha2::{Sha512, Digest};
use hex;
use serde_json;
use rand::Rng;
use crate::errors::{LelantusError, Result};
use crate::parameters::LelantusParameters;

/// Pedersen commitment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// Commitment value (hash)
    pub value: Vec<u8>,
    
    /// Randomness used in commitment
    pub randomness: Vec<u8>,
}

impl Commitment {
    /// Convert commitment to accumulator element
    pub fn to_element(&self) -> Result<AccumulatorElement> {
        Ok(AccumulatorElement {
            value: self.value.clone(),
        })
    }
    
    /// Serialize commitment to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| LelantusError::SerializationError(e.to_string()))
    }
    
    /// Deserialize commitment from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| LelantusError::SerializationError(e.to_string()))
    }
}

/// Accumulator element
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccumulatorElement {
    /// Element value
    pub value: Vec<u8>,
}

/// Commitment scheme
#[derive(Debug)]
pub struct CommitmentScheme {
    parameters: LelantusParameters,
    generator: Vec<u8>,
}

impl CommitmentScheme {
    /// Create a new commitment scheme
    pub fn new(parameters: &LelantusParameters) -> Result<Self> {
        parameters.validate()?;
        
        Ok(Self {
            parameters: parameters.clone(),
            generator: parameters.generator.clone(),
        })
    }
    
    /// Create a commitment to a value
    pub fn commit(&self, value: u64) -> Result<Commitment> {
        if value > self.parameters.max_coin_value {
            return Err(LelantusError::InvalidCommitment);
        }
        
        if value < self.parameters.min_coin_value {
            return Err(LelantusError::InvalidCommitment);
        }
        
        // Generate random randomness
        let mut rng = rand::thread_rng();
        let randomness: Vec<u8> = (0..self.parameters.randomness_bits / 8)
            .map(|_| rng.gen())
            .collect();
        
        // Compute commitment: H(generator || value || randomness)
        let mut hasher = Sha512::new();
        hasher.update(&self.generator);
        hasher.update(value.to_le_bytes());
        hasher.update(&randomness);
        
        let commitment_value = hex::encode(hasher.finalize()).into_bytes();
        
        Ok(Commitment {
            value: commitment_value,
            randomness,
        })
    }
    
    /// Create a commitment with specific randomness (for testing/verification)
    pub fn commit_with_randomness(
        &self,
        value: u64,
        randomness: Vec<u8>,
    ) -> Result<Commitment> {
        if value > self.parameters.max_coin_value {
            return Err(LelantusError::InvalidCommitment);
        }
        
        if randomness.len() != self.parameters.randomness_bits / 8 {
            return Err(LelantusError::InvalidCommitment);
        }
        
        // Compute commitment: H(generator || value || randomness)
        let mut hasher = Sha512::new();
        hasher.update(&self.generator);
        hasher.update(value.to_le_bytes());
        hasher.update(&randomness);
        
        let commitment_value = hex::encode(hasher.finalize()).into_bytes();
        
        Ok(Commitment {
            value: commitment_value,
            randomness,
        })
    }
    
    /// Verify a commitment (open it)
    pub fn verify(
        &self,
        commitment: &Commitment,
        value: u64,
    ) -> Result<bool> {
        let recomputed = self.commit_with_randomness(value, commitment.randomness.clone())?;
        Ok(recomputed.value == commitment.value)
    }
    
    /// Get the generator
    pub fn generator(&self) -> &[u8] {
        &self.generator
    }
    
    /// Get parameters
    pub fn parameters(&self) -> &LelantusParameters {
        &self.parameters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[test]
    fn test_commitment_creation() -> Result<()> {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params)?;
        let commitment = scheme.commit(1000)?;
        assert!(!commitment.value.is_empty());
        assert!(!commitment.randomness.is_empty());
        Ok(())
    }
    
    #[test]
    fn test_commitment_verification() -> Result<()> {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params)?;
        let commitment = scheme.commit(1000)?;
        
        let valid = scheme.verify(&commitment, 1000)?;
        assert!(valid);
        
        let invalid = scheme.verify(&commitment, 2000)?;
        assert!(!invalid);
        Ok(())
    }
    
    #[test]
    fn test_commitment_with_randomness() -> Result<()> {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params)?;
        let randomness = vec![42; params.randomness_bits / 8];
        let commitment = scheme.commit_with_randomness(1000, randomness)?;
        
        let valid = scheme.verify(&commitment, 1000)?;
        assert!(valid);
        Ok(())
    }
    
    #[test]
    fn test_invalid_commitment_value() -> Result<()> {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params)?;
        let result = scheme.commit(params.max_coin_value + 1);
        assert!(result.is_err());
        Ok(())
    }
}
