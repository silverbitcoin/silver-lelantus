//! Commitment scheme for Lelantus

use serde::{Deserialize, Serialize};
use blake3::Hasher;
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
        bincode::serialize(self)
            .map_err(|e| LelantusError::SerializationError(e.to_string()))
    }
    
    /// Deserialize commitment from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
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
        let mut hasher = Hasher::new();
        hasher.update(&self.generator);
        hasher.update(&value.to_le_bytes());
        hasher.update(&randomness);
        
        let commitment_value = hasher.finalize().as_bytes().to_vec();
        
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
        let mut hasher = Hasher::new();
        hasher.update(&self.generator);
        hasher.update(&value.to_le_bytes());
        hasher.update(&randomness);
        
        let commitment_value = hasher.finalize().as_bytes().to_vec();
        
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
    fn test_commitment_creation() {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params).unwrap();
        
        let commitment = scheme.commit(1000).unwrap();
        assert!(!commitment.value.is_empty());
        assert!(!commitment.randomness.is_empty());
    }
    
    #[test]
    fn test_commitment_verification() {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params).unwrap();
        
        let commitment = scheme.commit(1000).unwrap();
        assert!(scheme.verify(&commitment, 1000).unwrap());
        assert!(!scheme.verify(&commitment, 2000).unwrap());
    }
    
    #[test]
    fn test_commitment_with_randomness() {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params).unwrap();
        
        let randomness = vec![42; params.randomness_bits / 8];
        let commitment = scheme.commit_with_randomness(1000, randomness.clone()).unwrap();
        
        assert!(scheme.verify(&commitment, 1000).unwrap());
    }
    
    #[test]
    fn test_invalid_commitment_value() {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params).unwrap();
        
        let result = scheme.commit(params.max_coin_value + 1);
        assert!(result.is_err());
    }
}
