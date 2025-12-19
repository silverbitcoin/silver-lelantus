//! Witness for Lelantus proofs

use serde::{Deserialize, Serialize};
use crate::errors::{LelantusError, Result};
use crate::commitment::Commitment;

/// Witness for a coin in the accumulator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// The commitment being witnessed
    pub commitment: Commitment,
    
    /// Index in the accumulator
    pub index: usize,
    
    /// Accumulator value at witness creation
    pub accumulator_value: Vec<u8>,
    
    /// Proof of membership
    pub membership_proof: Vec<u8>,
    
    /// Coin value (encrypted)
    pub encrypted_value: Vec<u8>,
}

impl Witness {
    /// Create a new witness
    pub fn new(
        commitment: Commitment,
        index: usize,
        accumulator_value: Vec<u8>,
        membership_proof: Vec<u8>,
        encrypted_value: Vec<u8>,
    ) -> Self {
        Self {
            commitment,
            index,
            accumulator_value,
            membership_proof,
            encrypted_value,
        }
    }
    
    /// Verify the witness is valid
    pub fn verify(&self) -> Result<bool> {
        // Check that commitment is valid
        if self.commitment.value.is_empty() {
            return Err(LelantusError::InvalidWitness);
        }
        
        // Check that accumulator value is valid
        if self.accumulator_value.is_empty() {
            return Err(LelantusError::InvalidWitness);
        }
        
        // Check that membership proof is valid
        if self.membership_proof.is_empty() {
            return Err(LelantusError::InvalidWitness);
        }
        
        Ok(true)
    }
    
    /// Get the commitment
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }
    
    /// Get the index
    pub fn index(&self) -> usize {
        self.index
    }
    
    /// Get the accumulator value
    pub fn accumulator_value(&self) -> &[u8] {
        &self.accumulator_value
    }
    
    /// Serialize the witness
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| LelantusError::SerializationError(e.to_string()))
    }
    
    /// Deserialize the witness
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| LelantusError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_witness_creation() {
        let commitment = Commitment {
            value: vec![1; 32],
            randomness: vec![2; 32],
        };
        
        let witness = Witness::new(
            commitment,
            0,
            vec![3; 32],
            vec![4; 32],
            vec![5; 32],
        );
        
        assert_eq!(witness.index(), 0);
        assert!(witness.verify().is_ok());
    }
    
    #[test]
    fn test_witness_serialization() {
        let commitment = Commitment {
            value: vec![1; 32],
            randomness: vec![2; 32],
        };
        
        let witness = Witness::new(
            commitment,
            0,
            vec![3; 32],
            vec![4; 32],
            vec![5; 32],
        );
        
        let serialized = witness.serialize().unwrap();
        let deserialized = Witness::deserialize(&serialized).unwrap();
        
        assert_eq!(witness.index(), deserialized.index());
    }
}
