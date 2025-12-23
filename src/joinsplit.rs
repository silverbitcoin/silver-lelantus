//! JoinSplit transaction for Lelantus

use serde::{Deserialize, Serialize};
use serde_json;
use crate::commitment::Commitment;
use crate::proof::{RangeProof, ZKProof};

/// JoinSplit proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinSplitProof {
    /// Range proofs for outputs
    pub range_proofs: Vec<RangeProof>,
    
    /// Zero-knowledge proof
    pub zk_proof: ZKProof,
}

/// JoinSplit transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinSplit {
    /// Input commitments
    pub inputs: Vec<Commitment>,
    
    /// Output commitments
    pub outputs: Vec<Commitment>,
    
    /// Proof
    pub proof: JoinSplitProof,
    
    /// Transaction fee
    pub fee: u64,
}

impl JoinSplit {
    /// Get the number of inputs
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
    
    /// Get the number of outputs
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
    
    /// Serialize the JoinSplit
    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(serde_json::to_vec(self)?)
    }
    
    /// Deserialize the JoinSplit
    pub fn deserialize(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_joinsplit_creation() {
        let inputs = vec![
            Commitment {
                value: vec![1; 32],
                randomness: vec![2; 32],
            },
        ];
        
        let outputs = vec![
            Commitment {
                value: vec![3; 32],
                randomness: vec![4; 32],
            },
        ];
        
        let proof = JoinSplitProof {
            range_proofs: vec![],
            zk_proof: crate::proof::ZKProof {
                proof_data: vec![5; 32],
                challenge: vec![6; 32],
                response: vec![7; 32],
            },
        };
        
        let joinsplit = JoinSplit {
            inputs,
            outputs,
            proof,
            fee: 100,
        };
        
        assert_eq!(joinsplit.input_count(), 1);
        assert_eq!(joinsplit.output_count(), 1);
    }
    
    #[test]
    fn test_joinsplit_serialization() {
        let inputs = vec![
            Commitment {
                value: vec![1; 32],
                randomness: vec![2; 32],
            },
        ];
        
        let outputs = vec![
            Commitment {
                value: vec![3; 32],
                randomness: vec![4; 32],
            },
        ];
        
        let proof = JoinSplitProof {
            range_proofs: vec![],
            zk_proof: crate::proof::ZKProof {
                proof_data: vec![5; 32],
                challenge: vec![6; 32],
                response: vec![7; 32],
            },
        };
        
        let joinsplit = JoinSplit {
            inputs,
            outputs,
            proof,
            fee: 100,
        };
        
        let serialized = joinsplit.serialize().unwrap();
        let deserialized = JoinSplit::deserialize(&serialized).unwrap();
        
        assert_eq!(joinsplit.input_count(), deserialized.input_count());
        assert_eq!(joinsplit.output_count(), deserialized.output_count());
    }
}
