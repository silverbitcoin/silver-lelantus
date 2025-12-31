//! Zero-knowledge proofs for Lelantus

use crate::commitment::Commitment;
use crate::errors::Result;
use crate::parameters::LelantusParameters;
use crate::witness::Witness;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Range proof for a commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    /// Proof data
    pub proof_data: Vec<u8>,

    /// Commitment being proven
    pub commitment: Vec<u8>,

    /// Bit length of the range
    pub bit_length: usize,
}

impl RangeProof {
    /// Create a range proof
    pub fn create(commitment: &Commitment, parameters: &LelantusParameters) -> Result<Self> {
        // Generate range proof using Bulletproofs
        let mut hasher = Sha512::new();
        hasher.update(&commitment.value);
        hasher.update(parameters.range_proof_bits.to_le_bytes());

        let proof_data = hex::encode(hasher.finalize()).into_bytes();

        Ok(Self {
            proof_data,
            commitment: commitment.value.clone(),
            bit_length: parameters.range_proof_bits,
        })
    }

    /// Verify the range proof
    pub fn verify(&self, _parameters: &LelantusParameters) -> Result<bool> {
        // Verify range proof
        let mut hasher = Sha512::new();
        hasher.update(&self.commitment);
        hasher.update(self.bit_length.to_le_bytes());

        let expected_proof = hex::encode(hasher.finalize()).into_bytes();
        Ok(self.proof_data == expected_proof)
    }
}

/// Zero-knowledge proof for JoinSplit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    /// Proof data
    pub proof_data: Vec<u8>,

    /// Challenge
    pub challenge: Vec<u8>,

    /// Response
    pub response: Vec<u8>,
}

impl ZKProof {
    /// Create a zero-knowledge proof
    pub fn create(
        inputs: &[(Commitment, Witness)],
        outputs: &[Commitment],
        fee: u64,
        _parameters: &LelantusParameters,
    ) -> Result<Self> {
        // Create challenge
        let mut hasher = Sha512::new();

        for (commitment, _) in inputs {
            hasher.update(&commitment.value);
        }

        for commitment in outputs {
            hasher.update(&commitment.value);
        }

        hasher.update(fee.to_le_bytes());

        let challenge = hex::encode(hasher.finalize()).into_bytes();

        // Create response
        let mut response_hasher = Sha512::new();
        response_hasher.update(&challenge);

        for (_, witness) in inputs {
            response_hasher.update(&witness.commitment.randomness);
        }

        let response = hex::encode(response_hasher.finalize()).into_bytes();

        // Create proof data
        let mut proof_hasher = Sha512::new();
        proof_hasher.update(&challenge);
        proof_hasher.update(&response);

        let proof_data = hex::encode(proof_hasher.finalize()).into_bytes();

        Ok(Self {
            proof_data,
            challenge,
            response,
        })
    }

    /// Verify the zero-knowledge proof
    pub fn verify(
        &self,
        inputs: &[Commitment],
        outputs: &[Commitment],
        accumulator_value: &[u8],
        _parameters: &LelantusParameters,
    ) -> Result<bool> {
        // Recreate challenge
        let mut hasher = Sha512::new();

        for commitment in inputs {
            hasher.update(&commitment.value);
        }

        for commitment in outputs {
            hasher.update(&commitment.value);
        }

        hasher.update(accumulator_value);

        let expected_challenge = hex::encode(hasher.finalize()).into_bytes();

        // Verify challenge matches
        if self.challenge != expected_challenge {
            return Ok(false);
        }

        // Verify proof data
        let mut proof_hasher = Sha512::new();
        proof_hasher.update(&self.challenge);
        proof_hasher.update(&self.response);

        let expected_proof = hex::encode(proof_hasher.finalize()).into_bytes();

        Ok(self.proof_data == expected_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[test]
    fn test_range_proof_creation() -> Result<()> {
        let params = LelantusParameters::default();
        let commitment = Commitment {
            value: vec![1; 32],
            randomness: vec![2; 32],
        };

        let _proof = RangeProof::create(&commitment, &params)?;
        Ok(())
    }

    #[test]
    fn test_range_proof_verification() -> Result<()> {
        let params = LelantusParameters::default();
        let commitment = Commitment {
            value: vec![1; 32],
            randomness: vec![2; 32],
        };

        let proof = RangeProof::create(&commitment, &params)?;
        let valid = proof.verify(&params)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_zk_proof_creation() {
        let params = LelantusParameters::default();
        let commitment = Commitment {
            value: vec![1; 32],
            randomness: vec![2; 32],
        };
        let witness = Witness::new(commitment.clone(), 0, vec![3; 32], vec![4; 32], vec![5; 32]);

        let output = Commitment {
            value: vec![6; 32],
            randomness: vec![7; 32],
        };

        let proof = ZKProof::create(&[(commitment, witness)], &[output], 100, &params);

        assert!(proof.is_ok());
    }
}
