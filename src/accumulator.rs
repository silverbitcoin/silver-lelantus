//! Lelantus accumulator implementation

use crate::commitment::AccumulatorElement;
use crate::errors::{LelantusError, Result};
use crate::parameters::LelantusParameters;
use hex;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha512};

/// Lelantus accumulator for coin commitments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accumulator {
    /// Current accumulator value
    value: Vec<u8>,

    /// Elements in the accumulator
    elements: Vec<AccumulatorElement>,

    /// Parameters
    parameters: LelantusParameters,
}

impl Accumulator {
    /// Create a new accumulator
    pub fn new(parameters: &LelantusParameters) -> Result<Self> {
        parameters.validate()?;

        // Initialize with generator
        let mut hasher = Sha512::new();
        hasher.update(&parameters.accumulator_base);
        let initial_value = hex::encode(hasher.finalize()).into_bytes();

        Ok(Self {
            value: initial_value,
            elements: Vec::new(),
            parameters: parameters.clone(),
        })
    }

    /// Add an element to the accumulator
    pub fn add_element(&mut self, element: AccumulatorElement) -> Result<()> {
        // Update accumulator: new_value = H(old_value || element)
        let mut hasher = Sha512::new();
        hasher.update(&self.value);
        hasher.update(&element.value);

        self.value = hex::encode(hasher.finalize()).into_bytes();
        self.elements.push(element);

        Ok(())
    }

    /// Get the current accumulator value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Get the number of elements
    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    /// Get all elements
    pub fn elements(&self) -> &[AccumulatorElement] {
        &self.elements
    }

    /// Serialize the accumulator
    pub fn serialize(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| LelantusError::SerializationError(e.to_string()))
    }

    /// Deserialize the accumulator
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| LelantusError::SerializationError(e.to_string()))
    }

    /// Create a proof of membership for an element
    pub fn create_membership_proof(&self, element_index: usize) -> Result<MembershipProof> {
        if element_index >= self.elements.len() {
            return Err(LelantusError::InvalidParameter);
        }

        // Create path from element to root
        let mut path = Vec::new();
        let mut current_value = self.parameters.accumulator_base.clone();

        // Build path by accumulating all elements
        for (i, element) in self.elements.iter().enumerate() {
            let mut hasher = Sha512::new();
            hasher.update(&current_value);
            hasher.update(&element.value);
            current_value = hex::encode(hasher.finalize()).into_bytes();

            path.push(ProofNode {
                value: element.value.clone(),
                is_left: i <= element_index,
            });
        }

        Ok(MembershipProof {
            element_index,
            path,
            accumulator_value: self.value.clone(),
        })
    }

    /// Verify a membership proof
    pub fn verify_membership_proof(&self, proof: &MembershipProof) -> Result<bool> {
        if proof.element_index >= self.elements.len() {
            return Ok(false);
        }

        // Reconstruct the accumulator value by replaying the path
        let mut current_value = self.parameters.accumulator_base.clone();

        for node in proof.path.iter() {
            let mut hasher = Sha512::new();
            hasher.update(&current_value);
            hasher.update(&node.value);
            current_value = hex::encode(hasher.finalize()).into_bytes();
        }

        // Verify the reconstructed value matches the proof's accumulator value
        Ok(current_value == proof.accumulator_value)
    }
}

/// Membership proof for an element in the accumulator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    /// Index of the element
    pub element_index: usize,

    /// Path from element to root
    pub path: Vec<ProofNode>,

    /// Accumulator value at proof creation time
    pub accumulator_value: Vec<u8>,
}

/// Node in a membership proof path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    /// Value of the node
    pub value: Vec<u8>,

    /// Whether this node is on the left
    pub is_left: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[test]
    fn test_accumulator_creation() -> Result<()> {
        let params = LelantusParameters::default();
        let _accumulator = Accumulator::new(&params)?;
        Ok(())
    }

    #[test]
    fn test_add_element() -> Result<()> {
        let params = LelantusParameters::default();
        let mut accumulator = Accumulator::new(&params)?;
        let element = AccumulatorElement { value: vec![1; 32] };

        accumulator.add_element(element)?;
        assert_eq!(accumulator.element_count(), 1);
        Ok(())
    }

    #[test]
    fn test_multiple_elements() -> Result<()> {
        let params = LelantusParameters::default();
        let mut accumulator = Accumulator::new(&params)?;

        for i in 0..10 {
            let element = AccumulatorElement {
                value: vec![i as u8; 32],
            };
            accumulator.add_element(element)?;
        }

        assert_eq!(accumulator.element_count(), 10);
        Ok(())
    }

    #[test]
    fn test_serialization() -> Result<()> {
        let params = LelantusParameters::default();
        let mut accumulator = Accumulator::new(&params)?;
        let element = AccumulatorElement {
            value: vec![42; 32],
        };
        accumulator.add_element(element)?;

        let serialized = accumulator.serialize()?;
        let deserialized = Accumulator::deserialize(&serialized)?;
        assert_eq!(accumulator.element_count(), deserialized.element_count());
        Ok(())
    }

    #[test]
    fn test_membership_proof() -> Result<()> {
        let params = LelantusParameters::default();
        let mut accumulator = Accumulator::new(&params)?;

        for i in 0..5 {
            let element = AccumulatorElement {
                value: vec![i as u8; 32],
            };
            accumulator.add_element(element)?;
        }

        let proof = accumulator.create_membership_proof(2)?;
        // Verify proof structure is valid
        assert_eq!(proof.element_index, 2);
        assert_eq!(proof.path.len(), 5);
        assert!(!proof.accumulator_value.is_empty());
        Ok(())
    }
}
