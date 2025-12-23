//! Serialization utilities for Lelantus

use serde::{Deserialize, Serialize};
use serde_json;
use crate::errors::{LelantusError, Result};

/// Serializable wrapper for Lelantus types
pub trait LelantusSerializable: Serialize + for<'de> Deserialize<'de> {
    /// Serialize to bytes
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| LelantusError::SerializationError(e.to_string()))
    }
    
    /// Deserialize from bytes
    fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| LelantusError::SerializationError(e.to_string()))
    }
}

/// Hex encoding utilities
pub mod hex_util {
    use crate::errors::Result;
    
    /// Encode bytes to hex string
    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }
    
    /// Decode hex string to bytes
    pub fn decode(hex_str: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str)
            .map_err(|e| crate::errors::LelantusError::SerializationError(e.to_string()))
    }
}

/// JSON encoding utilities
pub mod json {
    use crate::errors::Result;
    
    /// Encode value to JSON
    pub fn encode<T: serde::Serialize>(value: &T) -> Result<String> {
        serde_json::to_string(value)
            .map_err(|e| crate::errors::LelantusError::SerializationError(e.to_string()))
    }
    
    /// Decode JSON to value
    pub fn decode<T: for<'de> serde::Deserialize<'de>>(json_str: &str) -> Result<T> {
        serde_json::from_str(json_str)
            .map_err(|e| crate::errors::LelantusError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::Commitment;
    
    #[test]
    fn test_hex_encoding() {
        let data = vec![1, 2, 3, 4, 5];
        let encoded = hex_util::encode(&data);
        let decoded = hex_util::decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }
    
    #[test]
    fn test_json_encoding() {
        let commitment = Commitment {
            value: vec![1; 32],
            randomness: vec![2; 32],
        };
        
        let json_str = json::encode(&commitment).unwrap();
        let decoded: Commitment = json::decode(&json_str).unwrap();
        
        assert_eq!(commitment.value, decoded.value);
    }
}
