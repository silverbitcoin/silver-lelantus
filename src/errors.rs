//! Error types for Lelantus protocol

use thiserror::Error;

/// Lelantus protocol errors
#[derive(Error, Debug, Clone)]
pub enum LelantusError {
    #[error("Invalid input count: must be between 1 and 16")]
    InvalidInputCount,
    
    #[error("Invalid output count: must be between 1 and 2")]
    InvalidOutputCount,
    
    #[error("Balance mismatch: inputs do not equal outputs + fee")]
    BalanceMismatch,
    
    #[error("Invalid commitment")]
    InvalidCommitment,
    
    #[error("Invalid witness")]
    InvalidWitness,
    
    #[error("Invalid proof")]
    InvalidProof,
    
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    
    #[error("Accumulator error: {0}")]
    AccumulatorError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Invalid parameter")]
    InvalidParameter,
    
    #[error("Witness not found")]
    WitnessNotFound,
    
    #[error("Range proof error: {0}")]
    RangeProofError(String),
    
    #[error("Zero-knowledge proof error: {0}")]
    ZKProofError(String),
}

/// Result type for Lelantus operations
pub type Result<T> = std::result::Result<T, LelantusError>;
