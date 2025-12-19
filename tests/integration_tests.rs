//! Integration tests for Lelantus protocol

use silver_lelantus::*;

#[test]
fn test_lelantus_full_workflow() {
    // Create parameters
    let params = LelantusParameters::default();
    
    // Create state
    let state = LelantusState::new(params).expect("Failed to create state");
    
    // Create commitment
    let commitment = state.commitment_scheme()
        .commit(1000)
        .expect("Failed to create commitment");
    
    // Add coin
    state.add_coin(&commitment).expect("Failed to add coin");
    
    // Verify accumulator
    let accumulator = state.get_accumulator().expect("Failed to get accumulator");
    assert!(!accumulator.is_empty());
}

#[test]
fn test_lelantus_multiple_coins() {
    let params = LelantusParameters::default();
    let state = LelantusState::new(params).expect("Failed to create state");
    
    // Add multiple coins
    for i in 0..10 {
        let commitment = state.commitment_scheme()
            .commit(1000 + i * 100)
            .expect("Failed to create commitment");
        
        state.add_coin(&commitment).expect("Failed to add coin");
    }
    
    // Verify accumulator
    let accumulator = state.get_accumulator().expect("Failed to get accumulator");
    assert!(!accumulator.is_empty());
}

#[test]
fn test_lelantus_privacy_levels() {
    for privacy_level in &[
        PrivacyLevel::Standard,
        PrivacyLevel::Enhanced,
        PrivacyLevel::Maximum,
    ] {
        let params = LelantusParameters::with_privacy_level(*privacy_level);
        let state = LelantusState::new(params).expect("Failed to create state");
        
        let commitment = state.commitment_scheme()
            .commit(1000)
            .expect("Failed to create commitment");
        
        state.add_coin(&commitment).expect("Failed to add coin");
    }
}
