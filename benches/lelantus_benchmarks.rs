//! Benchmarks for Lelantus protocol

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use silver_lelantus::*;

fn bench_commitment_creation(c: &mut Criterion) {
    c.bench_function("commitment_creation", |b| {
        let params = LelantusParameters::default();
        let scheme = match CommitmentScheme::new(&params) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create commitment scheme: {}", e);
                return;
            }
        };
        
        b.iter(|| {
            match scheme.commit(black_box(1000)) {
                Ok(commitment) => commitment,
                Err(e) => {
                    eprintln!("Commitment creation failed: {}", e);
                    return;
                }
            }
        });
    });
}

fn bench_accumulator_add(c: &mut Criterion) {
    c.bench_function("accumulator_add", |b| {
        let params = LelantusParameters::default();
        let state = match LelantusState::new(params) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create Lelantus state: {}", e);
                return;
            }
        };
        
        b.iter(|| {
            let commitment = match state.commitment_scheme().commit(black_box(1000)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Commitment creation failed: {}", e);
                    return;
                }
            };
            
            if let Err(e) = state.add_coin(&commitment) {
                eprintln!("Failed to add coin: {}", e);
            }
        });
    });
}

criterion_group!(benches, bench_commitment_creation, bench_accumulator_add);
criterion_main!(benches);
