//! Benchmarks for Lelantus protocol

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use silver_lelantus::*;

fn bench_commitment_creation(c: &mut Criterion) {
    c.bench_function("commitment_creation", |b| {
        let params = LelantusParameters::default();
        let scheme = CommitmentScheme::new(&params).unwrap();
        
        b.iter(|| {
            scheme.commit(black_box(1000)).unwrap()
        });
    });
}

fn bench_accumulator_add(c: &mut Criterion) {
    c.bench_function("accumulator_add", |b| {
        let params = LelantusParameters::default();
        let state = LelantusState::new(params).unwrap();
        
        b.iter(|| {
            let commitment = state.commitment_scheme()
                .commit(black_box(1000))
                .unwrap();
            state.add_coin(&commitment).unwrap();
        });
    });
}

criterion_group!(benches, bench_commitment_creation, bench_accumulator_add);
criterion_main!(benches);
