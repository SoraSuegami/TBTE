use std::f32::consts::E;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use kzg::Fr;
use rand::thread_rng;
use rand::Rng;
use rust_kzg_blst::types::fr::FsFr;
// Import all necessary structs, traits, and functions from the TBTE module
use TBTE::*;

// Define constants
// const FIELD_ELEMENTS_PER_BLOB: usize = 4096; // Example value
// const NUM_PARTIES: u64 = 100;
// const CORRUPT_THRESHOLD: u64 = 33;

fn benchmark_kzg_tbte_1024_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 10, 9, 3);
}

fn benchmark_kzg_tbte_2048_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 11, 9, 3);
}

fn benchmark_kzg_tbte_4096_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 12, 9, 3);
}

fn benchmark_kzg_tbte_8192_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 13, 9, 3);
}

fn benchmark_kzg_tbte_16384_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 14, 9, 3);
}

fn benchmark_kzg_tbte_32768_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 15, 9, 3);
}

fn benchmark_kzg_tbte_65536_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 16, 9, 3);
}

fn benchmark_kzg_tbte_1024_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 10, 99, 33);
}

fn benchmark_kzg_tbte_2048_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 11, 99, 3);
}

fn benchmark_kzg_tbte_4096_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 12, 99, 33);
}

fn benchmark_kzg_tbte_8192_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 13, 99, 33);
}

fn benchmark_kzg_tbte_16384_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 14, 99, 33);
}

fn benchmark_kzg_tbte_32768_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 15, 99, 33);
}

fn benchmark_kzg_tbte_65536_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 16, 99, 33);
}

// Benchmark function
fn benchmark_kzg_tbte(
    c: &mut Criterion,
    batch_scale: usize,
    num_parties: u64,
    corrupt_threshold: u64,
) {
    // Create a benchmark group
    let mut group = c.benchmark_group("KZG_TBTE_Benchmark");

    // Set sample size to 10 for averaging over 10 runs
    group.sample_size(10);

    // Initialize the TBTE scheme with a domain separation tag (DST)
    let tbte = KZGTbteScheme::new(b"dst".to_vec());

    // Setup CRS (Common Reference String)
    let batch_size: usize = 1 << batch_scale;
    let secret = [0u8; 32]; // Example secret
    let crs = tbte
        .setup_crs(batch_scale, secret)
        .expect("CRS setup failed");
    // Setup keys with the given number of parties and corruption threshold
    let (sks, pk) = tbte
        .setup_keys(crs, corrupt_threshold, num_parties)
        .expect("Key setup failed");

    // Generate random tags
    let mut tags = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        tags.push(KZGTag(FsFr::rand()));
    }

    // Generate random plaintexts
    let mut rng = thread_rng();
    let plaintexts: Vec<bool> = (0..batch_size).map(|_| rng.gen::<bool>()).collect();
    // Epoch ID
    let eid = 1;

    // Encryption Benchmark
    group.bench_function("encryption", |b| {
        b.iter(|| {
            // Perform batch encryption
            let ct = tbte
                .enc(&pk, &eid, 0, &tags[0], &plaintexts[0])
                .expect("Encryption failed");

            // Consume the ciphertexts to prevent optimizations
            black_box(ct);
        });
    });
    let cts = tbte
        .enc_batch(
            &pk,
            &eid,
            &(0u64..batch_size as u64).collect::<Vec<u64>>(),
            &tags,
            &plaintexts,
        )
        .expect("Encryption failed");

    // Digest Benchmark
    group.bench_function("digest", |b| {
        b.iter(|| {
            // Compute digest
            let digest = tbte.digest(&pk, &tags).expect("Digest computation failed");

            // Consume the digest to prevent optimizations
            black_box(digest);
        });
    });
    let digest = tbte.digest(&pk, &tags).expect("Digest computation failed");

    // Partial Decryption Benchmark
    group.bench_function("partial decryption", |b| {
        b.iter(|| {
            // Generate partial decryptions
            let pd = tbte
                .batch_dec(&sks[0], &eid, &digest)
                .expect("Partial decryption failed");

            // Consume the recovered plaintexts to prevent optimizations
            black_box(pd);
        });
    });
    let pds: Vec<_> = sks
        .iter()
        .map(|sk| tbte.batch_dec(sk, &eid, &digest))
        .collect::<Result<Vec<_>, _>>()
        .expect("Partial decryption failed");

    // Combine Benchmark
    group.bench_function("combine", |b| {
        b.iter(|| {
            // Perform combine step to recover plaintexts
            let recovered = tbte
                .combine(&pk, &eid, &cts, &pds)
                .expect("Combine step failed");

            // Consume the recovered plaintexts to prevent optimizations
            black_box(recovered);
        });
    });

    // Finish the benchmark group
    group.finish();
}

// Define the benchmark group and main function
criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = benchmark_kzg_tbte_1024_9_3, benchmark_kzg_tbte_2048_9_3, benchmark_kzg_tbte_4096_9_3, benchmark_kzg_tbte_8192_9_3, benchmark_kzg_tbte_16384_9_3, benchmark_kzg_tbte_32768_9_3, benchmark_kzg_tbte_65536_9_3, benchmark_kzg_tbte_1024_99_33, benchmark_kzg_tbte_2048_99_33, benchmark_kzg_tbte_4096_99_33, benchmark_kzg_tbte_8192_99_33, benchmark_kzg_tbte_16384_99_33, benchmark_kzg_tbte_32768_99_33, benchmark_kzg_tbte_65536_99_33
}
criterion_main!(benches);
