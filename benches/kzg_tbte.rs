use std::f32::consts::E;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use kzg::{Fr, G1, G2};
use rand::thread_rng;
use rand::Rng;
use rust_kzg_blst::types::fr::FsFr;
// Import all necessary structs, traits, and functions from the TBTE module
use TBTE::*;

// Define constants
// const FIELD_ELEMENTS_PER_BLOB: usize = 4096; // Example value
// const NUM_PARTIES: u64 = 100;
// const CORRUPT_THRESHOLD: u64 = 33;

fn benchmark_kzg_tbte_10_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 10, 9, 3);
}

fn benchmark_kzg_tbte_11_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 11, 9, 3);
}

fn benchmark_kzg_tbte_12_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 12, 9, 3);
}

fn benchmark_kzg_tbte_13_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 13, 9, 3);
}

fn benchmark_kzg_tbte_14_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 14, 9, 3);
}

fn benchmark_kzg_tbte_15_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 15, 9, 3);
}

fn benchmark_kzg_tbte_16_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 16, 9, 3);
}

fn benchmark_kzg_tbte_17_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 17, 9, 3);
}

fn benchmark_kzg_tbte_18_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 18, 9, 3);
}

fn benchmark_kzg_tbte_19_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 19, 9, 3);
}

fn benchmark_kzg_tbte_20_9_3(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 20, 9, 3);
}

fn benchmark_kzg_tbte_10_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 10, 99, 33);
}

fn benchmark_kzg_tbte_11_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 11, 99, 3);
}

fn benchmark_kzg_tbte_12_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 12, 99, 33);
}

fn benchmark_kzg_tbte_13_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 13, 99, 33);
}

fn benchmark_kzg_tbte_14_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 14, 99, 33);
}

fn benchmark_kzg_tbte_15_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 15, 99, 33);
}

fn benchmark_kzg_tbte_16_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 16, 99, 33);
}

fn benchmark_kzg_tbte_17_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 17, 99, 33);
}

fn benchmark_kzg_tbte_18_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 18, 99, 33);
}

fn benchmark_kzg_tbte_19_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 19, 99, 33);
}

fn benchmark_kzg_tbte_20_99_33(c: &mut Criterion) {
    benchmark_kzg_tbte(c, 20, 99, 33);
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
    let hasher = Sha256HasherFp12ToBytes::new();
    let sym_enc = ChaCha20EncScheme::new();
    let tbte = KZGTbteScheme::new(b"dst".to_vec(), hasher, sym_enc);

    // Setup CRS (Common Reference String)
    let batch_size: usize = 1 << batch_scale;
    let secret = [0u8; 32]; // Example secret
                            // Setup Benchmark
                            // group.bench_function(
                            //     format!(
                            //         "setup batch_scale={}, num_parties={}, corrupt_threshold={}",
                            //         batch_scale, num_parties, corrupt_threshold
                            //     ),
                            //     |b| {
                            //         b.iter(|| {
                            //             // Setup the CRS
                            //             let crs = tbte
                            //                 .setup_crs(batch_scale, secret)
                            //                 .expect("CRS setup failed");
                            //             // Setup keys with the given number of parties and corruption threshold
                            //             let (sks, pk) = tbte
                            //                 .setup_keys(crs, corrupt_threshold, num_parties)
                            //                 .expect("Key setup failed");

    //             // Consume the keys to prevent optimizations
    //             black_box(sks);
    //             black_box(pk);
    //         });
    //     },
    // );
    let crs = tbte
        .setup_crs(batch_scale, secret)
        .expect("CRS setup failed");
    // Setup keys with the given number of parties and corruption threshold
    let (sks, pk) = tbte
        .setup_keys(crs, corrupt_threshold, num_parties)
        .expect("Key setup failed");
    println!("pk size: {:?}", pk.data_sizes());

    // Generate random tags
    let mut tags = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        tags.push(KZGTag(FsFr::rand()));
    }

    // Generate random plaintexts
    let mut rng = thread_rng();
    let plaintexts: Vec<Vec<u8>> = (0..batch_size)
        .map(|_| rng.gen::<[u8; 32]>().to_vec())
        .collect();
    // Epoch ID
    let eid = 1;

    // Encryption Benchmark
    group.bench_function(
        format!(
            "encryption batch_scale={}, num_parties={}, corrupt_threshold={}",
            batch_scale, num_parties, corrupt_threshold
        ),
        |b| {
            b.iter(|| {
                // Perform batch encryption
                let ct = tbte
                    .enc(&pk, &eid, 0, &tags[0], &plaintexts[0])
                    .expect("Encryption failed");
                // Consume the ciphertexts to prevent optimizations
                black_box(ct);
            });
        },
    );
    let cts = tbte
        .enc_batch(
            &pk,
            &eid,
            &(0u64..batch_size as u64).collect::<Vec<u64>>(),
            &tags,
            &plaintexts,
        )
        .expect("Encryption failed");
    println!("ct size: {:?}", cts[0].data_size());

    // Digest Benchmark
    group.bench_function(
        format!(
            "digest batch_scale={}, num_parties={}, corrupt_threshold={}",
            batch_scale, num_parties, corrupt_threshold
        ),
        |b| {
            b.iter(|| {
                // Compute digest
                let digest = tbte.digest(&pk, &tags).expect("Digest computation failed");
                // Consume the digest to prevent optimizations
                black_box(digest);
            });
        },
    );
    let digest = tbte.digest(&pk, &tags).expect("Digest computation failed");
    println!("digest size {}", digest.to_bytes().len());

    // Partial Decryption Benchmark
    group.bench_function(
        format!(
            "partial decryption batch_scale={}, num_parties={}, corrupt_threshold={}",
            batch_scale, num_parties, corrupt_threshold
        ),
        |b| {
            b.iter(|| {
                // Generate partial decryptions
                let pd = tbte
                    .batch_dec(&sks[0], &eid, &digest)
                    .expect("Partial decryption failed");
                // Consume the recovered plaintexts to prevent optimizations
                black_box(pd);
            });
        },
    );
    let pds: Vec<_> = sks
        .iter()
        .map(|sk| tbte.batch_dec(sk, &eid, &digest))
        .collect::<Result<Vec<_>, _>>()
        .expect("Partial decryption failed");
    println!("pd size: {:?}", 8 + pds[0].1.to_bytes().len());

    // Combine Benchmark
    group.bench_function(
        format!(
            "combine batch_scale={}, num_parties={}, corrupt_threshold={}",
            batch_scale, num_parties, corrupt_threshold
        ),
        |b| {
            b.iter(|| {
                // Perform combine step to recover plaintexts
                let recovered = tbte
                    .combine(&pk, &eid, &cts[0..1], &tags, &pds)
                    .expect("Combine step failed");

                // Consume the recovered plaintexts to prevent optimizations
                black_box(recovered);
            });
        },
    );

    // Finish the benchmark group
    group.finish();
}

// Define the benchmark group and main function
criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = benchmark_kzg_tbte_10_9_3, benchmark_kzg_tbte_10_99_33, benchmark_kzg_tbte_11_9_3, benchmark_kzg_tbte_11_99_33, benchmark_kzg_tbte_12_9_3, benchmark_kzg_tbte_12_99_33, benchmark_kzg_tbte_13_9_3, benchmark_kzg_tbte_13_99_33, benchmark_kzg_tbte_14_9_3, benchmark_kzg_tbte_14_99_33, benchmark_kzg_tbte_15_9_3, benchmark_kzg_tbte_15_99_33, benchmark_kzg_tbte_16_9_3, benchmark_kzg_tbte_16_99_33, benchmark_kzg_tbte_17_9_3, benchmark_kzg_tbte_17_99_33, benchmark_kzg_tbte_18_9_3, benchmark_kzg_tbte_18_99_33, benchmark_kzg_tbte_19_9_3, benchmark_kzg_tbte_19_99_33, benchmark_kzg_tbte_20_9_3, benchmark_kzg_tbte_20_99_33
}
criterion_main!(benches);
