# Constant-Cost Batched Partial Decryption in Threshold Encryption
This repository provides an implementation of tag-based batched threshold encryption (TBTE).

## Requirement
- rustc 1.78.0 (9b00956e5 2024-04-29)
- cargo 1.78.0 (54d8815d0 2024-03-26)

## Build
You can build this rust library as follows:

1. Clone this repository. Let `TBTE` be the path to the folder where this repository was cloned.
2. Download the rust-kzg library from [this link](https://anonymous.4open.science/api/repo/rust-kzg-1DE3/zip).
3. Unzip the downloaded file.
4. Place the unzipped directory in the parent directory of the folder where this repository was cloned. In other words, the `TBTE` and `Rust KZG 1DE3` directories should be placed under the same parent directory.
5. In the `TBTE` directory, run `cargo build`.

## Test
After building our library, you can run our test codes by `cargo test`.

## Bench
You can run benchmark codes by `cargo bench`.
