use std::hint::black_box;
use criterion::{ criterion_group, criterion_main, Criterion};
use vault_core::core::crypto::{derive_new_key, encrypt, decrypt};

const TEST_PASSWORD: &str = "a-very-STRONG-and-SECRET-password-!@#$";
const TEST_DATA: &[u8] = b"pdhrfmbejabgtbtxovoqdurdinuyynntunyjrzsugdtaflxqlxxpnctcoxphjohigyybxlgxgnwnigvqeqsimdibrmsznwmxymlk";

fn benchmark_key_derivation(c: &mut Criterion) {
    c.bench_function("key derivation", |b| {
        b.iter(|| {
            derive_new_key(black_box(TEST_PASSWORD)).expect("Key derivation failed");
        });
    });
}

fn benchmark_encryption_decryption(c: &mut Criterion){
    let (_salt,key)=derive_new_key(TEST_PASSWORD).expect("Key derivation failed");
    let encrypted_data=encrypt(TEST_DATA, &key).unwrap();

    let mut group= c.benchmark_group("AES-256-GCM");
    group.bench_function("encryption", |b| {
        b.iter(|| {
            encrypt(black_box(TEST_DATA), black_box(&key)).unwrap();
        });
    });
    group.bench_function("decryption", |b| {
        b.iter(|| {
            decrypt(black_box(&encrypted_data), black_box(&key)).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, benchmark_key_derivation, benchmark_encryption_decryption);
criterion_main!(benches);