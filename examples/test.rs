use benchmark_simple::{Bench, Options};

use sm4_gcm::Sm4GcmStreamEncryptor;

fn main() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let mut e = Sm4GcmStreamEncryptor::new(key, &nonce);

    println!("{}", hex::encode(&key));
    println!("{}", hex::encode(&nonce));

    let a = e.update(b"hello world");
    let (b, t) = e.finalize();

    let mut enc = a.clone();
    enc.extend_from_slice(&b);
    enc.extend_from_slice(&t);

    println!("{}", hex::encode(&enc));

    // ----------------------------------------------------------------------
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 1_000,
        warmup_iterations: 1_00,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_sm4_encrypt(&mut m));
    println!("SM4/GCM encrypt : {}", res.throughput(m.len() as _));
}


fn test_sm4_encrypt(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let mut encryptor = Sm4GcmStreamEncryptor::new(key, &nonce);

    encryptor.update(m);
    encryptor.finalize();
}