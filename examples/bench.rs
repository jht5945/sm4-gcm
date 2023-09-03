use benchmark_simple::{Bench, Options};

use sm4_gcm::{Sm4GcmStreamEncryptor, Sm4Key};

fn main() {
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
    let key = Sm4Key([0u8; 16]);
    let nonce = [0u8; 12];
    let mut encryptor = Sm4GcmStreamEncryptor::new(&key, &nonce);

    encryptor.update(m);
    encryptor.finalize();
}