mod util;
mod encryptor;

pub use encryptor::Sm4GcmStreamEncryptor;
use crate::encryptor::sm4_gcm_aad_encrypt;

#[test]
fn test_encrypt() {
    let data = vec![
        ([0u8; 16], [0u8; 12], &[], &b"hello world", "1587c6137e306fed6a6a5f49539b6dd6fe2b7872c3279636db07c2")
    ];

    for (key, nonce, aad, message, expected) in data {
        let encrypted = hex::encode(sm4_gcm_aad_encrypt(key, &nonce, aad, *message));
        assert_eq!(expected, &encrypted);
    }
}