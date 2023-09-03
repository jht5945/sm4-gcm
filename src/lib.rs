pub use encryptor::Sm4GcmStreamEncryptor;

pub use crate::encryptor::sm4_gcm_aad_encrypt;
pub use crate::encryptor::sm4_gcm_encrypt;

mod util;
mod encryptor;
mod decryptor;

// Test vectors are all from BC
#[test]
fn test_encrypt() {
    let data = vec![
        ([0u8; 16], [0u8; 12], &[][..], &b"A"[..], "3c0a0922976fa15e835bc96750e730d967"),
        ([0u8; 16], [0u8; 12], &[][..], &b"hello world"[..], "1587c6137e306fed6a6a5f49539b6dd6fe2b7872c3279636db07c2"),
        ([0u8; 16], [0xffu8; 12], &[][..], &b"Hello World!"[..], "cba3523bdf74096f3de1f9160a5adb7bf385dea4d50c910e663ec75a"),
        ([0xffu8; 16], [0xffu8; 12], &[][..], &b"Hello World!"[..], "99eb1206b5b2a9f9c7d7ec4a81de507f5d79938a10ccd91da68d2fb1"),
        ([0xffu8; 16], [0xffu8; 12], &[0xaau8, 0xbbu8, 0xccu8][..], &b"Hello World!"[..], "99eb1206b5b2a9f9c7d7ec4a7be091388b3049363189e64a47d20c19"),
        ([0u8; 16], [0u8; 12], &[][..],
         &b"Hello World!Hello World!Hello World!Hello World!Hello World!Hello World!"[..],
         "3587c6137e304fed6a6a5fc0f78e01e5ea4b604843929848601d4b1600e35c1\
         987a30fd521f6b8f66e950cfb735ca19ab45bd8d050a06b2d560a5927a5611f76\
         82cd8c6db56ab52dae82a6db190c54ff8299ac7d339f92db"),
    ];

    for (key, nonce, aad, message, expected) in data {
        let encrypted = hex::encode(sm4_gcm_aad_encrypt(key, &nonce, aad, message));
        assert_eq!(expected, &encrypted);
    }
}