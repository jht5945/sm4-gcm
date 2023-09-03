use sm4_gcm::Sm4Key;

fn main() {
    let key = Sm4Key([0u8; 16]);
    let nonce = [0u8; 12];
    let plaintext = b"Hello World!";

    let ciphertext = sm4_gcm::sm4_gcm_encrypt(&key, &nonce, plaintext);
    println!("Encrypted: {}", hex::encode(&ciphertext));
    let decrypted = sm4_gcm::sm4_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}