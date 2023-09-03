# sm4-gcm

Encrypt & Decrypt test code:
```rust
fn main() {
    let key = Sm4Key([0u8; 16]);
    let nonce = [0u8; 12];
    let plaintext = b"Hello World!";

    let ciphertext = sm4_gcm::sm4_gcm_encrypt(&key, &nonce, plaintext);
    println!("Encrypted: {}", hex::encode(&ciphertext));
    let decrypted = sm4_gcm::sm4_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}
```


Generate test vector BC test code:
```java
public static void encryptGcmNoPadding(String key, String data, String nonce, String associatedData) throws Exception {
    Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
    Key sm4Key = new SecretKeySpec(Bytes.fromHex(key).bytes(), "SM4");
    byte[] iv = Bytes.fromHex(nonce).bytes();
    GCMParameterSpec s = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, sm4Key, s);
    if (associatedData != null && associatedData.length() > 0) {
        cipher.updateAAD(Bytes.fromHex(associatedData).bytes());
    }
    byte[] aa = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    System.out.println(Bytes.from(aa).asHex());
}
```


Benchmark @MacBook Pro (Retina, 15-inch, Late 2013/2 GHz Quad-Core Intel Core i7)
```text
$ cargo run --release --example bench
SM4/GCM encrypt : 65.69 M/s
```
