# sm4-gcm

PENGING...


BC test code:
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


