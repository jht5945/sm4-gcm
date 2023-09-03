use ghash::GHash;
use ghash::universal_hash::UniversalHash;
use sm4::cipher::{Block, BlockEncrypt, KeyInit};
use sm4::cipher::generic_array::GenericArray;
use sm4::Sm4;
use zeroize::Zeroize;

use crate::util::{BLOCK_SIZE, inc_32, msb_s, normalize_nonce, Sm4Block, Sm4Key, u8to128};

pub fn sm4_gcm_encrypt(key: &Sm4Key, nonce: &[u8], message: &[u8]) -> Vec<u8> {
    sm4_gcm_aad_encrypt(key, nonce, &[], message)
}

pub fn sm4_gcm_aad_encrypt(key: &Sm4Key, nonce: &[u8], aad: &[u8], message: &[u8]) -> Vec<u8> {
    let mut encryptor = Sm4GcmStreamEncryptor::new(key, nonce);
    if aad.len() > 0 {
        encryptor.init_adata(aad);
    }
    let mut enc1 = encryptor.update(message);
    let (enc2, tag) = encryptor.finalize();
    enc1.extend_from_slice(&enc2);
    enc1.extend_from_slice(&tag);
    enc1
}

pub struct Sm4GcmStreamEncryptor {
    cipher: Sm4,
    message_buffer: Vec<u8>,
    ghash: GHash,
    init_nonce: u128,
    encryption_nonce: u128,
    adata_len: usize,
    message_len: usize,
}

impl Sm4GcmStreamEncryptor {
    pub fn new(key: &Sm4Key, nonce: &[u8]) -> Self {
        let mut key = GenericArray::from(key.0);
        let cipher = Sm4::new(&key);

        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);
        let ghash = GHash::new(&ghash_key);
        ghash_key.zeroize();
        key.zeroize();

        let mut s = Self {
            cipher,
            message_buffer: vec![],
            ghash,
            init_nonce: 0,
            encryption_nonce: 0,
            adata_len: 0,
            message_len: 0,
        };
        let (_, normalized_nonce) = s.normalize_nonce(nonce);
        s.init_nonce = normalized_nonce;
        s.encryption_nonce = normalized_nonce;
        s
    }

    pub fn init_adata(&mut self, adata: &[u8]) {
        if adata.len() > 0 {
            self.adata_len += adata.len();
            self.ghash.update_padded(adata);
        }
    }

    pub fn update(&mut self, message: &[u8]) -> Vec<u8> {
        self.message_buffer.extend_from_slice(message);
        let message_buffer_slice = self.message_buffer.as_slice();
        if message_buffer_slice.len() < BLOCK_SIZE {
            return Vec::with_capacity(0);
        }
        let blocks_count = message_buffer_slice.len() / BLOCK_SIZE;
        let mut blocks = Vec::with_capacity(blocks_count);
        for _ in 0..blocks_count {
            self.encryption_nonce = inc_32(self.encryption_nonce);
            let ctr = self.encryption_nonce.to_be_bytes();
            blocks.push(Block::<Sm4Block>::clone_from_slice(&ctr));
        }
        self.cipher.encrypt_blocks(&mut blocks);

        let mut encrypted_message = message_buffer_slice[0..blocks_count * BLOCK_SIZE].to_vec();
        for i in 0..blocks_count {
            let chunk = &mut encrypted_message[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            let block = blocks[i].as_slice();
            for k in 0..BLOCK_SIZE {
                chunk[k] ^= block[k];
            }
        }
        self.ghash.update_padded(&encrypted_message);
        self.message_buffer = message_buffer_slice[blocks_count * BLOCK_SIZE..].to_vec();
        self.message_len += encrypted_message.len();

        encrypted_message
    }

    pub fn finalize(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut final_encrypted_message = Vec::with_capacity(BLOCK_SIZE);
        if !self.message_buffer.is_empty() {
            // last block and this block len may less than 128 bits (16 bytes)
            self.encryption_nonce = inc_32(self.encryption_nonce);
            let mut ctr = self.encryption_nonce.to_be_bytes();
            let block = Block::<Sm4Block>::from_mut_slice(&mut ctr);
            self.cipher.encrypt_block(block);

            let chunk = self.message_buffer.as_slice();
            let msb = msb_s(chunk.len() * 8, block.as_slice());
            let y = u8to128(chunk) ^ u8to128(&msb);
            final_encrypted_message.extend_from_slice(&y.to_be_bytes()[16 - chunk.len()..16]);
            self.ghash.update_padded(&final_encrypted_message);
            self.message_len += final_encrypted_message.len();
        }
        let adata_bit_len = self.adata_len * 8;
        let message_bit_len = self.message_len * 8;
        let mut adata_and_message_len = Vec::with_capacity(BLOCK_SIZE);
        adata_and_message_len.extend_from_slice(&(adata_bit_len as u64).to_be_bytes());
        adata_and_message_len.extend_from_slice(&(message_bit_len as u64).to_be_bytes());
        self.ghash.update_padded(&adata_and_message_len);


        let tag = self.compute_tag();

        (final_encrypted_message, tag)
    }

    fn compute_tag(&mut self) -> Vec<u8> {
        let mut bs = self.init_nonce.to_be_bytes().clone();
        let block = Block::<Sm4Block>::from_mut_slice(&mut bs);
        self.cipher.encrypt_block(block);
        let ghash = self.ghash.clone().finalize();
        let tag_trunk = ghash.as_slice();
        let y = u8to128(&tag_trunk) ^ u8to128(&block.as_slice());
        y.to_be_bytes().to_vec()
    }

    fn ghash_key(&mut self) -> u128 {
        let mut block = [0u8; BLOCK_SIZE];
        let block = Block::<Sm4Block>::from_mut_slice(&mut block);
        self.cipher.encrypt_block(block);
        u8to128(&block.as_slice())
    }

    fn normalize_nonce(&mut self, nonce_bytes: &[u8]) -> (u128, u128) {
        let ghash_key = self.ghash_key();
        normalize_nonce(ghash_key, nonce_bytes)
    }
}