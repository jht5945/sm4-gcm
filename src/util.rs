use std::error::Error;

use sm4::cipher::BlockSizeUser;
use sm4::cipher::consts::U16;
use zeroize::Zeroize;

pub(crate) struct Sm4Block {}

impl BlockSizeUser for Sm4Block {
    type BlockSize = U16;
}

pub(crate) const BLOCK_SIZE: usize = 16;

pub struct Sm4Key(pub [u8; 16]);

impl Sm4Key {
    pub fn from_slice(key: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self(key.try_into()?))
    }
}

impl Drop for Sm4Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}


// R = 11100001 || 0(120)
const R: u128 = 0b11100001 << 120;

pub(crate) fn gmul_128(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in (0..128).rev() {
        let xi = (x >> i) & 1;
        if xi != 0 {
            z ^= v;
        }
        v = match v & 1 == 0 {
            true => { v >> 1 }
            false => { (v >> 1) ^ R }
        };
    }
    z
}

pub(crate) fn ghash(key: u128, messages: &[u128]) -> u128 {
    let mut y = 0u128;
    for message in messages {
        let yi = gmul_128(y ^ message, key);
        y = yi;
    }
    y
}

pub(crate) fn normalize_nonce(ghash_key: u128, nonce_bytes: &[u8]) -> (u128, u128) {
    let nonce = u8to128(nonce_bytes);
    let normalized_nonce = match nonce_bytes.len() == 12 {
        true => {
            nonce << 32 | 0x00000001
        }
        false => {
            let mut iv_padding = vec![];
            // s = 128[len(iv) / 128] - len(iv)
            let s = 128 * (((nonce_bytes.len() * 8) + 128 - 1) / 128) - (nonce_bytes.len() * 8);
            iv_padding.push(nonce << s);
            iv_padding.push((nonce_bytes.len() * 8) as u128);
            ghash(ghash_key, &iv_padding)
        }
    };
    (ghash_key, normalized_nonce)
}

pub(crate) fn msb_s(s: usize, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![];
    let n = s / 8;
    let remain = s % 8;
    result.extend_from_slice(&bytes[0..n]);
    if remain > 0 {
        result.push(bytes[n] >> (8 - remain));
    }
    result
}

#[inline]
pub(crate) fn u8to128(bytes: &[u8]) -> u128 {
    bytes.iter().rev().enumerate().fold(0, |acc, (i, &byte)| {
        acc | (byte as u128) << (i * 8)
    })
}

// incs(X)=MSBlen(X)-s(X) || [int(LSBs(X))+1 mod 2^s]s
#[inline]
pub(crate) fn inc_32(bits: u128) -> u128 {
    let msb = bits >> 32;
    let mut lsb = (bits & 0xffffffff) as u32;
    lsb = lsb.wrapping_add(1);
    msb << 32 | lsb as u128
}
