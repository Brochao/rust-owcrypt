
use crate::consts;
use sha1;
use sha2::{Sha256,Sha512, Digest as Sha2Digest};
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512, Keccak256, Keccak512};
use md4::Md4;
use md5;
use ripemd160::Ripemd160;

#[allow(unused_imports)]
use blake2_rfc::blake2b::blake2b;
use blake2_rfc::blake2s::blake2s;

#[allow(unused_imports)]
use blake::Blake;

use sm3::Sm3;
#[allow(unused_imports)]
use sha2::digest::Reset;

use hmac_sha256::{HMAC as HMAC_SHA256};
use hmac_sha512::{HMAC as HMAC_SHA512};



#[allow(unused_variables)]
#[allow(unused_mut)]
pub fn hash(data: & [u8], digest_length: usize, type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    match type_choose {

        consts::HASH_ALG_SHA1 => {
            let mut sha1_context = sha1::Sha1::new();
            sha1_context.update(data);

            Ok(Box::new(sha1_context.digest().bytes().to_vec()))

        }

        consts::HASH_ALG_SHA3_256 => {
            let mut sha3_256_context = Sha3_256::new();
            sha3_256_context.update(data);
            Ok(Box::new(sha3_256_context.finalize().to_vec()))
        }

        consts::HASH_ALG_SHA256 => {
            let mut sha256_context = Sha256::new();
            sha256_context.input(data);
            Ok(Box::new(sha256_context.result().to_vec()))
        }

        consts::HASH_ALG_SHA512 => {
            let mut sha512_context = Sha512::new();
            sha512_context.input(data);
            Ok(Box::new(sha512_context.result().to_vec()))
        }

        consts::HASH_ALG_MD4 => {
            let mut md4_context = Md4::new();
            md4_context.update(data);
            Ok(Box::new(md4_context.finalize().to_vec()))
        }

        consts::HASH_ALG_MD5 => {
            Ok(Box::new(md5::compute(data).to_vec()))
        }

        consts::HASH_ALG_RIPEMD160 => {
            let mut ripemd160_context = Ripemd160::new();
            ripemd160_context.update(data);
            Ok(Box::new(ripemd160_context.finalize().to_vec()))
        }

        consts::HASH_ALG_BLAKE2B => {
            let mut hash = blake2b(digest_length, &[], data);
            Ok(Box::new(hash.as_bytes().to_vec()))
        }

        consts::HASH_ALG_BLAKE2S => {
            let mut hash = blake2s(digest_length, &[], data);
            Ok(Box::new(hash.as_bytes().to_vec()))
        }

        consts::HASH_ALG_SM3 => {
            let mut sm3_context = Sm3::new();
            sm3_context.input(data);
            Ok(Box::new(sm3_context.result().to_vec()))

        }

        consts::HASH_ALG_DOUBLE_SHA256 => {
            let mut sha256_context = Sha256::new();
            sha256_context.input(data);
            let sha256_hash = sha256_context.result();
            sha256_context = Sha256::new();
            sha256_context.input(sha256_hash);
            Ok(Box::new(sha256_context.result().to_vec()))
        }

        consts::HASH_ALG_HASH160 => {
            let mut sha256_context = Sha256::new();
            sha256_context.input(data);
            let sha256_hash = sha256_context.result();
            let mut ripemd160_context = Ripemd160::new();
            ripemd160_context.update(sha256_hash);
            Ok(Box::new(ripemd160_context.finalize().to_vec()))
        }

        consts::HASH_ALG_BLAKE256 => {
            let mut result = [0; 32];
            blake::hash(256, data, &mut result).unwrap();
            Ok(Box::new(result.to_vec()))
        }

        consts::HASH_ALG_BLAKE512 => {
            let mut result = [0; 64];
            blake::hash(512, data, &mut result).unwrap();
            Ok(Box::new(result.to_vec()))
        }

        consts::HASH_ALG_KECCAK256 => {
            let mut keccak256_context = Keccak256::new();
            keccak256_context.update(data);
            Ok(Box::new(keccak256_context.finalize().to_vec()))
        }

        consts::HASH_ALG_KECCAK256_RIPEMD160 => {
            let mut keccak256_context = Keccak256::new();
            keccak256_context.update(data);
            let keccak256_hash = keccak256_context.finalize();
            let mut ripemd160_context = Ripemd160::new();
            ripemd160_context.update(keccak256_hash);
            Ok(Box::new(ripemd160_context.finalize().to_vec()))
        }

        consts::HASH_ALG_SHA3_256_RIPEMD160 => {
            let mut sha3_256_context = Sha3_256::new();
            sha3_256_context.update(data);
            let sha3_256_hash = sha3_256_context.finalize();
            let mut ripemd160_context = Ripemd160::new();
            ripemd160_context.update(sha3_256_hash);
            Ok(Box::new(ripemd160_context.finalize().to_vec()))
        }

        consts::HASH_ALG_KECCAK512 => {
            let mut keccak512_context = Keccak512::new();
            keccak512_context.update(data);
            Ok(Box::new(keccak512_context.finalize().to_vec()))
        }

        consts::HASH_ALG_SHA3_512 => {
            let mut sha3_512_context = Sha3_512::new();
            sha3_512_context.update(data);
            Ok(Box::new(sha3_512_context.finalize().to_vec()))
        }


        _ => Err(consts::HASH_UNKNOWN_TYPE)
    }
}

pub fn hmac(key: & [u8], data: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    match type_choose {

        consts::HMAC_SHA256_ALG => {
            let hmac_result = HMAC_SHA256::mac(data, key);
            Ok(Box::new(hmac_result.to_vec()))
        }

        consts::HMAC_SHA512_ALG => {
            let hmac_result = HMAC_SHA512::mac(data, key);
            Ok(Box::new(hmac_result.to_vec()))
        }

        _ => Err(consts::HMAC_UNKNOWN_TYPE)
    }
}