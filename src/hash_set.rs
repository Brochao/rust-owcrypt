use crate::consts;
use crate::ffi;

use libc::{
    uintptr_t,
    c_uint,
    c_uchar,
    c_ushort
};



// use sha1;
// use sha2::{Sha256,Sha512, Digest as Sha2Digest};
// use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512, Keccak256, Keccak512};
// use md4::Md4;
// use md5;
// use ripemd160::Ripemd160;

#[allow(unused_imports)]
use blake2_rfc::blake2b::blake2b;
use blake2_rfc::blake2s::blake2s;

#[allow(unused_imports)]
//use blake::Blake;

// use sm3::Sm3;
#[allow(unused_imports)]
// use sha2::digest::Reset;

// use hmac_sha256::{HMAC as HMAC_SHA256};
// use hmac_sha512::{HMAC as HMAC_SHA512};



#[allow(unused_variables)]
#[allow(unused_mut)]
pub fn hash(data: & [u8], digest_length: usize, type_choose: usize) -> Result<Box<Vec<u8>>, usize> {

    if (type_choose == consts::HASH_ALG_BLAKE2B || type_choose == consts::HASH_ALG_BLAKE2S) && digest_length == 0 {
        Err(consts::LENGTH_ERROR)
    } else {
        match type_choose {

            consts::HASH_ALG_MD4 |consts::HASH_ALG_MD5 => {
                let digest:[u8; 16] = [0; 16];
                unsafe {
                  ffi::hash(data.as_ptr() as uintptr_t, data.len() as c_ushort, digest.as_ptr() as uintptr_t, 0, type_choose as c_uint)
                };

                Ok(Box::new(digest.to_vec()))

            }

            consts::HASH_ALG_SHA1 | consts::HASH_ALG_RIPEMD160 | consts::HASH_ALG_SHA3_256_RIPEMD160 | consts::HASH_ALG_KECCAK256_RIPEMD160 | consts::HASH_ALG_HASH160 => {
                let digest:[u8; 20] = [0; 20];
                unsafe {
                    ffi::hash(data.as_ptr() as uintptr_t, data.len() as c_ushort, digest.as_ptr() as uintptr_t, 0, type_choose as c_uint)
                };

                Ok(Box::new(digest.to_vec()))

            }

            consts::HASH_ALG_SHA3_256 | consts::HASH_ALG_SHA256 | consts::HASH_ALG_KECCAK256 | consts::HASH_ALG_SM3 | consts::HASH_ALG_DOUBLE_SHA256 | consts::HASH_ALG_BLAKE256 => {
                let digest:[u8; 32] = [0; 32];
                unsafe {
                    ffi::hash(data.as_ptr() as uintptr_t, data.len() as c_ushort, digest.as_ptr() as uintptr_t, 0, type_choose as c_uint)
                };

                Ok(Box::new(digest.to_vec()))
            }

            consts::HASH_ALG_SHA512 | consts::HASH_ALG_SHA3_512 | consts::HASH_ALG_KECCAK512 | consts::HASH_ALG_BLAKE512 => {
                let digest:[u8; 64] = [0; 64];
                unsafe {
                    ffi::hash(data.as_ptr() as uintptr_t, data.len() as c_ushort, digest.as_ptr() as uintptr_t, 0, type_choose as c_uint)
                };

                Ok(Box::new(digest.to_vec()))
            }



            consts::HASH_ALG_BLAKE2B => {
                let mut hash = blake2b(digest_length, &[], data);
                Ok(Box::new(hash.as_bytes().to_vec()))
            }

            consts::HASH_ALG_BLAKE2S => {
                let mut hash = blake2s(digest_length, &[], data);
                Ok(Box::new(hash.as_bytes().to_vec()))
            }

            _ => Err(consts::HASH_UNKNOWN_TYPE)
        }
    }

}

// pub fn hmac(key: & [u8], data: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
//     match type_choose {
//
//         consts::HMAC_SHA256_ALG => {
//             let hmac_result = HMAC_SHA256::mac(data, key);
//             Ok(Box::new(hmac_result.to_vec()))
//         }
//
//         consts::HMAC_SHA512_ALG => {
//             let hmac_result = HMAC_SHA512::mac(data, key);
//             Ok(Box::new(hmac_result.to_vec()))
//         }
//
//         _ => Err(consts::HMAC_UNKNOWN_TYPE)
//     }
// }