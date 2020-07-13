use crate::ffi;
use crate::consts;
use libc::{
    uintptr_t,
    c_uint,
    c_uchar,
    c_ushort
};
use crate::consts::{ECC_PRIVATE_KEY_LENGTH_ERROR, ECC_MESSAGE_LENGTH_ERROR, ECC_MISS_ID};
use std::borrow::BorrowMut;

pub fn generate_public_key_from_private_key(private_key: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {

    if private_key.len() != 32 {
        Err(consts::ECC_PRIVATE_KEY_LENGTH_ERROR)
    } else {
        match type_choose {

            consts::ECC_CURVE_SECP256K1 | consts::ECC_CURVE_SECP256R1 | consts::ECC_CURVE_SM2_STANDARD | consts::ECC_CURVE_CURVE25519_SHA256 => {

                let public_key:[u8; 64] = [0; 64];
                let ret_code = unsafe {
                    ffi::ECC_genPubkey(private_key.as_ptr() as uintptr_t, public_key.as_ptr() as uintptr_t, type_choose as c_uint)
                };
                if ret_code as usize != consts::SUCCESS {
                    Err(ret_code as usize)
                } else {
                    Ok(Box::new(public_key.to_vec()))
                }
            }

            consts::ECC_CURVE_ED25519 | consts::ECC_CURVE_ED25519_NORMAL | consts::ECC_CURVE_X25519 => {
                let public_key:[u8; 32] = [0; 32];
                let ret_code = unsafe {
                    ffi::ECC_genPubkey(private_key.as_ptr() as uintptr_t, public_key.as_ptr() as uintptr_t, type_choose as c_uint)
                };
                if ret_code as usize != consts::SUCCESS {
                    Err(ret_code as usize)
                } else {
                    Ok(Box::new(public_key.to_vec()))
                }
            }
            _ => {Err(consts::ECC_UNKNOWN_TYPE)}
        }
     }

}

pub struct OW_signature {
    signature: [u8; 64],
    v        : u8
}

impl OW_signature {
    pub fn get_signature(&self) -> Box<Vec<u8>> {
        Box::new(self.signature.to_vec())
    }
    pub fn get_v(&self) -> Box<u8> {
        Box::new(self.v)
    }
}

pub fn sign(private_key: & [u8], id: & [u8], message: & [u8], type_choose: usize) -> Result<Box<OW_signature>, usize> {
    if private_key.len() != 32 {
        Err(ECC_PRIVATE_KEY_LENGTH_ERROR)
    } else if ((type_choose == consts::ECC_CURVE_SECP256K1 || type_choose == consts::ECC_CURVE_SECP256R1
        || type_choose == consts::ECC_CURVE_SM2_STANDARD || type_choose == consts::ECC_CURVE_CURVE25519_SHA256)
        && message.len() != 32) || message.len() == 0 {
        Err(ECC_MESSAGE_LENGTH_ERROR)
    } else if type_choose == consts::ECC_CURVE_SM2_STANDARD && id.len() == 0 {
        Err(ECC_MISS_ID)
    } else {
        let sig: [u8; 64] = [0; 64];
        let ret_v:u8 = 0;
        let ret_code = unsafe {
            ffi::ECC_sign(private_key.as_ptr() as uintptr_t,
                          id.as_ptr() as uintptr_t,
                          id.len() as c_ushort,
                          message.as_ptr() as usize,
                          32,
                          sig.as_ptr() as uintptr_t,
                          &ret_v as *const c_uchar as uintptr_t,
                          type_choose as c_uint)
        };

        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(OW_signature{ signature: sig, v: ret_v }))
        }
    }

}

pub fn verify(public_key: & [u8], id: & [u8], message: & [u8], signature: & [u8], type_choose: usize) -> bool {

        if (type_choose == consts::ECC_CURVE_SECP256K1 || type_choose == consts::ECC_CURVE_SECP256R1
            || type_choose == consts::ECC_CURVE_SM2_STANDARD || type_choose == consts::ECC_CURVE_CURVE25519_SHA256)
            && public_key.len() != 64 && message.len() != 32 {
            false
        } else if (type_choose == consts::ECC_CURVE_ED25519 || type_choose == consts::ECC_CURVE_ED25519_NORMAL
            || type_choose == consts::ECC_CURVE_X25519)
            && public_key.len() != 32 && message.len() == 0 {
            false
        } else if type_choose == consts::ECC_CURVE_SM2_STANDARD && id.len() == 0 {
            false
        } else if signature.len() != 64 {
            false
        } else {
            let ret_code = unsafe {
                ffi::ECC_verify(public_key.as_ptr() as uintptr_t,
                                id.as_ptr() as uintptr_t,
                                id.len() as c_ushort,
                                message.as_ptr() as usize,
                                32,
                                signature.as_ptr() as uintptr_t,
                                type_choose as c_uint)
            };
            if ret_code as usize == consts::SUCCESS {
                true
            } else {
                false
            }
        }
}

pub fn encrypt(public_key: & [u8], plain: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    if type_choose != consts::ECC_CURVE_SM2_STANDARD || public_key.len() != 64 || plain.len() == 0 {
        Err(consts::ECC_WRONG_TYPE)
    } else {
        let mut cipher:Vec<u8> = Vec::from(plain.clone());
        for _ in 0..97  {
            cipher.push(0);
        }

        let mut cipher_length: c_ushort = 0;

        let ret_code = unsafe {
            ffi::ECC_enc(public_key.as_ptr() as uintptr_t,
                         plain.as_ptr() as uintptr_t,
                         plain.len() as c_ushort,
                         cipher.as_slice().as_ptr() as uintptr_t,
                         &cipher_length as *const c_ushort as uintptr_t,
                         type_choose as c_uint)
        };
        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(cipher))
        }

    }
}

pub fn decrypt(private_key: & [u8], cipher : & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    if type_choose != consts::ECC_CURVE_SM2_STANDARD || private_key.len() != 32 || cipher.len() <= 97 {
        Err(consts::ECC_WRONG_TYPE)
    } else {
        let mut plain:Vec<u8> = Vec::from(cipher.clone());
        let mut plain_length: c_ushort = 0;

        let ret_code = unsafe {
            ffi::ECC_dec(private_key.as_ptr() as uintptr_t,
                         cipher.as_ptr() as uintptr_t,
                         cipher.len() as c_ushort,
                         plain.as_ptr() as uintptr_t,
                         &plain_length as *const c_ushort as uintptr_t,
                         type_choose as c_uint)
        };

        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(
                {
                    plain.split_off(cipher.len() - 97);
                    plain
                }
            )
            )
        }
    }
}


pub struct OW_ECKA_initiator_step1 {
    tmp_private_key: [u8;32],
    tmp_public_key : [u8; 64]
}

impl OW_ECKA_initiator_step1 {
    pub fn get_tmp_private_key(&self) -> Box<Vec<u8>> {
        Box::new(self.tmp_private_key.to_vec())
    }
    pub fn get_tmp_public_key(&self) -> Box<Vec<u8>> {
        Box::new(self.tmp_public_key.to_vec())
    }
}

pub fn ECKA_initiator_step1(type_choose: usize) -> Result<Box<OW_ECKA_initiator_step1>, usize> {
    if type_choose != consts::ECC_CURVE_SM2_STANDARD {
        Err(consts::ECC_WRONG_TYPE)
    } else {
        let tmp_private:[u8;32] = [0;32];
        let tmp_public:[u8;64] = [0;64];

        let ret_code = unsafe {
            ffi::ECC_key_exchange_initiator_step1(tmp_private.as_ptr() as uintptr_t, tmp_public.as_ptr() as uintptr_t, type_choose as c_uint)
        };

        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(OW_ECKA_initiator_step1{
                tmp_private_key: tmp_private,
                tmp_public_key:tmp_public
            }))
        }
    }
}

pub struct OW_ECKA_initiator_step2 {
    key: Vec<u8>,
    s  : [u8; 32]
}

impl OW_ECKA_initiator_step2 {
    pub fn get_key(&self) -> Box<Vec<u8>> {
        Box::new(self.key.to_vec())
    }
    pub fn get_s(&self) -> Box<Vec<u8>> {
        Box::new(self.s.to_vec())
    }
}

pub fn ECKA_initiator_step2(id_initiator: & [u8],
                            id_responder: & [u8],
                            private_key_initiator: & [u8],
                            public_key_initiator: & [u8],
                            public_key_responder: & [u8],
                            tmp_private_key_initiator: & [u8],
                            tmp_public_key_initiator: & [u8],
                            tmp_public_key_responder: & [u8],
                            s_in: & [u8],
                            key_length: u16,
                            type_choose: usize) -> Result<Box<OW_ECKA_initiator_step2>, usize> {
    if type_choose != consts::ECC_CURVE_SM2_STANDARD {
        Err(consts::ECC_WRONG_TYPE)
    } else if id_initiator.len() == 0 || id_responder.len() == 0 {
        Err(consts::ECC_MISS_ID)
    } else if private_key_initiator.len() != 32 || public_key_initiator.len() != 64 || public_key_responder.len() != 64
        || tmp_private_key_initiator.len() != 32 || tmp_public_key_initiator.len() != 64 || tmp_public_key_responder.len() != 64
        || s_in.len() != 32 || key_length == 0 {
        Err(consts::LENGTH_ERROR)
    } else {
        let mut result = Vec::new();
        result.resize(key_length as usize, 0);
        let checksum:[u8;32] = [0;32];

        let ret_code = unsafe {
            ffi::ECC_key_exchange_initiator_step2(id_initiator.as_ptr() as uintptr_t,
                                                  id_initiator.len() as c_ushort,
                                                  id_responder.as_ptr() as uintptr_t,
                                                  id_responder.len() as c_ushort,
                                                  private_key_initiator.as_ptr() as uintptr_t,
                                                  public_key_initiator.as_ptr() as uintptr_t,
                                                  tmp_private_key_initiator.as_ptr() as uintptr_t,
                                                  tmp_public_key_initiator.as_ptr() as uintptr_t,
                                                  tmp_public_key_responder.as_ptr() as uintptr_t,
                                                  s_in.as_ptr() as uintptr_t,
                                                  checksum.as_ptr() as uintptr_t,
                                                  key_length as c_ushort,
                                                  result.as_slice().as_ptr() as uintptr_t,
                                                  type_choose as c_uint
            )
        };
        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(OW_ECKA_initiator_step2{ key: result, s: checksum }))
        }
    }
}


pub struct OW_ECKA_responder_step1 {
    key: Vec<u8>,
    tmp_public_key:[u8;64],
    s_inner:[u8;32],
    s_outer:[u8;32]
}

impl OW_ECKA_responder_step1 {
    pub fn get_key(&self) -> Box<Vec<u8>> {
        Box::new(self.key.to_vec())
    }
    pub fn get_tmp_public_key(&self) -> Box<Vec<u8>> {
        Box::new(self.tmp_public_key.to_vec())
    }
    pub fn get_s_inner(&self) -> Box<Vec<u8>> {
        Box::new(self.s_inner.to_vec())
    }
    pub fn get_s_outer(&self) -> Box<Vec<u8>> {
        Box::new(self.s_outer.to_vec())
    }
}

pub fn ECKA_responder_step1(id_initiator: & [u8],
                            id_responder: & [u8],
                            private_key_responder: & [u8],
                            public_key_responder: & [u8],
                            public_key_initiator: & [u8],
                            tmp_public_key_initiator: & [u8],
                            key_length: u16,
                            type_choose: usize) -> Result<Box<OW_ECKA_responder_step1>, usize> {
    if type_choose != consts::ECC_CURVE_SM2_STANDARD {
        Err(consts::ECC_WRONG_TYPE)
    } else if id_initiator.len() == 0 || id_responder.len() == 0 {
        Err(consts::ECC_MISS_ID)
    } else if private_key_responder.len() != 32 || public_key_responder.len() != 64 || public_key_initiator.len() != 64 || tmp_public_key_initiator.len() != 64 || key_length == 0 {
        Err(consts::LENGTH_ERROR)
    } else {
        let mut result = Vec::new();
        result.resize(key_length as usize, 0);
        let tmp_public:[u8;64] = [0;64];
        let checksum_in:[u8;32] = [0;32];
        let checksum_out:[u8;32] = [0;32];

        let ret_code = unsafe {
            ffi::ECC_key_exchange_responder_step1(id_initiator.as_ptr() as uintptr_t,
                                                  id_initiator.len() as c_ushort,
                                                  id_responder.as_ptr() as uintptr_t,
                                                  id_responder.len() as c_ushort,
                                                  private_key_responder.as_ptr() as uintptr_t,
                                                  public_key_responder.as_ptr() as uintptr_t,
                                                  public_key_initiator.as_ptr() as uintptr_t,
                                                  tmp_public.as_ptr() as uintptr_t,
                                                  tmp_public_key_initiator.as_ptr() as uintptr_t,
                                                  checksum_in.as_ptr() as uintptr_t,
                                                  checksum_out.as_ptr() as uintptr_t,
                                                  key_length as c_ushort,
                                                  result.as_slice().as_ptr() as uintptr_t,
                                                  type_choose as c_uint)
        };
        
        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(OW_ECKA_responder_step1{
                key: result,
                tmp_public_key: tmp_public,
                s_inner: checksum_in,
                s_outer: checksum_out
            }))
        }
    }
}

pub fn ECKA_responder_ElGamal_step1(id_initiator: & [u8],
                            id_responder: & [u8],
                            private_key_responder: & [u8],
                            public_key_responder: & [u8],
                            public_key_initiator: & [u8],
                            tmp_public_key_initiator: & [u8],
                            key_length: u16,
                            random: & [u8],
                            type_choose: usize) -> Result<Box<OW_ECKA_responder_step1>, usize> {
    if type_choose != consts::ECC_CURVE_SM2_STANDARD {
        Err(consts::ECC_WRONG_TYPE)
    } else if id_initiator.len() == 0 || id_responder.len() == 0 {
        Err(consts::ECC_MISS_ID)
    } else if private_key_responder.len() != 32 || public_key_responder.len() != 64
        || public_key_initiator.len() != 64 || tmp_public_key_initiator.len() != 64
        || key_length == 0 || random.len() != 32 {
        Err(consts::LENGTH_ERROR)
    } else {
        let mut result = Vec::new();
        result.resize(key_length as usize, 0);
        let tmp_public:[u8;64] = [0;64];
        let checksum_in:[u8;32] = [0;32];
        let checksum_out:[u8;32] = [0;32];

        let ret_code = unsafe {
            ffi::ECC_key_exchange_responder_ElGamal_step1(id_initiator.as_ptr() as uintptr_t,
                                                  id_initiator.len() as c_ushort,
                                                  id_responder.as_ptr() as uintptr_t,
                                                  id_responder.len() as c_ushort,
                                                  private_key_responder.as_ptr() as uintptr_t,
                                                  public_key_responder.as_ptr() as uintptr_t,
                                                  public_key_initiator.as_ptr() as uintptr_t,
                                                  tmp_public.as_ptr() as uintptr_t,
                                                  tmp_public_key_initiator.as_ptr() as uintptr_t,
                                                  checksum_in.as_ptr() as uintptr_t,
                                                  checksum_out.as_ptr() as uintptr_t,
                                                  key_length as c_ushort,
                                                  result.as_slice().as_ptr() as uintptr_t,
                                                  random.as_ptr() as uintptr_t,
                                                  type_choose as c_uint)
        };

        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(OW_ECKA_responder_step1{
                key: result,
                tmp_public_key: tmp_public,
                s_inner: checksum_in,
                s_outer: checksum_out
            }))
        }
    }
}

pub fn ECKA_responder_step2(s_initiator: & [u8], s_responder: & [u8], type_choose: usize) -> bool{
    if type_choose != consts::ECC_CURVE_SM2_STANDARD {
        false
    } else if s_initiator.len() != 32 || s_responder.len() != 32 {
        false
    } else {
        let ret_code = unsafe {
            ffi::ECC_key_exchange_responder_step2(s_initiator.as_ptr() as uintptr_t,s_responder.as_ptr() as uintptr_t, type_choose as c_uint)
        };

        if ret_code as usize != consts::SUCCESS {
            false
        } else {
            true
        }
    }
}

pub fn point_multiply_G(scalar: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    if scalar.len() != 32 {
        Err(consts::LENGTH_ERROR)
    } else {
        match type_choose {
            consts::ECC_CURVE_SECP256K1 | consts::ECC_CURVE_SECP256R1 => {
                let point:[u8; 64] = [0; 64];
                let point_result:[u8;33] = [0; 33];
                let ret_code = unsafe {
                    ffi::ECC_point_mul_baseG(scalar.as_ptr() as uintptr_t, point.as_ptr() as uintptr_t, type_choose as c_uint)
                };

                if ret_code as usize != consts::SUCCESS {
                    Err(ret_code as usize)
                } else {
                    let ret_code = unsafe {
                        ffi::ECC_point_compress(point.as_ptr() as uintptr_t, 64, point_result.as_ptr() as uintptr_t, type_choose as c_uint)
                    };
                    if ret_code as usize != consts::SUCCESS {
                        Err(ret_code as usize)
                    } else {
                        Ok(Box::new(point_result.to_vec()))
                    }
                }
            }

            consts::ECC_CURVE_ED25519 => {
                let point:[u8;32] = [0;32];
                let ret_code = unsafe {
                    ffi::ECC_point_mul_baseG(scalar.as_ptr() as uintptr_t, point.as_ptr() as uintptr_t, type_choose as c_uint)
                };
                if ret_code as usize != consts::SUCCESS {
                    Err(ret_code as usize)
                } else {
                    Ok(Box::new(point.to_vec()))
                }
            }
            _ => Err(consts::ECC_WRONG_TYPE)
        }
    }
}

pub fn point_multiply_G_add(point_in: & [u8], scalar: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    if scalar.len() != 32 {
        Err(consts::LENGTH_ERROR)
    } else {
        match type_choose {
            consts::ECC_CURVE_SECP256K1 | consts::ECC_CURVE_SECP256R1 => {
                if point_in.len() != 64 {
                    Err(consts::LENGTH_ERROR)
                } else {
                    let point_out:[u8; 64] = [0; 64];
                    let ret_code = unsafe {
                        ffi::ECC_point_mul_baseG_add(point_in.as_ptr() as uintptr_t, scalar.as_ptr() as uintptr_t, point_out.as_ptr() as uintptr_t, type_choose as c_uint)
                    };
                    if ret_code as usize != consts::SUCCESS {
                        Err(ret_code as usize)
                    } else {
                        Ok(Box::new(point_out.to_vec()))
                    }
                }
            }
            consts::ECC_CURVE_ED25519 => {
                if point_in.len() != 32 {
                    Err(consts::LENGTH_ERROR)
                } else {
                    let point_out:[u8; 32] = [0; 32];
                    let ret_code = unsafe {
                        ffi::ECC_point_mul_baseG_add(point_in.as_ptr() as uintptr_t, scalar.as_ptr() as uintptr_t, point_out.as_ptr() as uintptr_t, type_choose as c_uint)
                    };
                    if ret_code as usize != consts::SUCCESS {
                        Err(ret_code as usize)
                    } else {
                        Ok(Box::new(point_out.to_vec()))
                    }
                }
            }
            _ => Err(consts::ECC_WRONG_TYPE)
        }
    }
}

pub fn point_compress(point: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    if point.len() != 64 || point.len() != 65 {
        Err(consts::LENGTH_ERROR)
    } else {
        if type_choose != consts::ECC_CURVE_SECP256R1 || type_choose != consts::ECC_CURVE_SECP256K1 || type_choose != consts::ECC_CURVE_SM2_STANDARD {
            Err(consts::ECC_WRONG_TYPE)
        } else {
            let point_out:[u8; 33] = [0; 33];
            let ret_code = unsafe {
                ffi::ECC_point_compress(point.as_ptr() as uintptr_t, point.len() as c_ushort, point_out.as_ptr() as uintptr_t, type_choose as c_uint)
            };
            if ret_code as usize != consts::SUCCESS {
                Err(ret_code as usize)
            } else {
                Ok(Box::new(point_out.to_vec()))
            }
        }
    }
}

pub fn point_decompress(point: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    if point.len() != 33 {
        Err(consts::LENGTH_ERROR)
    } else {
        if type_choose != consts::ECC_CURVE_SECP256R1 || type_choose != consts::ECC_CURVE_SECP256K1 || type_choose != consts::ECC_CURVE_SM2_STANDARD {
            Err(consts::ECC_WRONG_TYPE)
        } else {
            let point_out:[u8; 65] = [0; 65];
            let ret_code = unsafe {
                ffi::ECC_point_decompress(point.as_ptr() as uintptr_t, point.len() as c_ushort, point_out.as_ptr() as uintptr_t, type_choose as c_uint)
            };
            if ret_code as usize != consts::SUCCESS {
                Err(ret_code as usize)
            } else {
                Ok(Box::new(point_out.to_vec()))
            }
        }
    }
}

pub fn public_key_recover(signature: & [u8], message: & [u8], type_choose: usize) -> Result<Box<Vec<u8>>, usize> {
    if signature.len() != 65 || message.len() != 32 {
        Err(consts::LENGTH_ERROR)
    } else {
        if type_choose != consts::ECC_CURVE_SECP256R1 || type_choose != consts::ECC_CURVE_SECP256K1 {
            Err(consts::ECC_WRONG_TYPE)
        } else {
            let public_key:[u8; 64] = [0; 64];
            let ret_code = unsafe {
                ffi::ECC_recover_pubkey(signature.as_ptr() as uintptr_t,
                                        signature.len() as c_ushort,
                                        message.as_ptr() as uintptr_t,
                                        message.len() as c_ushort,
                                        public_key.as_ptr() as uintptr_t,
                                        type_choose as c_uint)
            };

            if ret_code as usize != consts::SUCCESS {
                Err(ret_code as usize)
            } else {
                Ok(Box::new(public_key.to_vec()))
            }
        }
    }
}

pub fn curve25519_x_to_ed(x: & [u8]) -> Result<Box<Vec<u8>>, usize> {
    if x.len() != 32 {
        Err(consts::LENGTH_ERROR)
    } else {
        let ed:[u8;32] = [0;32];
        let ret_code = unsafe {
            ffi::CURVE25519_convert_X_to_Ed(ed.as_ptr() as uintptr_t, x.as_ptr() as uintptr_t)
        };
        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(ed.to_vec()))
        }
    }
}

pub fn curve25519_ed_to_x(ed: & [u8]) -> Result<Box<Vec<u8>>, usize> {
    if ed.len() != 32 {
        Err(consts::LENGTH_ERROR)
    } else {
        let x:[u8;32] = [0;32];
        let ret_code = unsafe {
            ffi::CURVE25519_convert_Ed_to_X(x.as_ptr() as uintptr_t, ed.as_ptr() as uintptr_t)
        };
        if ret_code as usize != consts::SUCCESS {
            Err(ret_code as usize)
        } else {
            Ok(Box::new(x.to_vec()))
        }
    }
}