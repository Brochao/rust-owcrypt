
use libc::{
    uintptr_t,
    c_uint,
    c_ushort
};


#[link(name = "owcrypt")]
extern {
    pub(crate) fn ECC_genPubkey(private_key: uintptr_t,public_key:uintptr_t, type_choose: c_uint) -> c_ushort;
    pub(crate) fn ECC_sign(private_key: uintptr_t, id: uintptr_t, id_length: c_ushort, message: uintptr_t, message_length: c_ushort, signature: uintptr_t, type_choose: c_uint) -> c_ushort;
    pub(crate) fn ECC_verify(public_key: uintptr_t, id: uintptr_t, id_length: c_ushort, message: uintptr_t, message_length: c_ushort, signature: uintptr_t, type_choose: c_uint) -> c_ushort;
    pub(crate) fn ECC_enc(public_key: uintptr_t, plain: uintptr_t, plain_length: c_ushort, cipher: uintptr_t, cipher_length: uintptr_t, type_choose: c_uint) -> c_ushort;
    pub(crate) fn ECC_dec(private_key: uintptr_t, cipher: uintptr_t, cipher_length: c_ushort, plain: uintptr_t, plain_length: uintptr_t, type_choose: c_uint) -> c_ushort;


    pub(crate) fn ECC_key_exchange_initiator_step1(tmp_pri_initiator: uintptr_t, tmp_pub_initiator: uintptr_t, type_choose: c_uint) -> c_ushort;
    pub(crate) fn ECC_key_exchange_initiator_step2(id_initiator: uintptr_t,
                                                   id_initiator_length: c_ushort,
                                                   id_responder: uintptr_t,
                                                   id_responder_length: c_ushort,
                                                   pri_initiator: uintptr_t,
                                                   pub_initiator: uintptr_t,
                                                   tmp_pri_initiator: uintptr_t,
                                                   tmp_pub_initiator: uintptr_t,
                                                   tmp_pub_responder: uintptr_t,
                                                   s_in: uintptr_t,
                                                   s_out: uintptr_t,
                                                   key_length: c_ushort,
                                                   key: uintptr_t,
                                                   type_choose: c_uint) -> c_ushort;
    pub(crate) fn ECC_key_exchange_responder_step1(id_initiator: uintptr_t,
                                                   id_initiator_length: c_ushort,
                                                   id_responder: uintptr_t,
                                                   id_responder_length: c_ushort,
                                                   pri_responder: uintptr_t,
                                                   pub_responder: uintptr_t,
                                                   pub_initiator: uintptr_t,
                                                   tmp_pub_responder: uintptr_t,
                                                   tmp_pub_initiator: uintptr_t,
                                                   s_in: uintptr_t,
                                                   s_out: uintptr_t,
                                                   key_length: c_ushort,
                                                   key: uintptr_t,
                                                   type_choose: c_uint) -> c_ushort;

    pub(crate) fn ECC_key_exchange_responder_ElGamal_step1(id_initiator: uintptr_t,
                                                           id_initiator_length: c_ushort,
                                                           id_responder: uintptr_t,
                                                           id_responder_length: c_ushort,
                                                           pri_responder: uintptr_t,
                                                           pub_responder: uintptr_t,
                                                           pub_initiator: uintptr_t,
                                                           tmp_pub_responder: uintptr_t,
                                                           tmp_pub_initiator: uintptr_t,
                                                           s_in: uintptr_t,
                                                           s_out: uintptr_t,
                                                           key_length: c_ushort,
                                                           key: uintptr_t,
                                                           random: uintptr_t,
                                                           type_choose: c_uint) -> c_ushort;
    pub(crate) fn ECC_key_exchange_responder_step2(s_initiator: uintptr_t, s_responder: uintptr_t, type_choose: c_uint) -> c_ushort;



    pub(crate) fn ECC_get_curve_order(order: uintptr_t, type_choose: c_uint) -> c_ushort;
}