extern crate libc;
pub mod consts;
pub mod hash_set;


#[cfg(test)]
mod hash_tests {

    use crate::{hash_set, consts};

    #[test]
    fn example() {

        let data = "1234".as_bytes();
        let digest = hash_set::hash(data, 10, consts::HASH_ALG_BLAKE2B);

        if digest.is_ok() {
            println!("{:?}", digest.unwrap())
        } else {
            println!("failed with error code : {}", digest.unwrap_err())
        }
    }
}



#[cfg(test)]
mod tests {

    extern {
        // uint16_ow ECC_get_curve_order(uint8_ow *order, uint32_ow type)
        fn ECC_get_curve_order(order: libc::uintptr_t, type_choose: libc::c_uint) -> libc::c_ushort;
    }

    #[test]
    fn example() {
        let order:[u8;32] = [0;32];
        unsafe {
            ECC_get_curve_order(order.as_ptr() as usize, 0xECC00000);
        }
        println!("{:?}", order);
    }
}

