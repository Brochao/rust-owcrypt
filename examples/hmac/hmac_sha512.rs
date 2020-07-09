
#[cfg(test)]
mod tests {
    use owcrypt::{hash_set, consts};

    #[test]
    fn example() {
        let data = "1234".as_bytes();
        let key = "testkey".as_bytes();
        let digest = hash_set::hmac(key, data, consts::HMAC_SHA512_ALG);

        if digest.is_ok() {
            println!("{:?}", digest.unwrap())
        } else {
            println!("failed with error code : {}", digest.unwrap_err())
        }
    }
}
