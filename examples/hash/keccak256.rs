
#[cfg(test)]
mod tests {

    use owcrypt::{hash_set, consts};

    #[test]
    fn example() {
        let data = "1234".as_bytes();
        let digest = hash_set::hash(data, 0, consts::HASH_ALG_KECCAK256);

        if digest.is_ok() {
            println!("{:?}", digest.unwrap())
        } else {
            println!("failed with error code : {}", digest.unwrap_err())
        }
    }
}