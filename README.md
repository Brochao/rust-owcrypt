# owcrypt

A Rust version for BlockTree's owcrypt library

[golang version](https://github.com/blocktree/go-owcrypt)
[c version](https://github.com/blocktree/owcrypt)

## Using owcrypt

### Hash

```rust
use owcrypt::{hash_set, consts};

fn main() {
        let data = "1234".as_bytes();
        let digest = hash_set::hash(data, 10, consts::HASH_ALG_BLAKE2B);

        if digest.is_ok() {
            println!("{:?}", digest.unwrap())
        } else {
            println!("failed with error code : {}", digest.unwrap_err())
        }
}
```

### Hmac
```rust
use owcrypt::{hash_set, consts};

fn main() {
        let data = "1234".as_bytes();
        let key = "testkey".as_bytes();
        let digest = hash_set::hmac(key, data, consts::HMAC_SHA256_ALG);

        if digest.is_ok() {
            println!("{:?}", digest.unwrap())
        } else {
            println!("failed with error code : {}", digest.unwrap_err())
        }
}
```

### Generate public key from private key
```rust
use owcrypt::{ecc_set, consts};

fn main() {
        let private_key:[u8;32] = [115,247,83,241,135,33,66,130,184,16,175,201,202,56,254,44,149,145,55,9,183,223,53,199,148,139,213,41,82,111,244,144];

        let public_key = ecc_set::generate_public_key_from_private_key(&private_key, consts::ECC_CURVE_ED25519_NORMAL);

        if public_key.is_ok() {
            println!("{:?}",public_key.unwrap())
        } else {
            println!("failed with err code : {:?}",public_key.err())
        }
}
```

### Sign
```rust
use owcrypt::{ecc_set, consts};

fn main() {
        let private_key:[u8;32] = [115,247,83,241,135,33,66,130,184,16,175,201,202,56,254,44,149,145,55,9,183,223,53,199,148,139,213,41,82,111,244,144];
        let message:[u8; 32] = [115,247,83,241,135,33,66,130,184,16,175,201,202,56,254,44,149,145,55,9,183,223,53,199,148,139,213,41,82,111,244,144];
        let id:[u8; 0] = [];
        let signature_result = ecc_set::sign(&private_key, &id, &message, consts::ECC_CURVE_SECP256K1);
        if signature_result.is_ok() {
            let signature = signature_result.unwrap();
            println!("signature : {:?}",signature.get_signature());
            println!("v         : {}", signature.get_v())
        } else {
            println!("failed with err code : {:?}",signature_result.err())
        }
}
```

### Verify

```rust
use owcrypt::{ecc_set, consts};

fn main() {
        let public_key:[u8;64] = [178,55,113,109,53,3,33,108,112,75,5,0,150,16,23,206,244,154,54,181,179,39,236,41,150,187,180,199,246,76,115,126,169,85,20,242,202,85,39,60,236,24,88,176,183,205,107,238,54,14,176,232,125,131,20,215,99,29,26,244,129,104,43,1];
        let message:[u8; 32] = [115,247,83,241,135,33,66,130,184,16,175,201,202,56,254,44,149,145,55,9,183,223,53,199,148,139,213,41,82,111,244,144];
        let id:[u8; 0] = [];
        let signature:[u8;64] = [19,145,178,250,96,237,214,62,25,9,220,156,200,40,109,29,154,30,233,15,62,156,68,27,209,140,207,49,92,224,45,159,95,212,51,187,203,55,49,145,106,207,46,253,67,75,86,240,146,111,33,168,213,76,35,213,104,2,211,31,146,89,25,187];

        let result = ecc_set::verify(&public_key, &id, &message, &signature, consts::ECC_CURVE_SECP256K1);

        println!("{}", result)
}
```

### Encrypt
```rust
use owcrypt::{ecc_set, consts};

fn main() {
        let public_key:[u8; 64] = [190,103,219,79,194,17,69,124,250,72,231,23,233,194,146,44,152,250,245,187,145,24,63,244,44,95,190,249,74,109,116,66,116,164,229,85,42,151,147,78,198,148,221,31,115,46,172,120,40,197,24,156,29,163,219,14,67,189,77,162,101,24,202,127];
        let plain:[u8;32] = [115,247,83,241,135,33,66,130,184,16,175,201,202,56,254,44,149,145,55,9,183,223,53,199,148,139,213,41,82,111,244,144];

        let cipher = ecc_set::encrypt(&public_key, &plain, consts::ECC_CURVE_SM2_STANDARD);

        if cipher.is_ok() {
            println!("{:?}", cipher.unwrap().to_vec())
        } else {
            println!("{:?}", cipher.err());
        }
}
```

### Decrypt
```rust
use owcrypt::{ecc_set, consts};

fn main() {
        let private_key:[u8; 32] = [115,247,83,241,135,33,66,130,184,16,175,201,202,56,254,44,149,145,55,9,183,223,53,199,148,139,213,41,82,111,244,144];
        let cipher:[u8;129] = [4, 20, 79, 73, 111, 102, 39, 62, 121, 208, 112, 88, 183, 42, 139, 50, 99, 34, 240, 221, 63, 32, 126, 221, 204, 179, 174, 140, 111, 224, 40, 236, 48, 3, 34, 176, 76, 244, 36, 176, 113, 217, 195, 61, 155, 194, 159, 252, 69, 219, 137, 135, 105, 20, 129, 31, 201, 229, 77, 150, 76, 90, 102, 225, 4, 28, 42, 73, 246, 93, 53, 243, 164, 98, 67, 149, 40, 83, 2, 98, 24, 38, 198, 155, 208, 191, 225, 194, 154, 197, 124, 93, 102, 235, 66, 9, 101, 188, 178, 178, 152, 42, 107, 88, 20, 84, 209, 124, 11, 36, 80, 33, 210, 229, 255, 160, 138, 4, 172, 233, 126, 253, 155, 237, 232, 47, 198, 238, 164];

        let plain = ecc_set::decrypt(&private_key, &cipher, consts::ECC_CURVE_SM2_STANDARD);

        if plain.is_ok() {
            println!("{:?}", plain.unwrap().to_vec())
        } else {
            println!("{:?}", plain.err());
        }
}
```
