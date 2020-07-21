extern crate cc;

#[allow(dead_code)]
#[allow(unused_variables)]
fn main() {
    let mut clib_config = cc::Build::new();
    // clib_config.include("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include");
    clib_config.include("src/c-owcrypt/bignum");
    clib_config.file("src/c-owcrypt/bignum/bignum.c")
        .file("src/c-owcrypt/bignum/bigrand.c");

    clib_config.include("src/c-owcrypt/crypto");
    clib_config.file("src/c-owcrypt/crypto/ecc_set.c")
        .file("src/c-owcrypt/crypto/hash_set.c");

    clib_config .include("src/c-owcrypt/ecc_drv");
    clib_config.file("src/c-owcrypt/ecc_drv/CURVE25519.c")
        .file("src/c-owcrypt/ecc_drv/ecc_drv.c")
        .file("src/c-owcrypt/ecc_drv/ECDSA.c")
        .file("src/c-owcrypt/ecc_drv/secp256k1.c")
        .file("src/c-owcrypt/ecc_drv/secp256r1.c")
        .file("src/c-owcrypt/ecc_drv/sm2.c");

    clib_config .include("src/c-owcrypt/hash_drv");
    clib_config.file("src/c-owcrypt/hash_drv/blake2b.c")
        .file("src/c-owcrypt/hash_drv/blake2s.c")
        .file("src/c-owcrypt/hash_drv/blake256.c")
        .file("src/c-owcrypt/hash_drv/blake512.c")
        .file("src/c-owcrypt/hash_drv/hmac.c")
        .file("src/c-owcrypt/hash_drv/keccak256.c")
        .file("src/c-owcrypt/hash_drv/keccak512.c")
        .file("src/c-owcrypt/hash_drv/md4.c")
        .file("src/c-owcrypt/hash_drv/md5.c")
        .file("src/c-owcrypt/hash_drv/pbkdf2.c")
        .file("src/c-owcrypt/hash_drv/ripemd160.c")
        .file("src/c-owcrypt/hash_drv/sha1.c")
        .file("src/c-owcrypt/hash_drv/sha3_256.c")
        .file("src/c-owcrypt/hash_drv/sha3_512.c")
        .file("src/c-owcrypt/hash_drv/sha256.c")
        .file("src/c-owcrypt/hash_drv/sha512.c")
        .file("src/c-owcrypt/hash_drv/sm3.c");

    clib_config .include("src/c-owcrypt/owcrypt_core");
    clib_config.file("src/c-owcrypt/owcrypt_core/owc_algorithm.c")
        .file("src/c-owcrypt/owcrypt_core/owc_alloc.c")
        .file("src/c-owcrypt/owcrypt_core/owc_core.c")
        .file("src/c-owcrypt/owcrypt_core/owc_curve.c")
        .file("src/c-owcrypt/owcrypt_core/owc_montgamery.c");
    #[allow(unused_variables)]
        clib_config.compile("libowcrypt.a")
}