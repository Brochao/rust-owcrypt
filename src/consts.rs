pub const SUCCESS           : usize = 0x0001;
pub const FAILURE           : usize = 0x0000;
pub const ECC_PRIKEY_ILLEGAL: usize = 0xE000;
pub const ECC_PUBKEY_ILLEGAL: usize = 0xE001;
pub const ECC_WRONG_TYPE    : usize = 0xE002;
pub const ECC_MISS_ID       : usize = 0xE003;
pub const RAND_IS_NULL      : usize = 0xE004;
pub const LENGTH_ERROR      : usize = 0xE005;
pub const POINT_AT_INFINITY : usize = 0xE006;
pub const MESSAGE_ILLEGAL   : usize = 0xE007;

pub const HASH_UNKNOWN_TYPE : usize = 0xE008;
pub const HMAC_UNKNOWN_TYPE : usize = 0xE009;
pub const ECC_PRIVATE_KEY_LENGTH_ERROR :usize = 0xE00A;
pub const ECC_MESSAGE_LENGTH_ERROR :usize = 0xE00B;
pub const ECC_UNKNOWN_TYPE  :usize = 0xE00C;

pub const HASH_ALG_SHA1               : usize = 0xA0000000;
pub const HASH_ALG_SHA3_256           : usize = 0xA0000001;
pub const HASH_ALG_SHA256             : usize = 0xA0000002;
pub const HASH_ALG_SHA512             : usize = 0xA0000003;
pub const HASH_ALG_MD4                : usize = 0xA0000004;
pub const HASH_ALG_MD5                : usize = 0xA0000005;
pub const HASH_ALG_RIPEMD160          : usize = 0xA0000006;
pub const HASH_ALG_BLAKE2B            : usize = 0xA0000007;
pub const HASH_ALG_BLAKE2S            : usize = 0xA0000008;
pub const HASH_ALG_SM3                : usize = 0xA0000009;
pub const HASH_ALG_DOUBLE_SHA256      : usize = 0xA000000A;
pub const HASH_ALG_HASH160            : usize = 0xA000000B;
pub const HASH_ALG_BLAKE256           : usize = 0xA000000C;
pub const HASH_ALG_BLAKE512           : usize = 0xA000000D;
pub const HASH_ALG_KECCAK256          : usize = 0xA000000E;
pub const HASH_ALG_KECCAK256_RIPEMD160: usize = 0xA000000F;
pub const HASH_ALG_SHA3_256_RIPEMD160 : usize = 0xA0000010;
pub const HASH_ALG_KECCAK512          : usize = 0xA0000011;
pub const HASH_ALG_SHA3_512           : usize = 0xA0000012;

pub const HMAC_SHA256_ALG    : usize = 0x50505050;
pub const HMAC_SHA512_ALG    : usize = 0x50505051;


pub const ECC_CURVE_SECP256K1         : usize = 0xECC00000;
pub const ECC_CURVE_SECP256R1         : usize = 0xECC00001;
pub const ECC_CURVE_PRIMEV1           : usize = ECC_CURVE_SECP256R1;
pub const ECC_CURVE_NIST_P256         : usize = ECC_CURVE_SECP256R1;
pub const ECC_CURVE_SM2_STANDARD      : usize = 0xECC00002;
pub const ECC_CURVE_ED25519_NORMAL    : usize = 0xECC00003;
pub const ECC_CURVE_ED25519           : usize = 0xECC00004;
pub const ECC_CURVE_X25519            : usize = 0xECC00005;
pub const ECC_CURVE_CURVE25519_SHA256 : usize = 0xECC00006;