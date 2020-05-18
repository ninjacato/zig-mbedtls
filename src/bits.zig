pub const MBEDTLS_ERR_PK_ALLOC_FAILED               = -0x3F80;
pub const MBEDTLS_ERR_PK_BAD_INPUT_DATA             = -0x3E80;
pub const MBEDTLS_ERR_PK_FILE_IO_ERROR              = -0x3E00;

pub const MBEDTLS_ERR_ERROR_GENERIC_ERROR           = -0x0001;
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED     = -0x006E;

pub const MBEDTLS_ERR_AES_BAD_INPUT_DATA            = -0x0021;
pub const MBEDTLS_ERR_AES_INVALID_KEY_LENGTH        = -0x0020;
pub const MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH      = -0x0022;

pub const MBEDTLS_ERR_NET_UNKNOWN_HOST              = -0x0052;
pub const MBEDTLS_ERR_NET_SOCKET_FAILED             = -0x0042;
pub const MBEDTLS_ERR_NET_CONNECT_FAILED            = -0x0044;
pub const MBEDTLS_ERR_NET_INVALID_CONTEXT           = -0x0045;
pub const MBEDTLS_ERR_NET_CONN_RESET                = -0x0050;
pub const MBEDTLS_ERR_NET_SEND_FAILED               = -0x004E;

pub const MBEDTLS_ERR_MPI_BAD_INPUT_DATA            = -0x0004;

pub const MBEDTLS_SSL_VERIFY_NONE                   = 0;
pub const MBEDTLS_SSL_VERIFY_OPTIONAL               = 1;
pub const MBEDTLS_SSL_VERIFY_REQUIRED               = 2;

pub const MBEDTLS_SSL_PRESET_DEFAULT                = 0;
pub const MBEDTLS_SSL_PRESET_SUITEB                 = 2;

pub const MBEDTLS_ERR_SSL_BAD_INPUT_DATA            = -0x7100;
pub const MBEDTLS_ERR_SSL_ALLOC_FAILED              = -0x7F00;
pub const MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE       = -0x7080;
pub const MBEDTLS_ERR_SSL_WANT_WRITE                = -0x6880;
pub const MBEDTLS_ERR_SSL_WANT_READ                 = -0x6900;
pub const MBEDTLS_ERR_SSL_INTERNAL_ERROR            = -0x6C00;
pub const MBEDTLS_ERR_SSL_HW_ACCEL_FAILED           = -0x7F80;
pub const MBEDTLS_ERR_SSL_COMPRESSION_FAILED        = -0x6F00;
pub const MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL          = -0x6A00;
pub const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY         = -0x7880;

pub const MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA         = -0x6100;
pub const MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED        = -0x6400;
pub const MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE    = -0x6080;
pub const MBEDTLS_ERR_CIPHER_INVALID_CONTEXT        = -0x6380;
pub const MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED    = -0x6280;