#include "cryptosignwrapper.h"
#include "errors.h"

#include <sodium.h>
#include <stdexcept>
#include "aes_128_ctr/aes.hpp"
#include "keccak/sha3.hpp"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#undef APPMACROS_ONLY
// #include <openssl/applink.c>

#define CHAR_PTR(x) (const_cast<char *>((x).data()))
#define UCHAR_PTR(x) (reinterpret_cast<unsigned char *>(CHAR_PTR(x)))
#define CONST_UCHAR_PTR(x) reinterpret_cast<unsigned char const *>((x).data())

#if \
    (PUBLIC_KEY_LENGTH != crypto_sign_PUBLICKEYBYTES) || \
    (SECRET_KEY_LENGTH != crypto_sign_SECRETKEYBYTES) || \
    (SEED_LENGTH  != crypto_sign_SEEDBYTES) ||           \
    (SIGNATURE_LENGTH != crypto_sign_BYTES) ||           \
    (HMAC_SHA256_BYTES != crypto_auth_hmacsha256_BYTES)
#pragma message "Error. Libsodium library was updated. Update define parameters in the wrapper!"

#else

namespace wrapper
{
namespace crypto
{
std::string getSignature(bytes const &secretKey, std::string const &message)
{
    auto msg = CONST_UCHAR_PTR(message);
    auto sk = CONST_UCHAR_PTR(secretKey);

    unsigned char sig[SIGNATURE_LENGTH];
    unsigned long long sigLength;

    crypto_sign_detached(sig, &sigLength, msg, message.length(), sk);

    return std::string(sig, sig + sigLength);
}

bytes getSeed(bytes const &secretKey)
{
    auto sk = CONST_UCHAR_PTR(secretKey);

    unsigned char seed[SEED_LENGTH];

    crypto_sign_ed25519_sk_to_seed(seed, sk);

    return bytes(seed, seed + SEED_LENGTH);
}

bytes getSecretKey(bytes const &seed)
{
    auto sd = CONST_UCHAR_PTR(seed);

    unsigned char pk[PUBLIC_KEY_LENGTH];
    unsigned char sk[SECRET_KEY_LENGTH];

    crypto_sign_seed_keypair(pk, sk, sd);

    return bytes(sk, sk + SECRET_KEY_LENGTH);
}

bytes getPublicKey(bytes const &secretKey)
{
    auto sk = CONST_UCHAR_PTR(secretKey);

    unsigned char pk[PUBLIC_KEY_LENGTH];

    crypto_sign_ed25519_sk_to_pk(pk, sk);

    return bytes(pk, pk + PUBLIC_KEY_LENGTH);
}

bool verify(std::string const &signature, std::string const &message, bytes const &publicKey)
{
    auto sig = CONST_UCHAR_PTR(signature);
    auto msg = CONST_UCHAR_PTR(message);
    auto pk = CONST_UCHAR_PTR(publicKey);
    auto msgLen = message.size();

    int const res = crypto_sign_verify_detached(sig, msg, msgLen, pk);

    return res == 0;
}

bytes scrypt(std::string const &password, KdfParams const &kdfParams)
{
    unsigned int const keyLength = kdfParams.dklen;
    unsigned char derivedKey[keyLength];

    auto passw = CONST_UCHAR_PTR(password);
    auto salt = CONST_UCHAR_PTR(kdfParams.salt);

    if (crypto_pwhash_scryptsalsa208sha256_ll
            (passw, password.size(),
             salt, kdfParams.salt.size(),
             kdfParams.n,
             kdfParams.r,
             kdfParams.p,
             derivedKey, keyLength) !=0)
    {
        throw std::runtime_error(ERROR_MSG_SCRYPTSY);
    }

    return bytes(derivedKey, derivedKey + keyLength);
}

std::string hmacsha256(bytes const &key, std::string const &cipherText)
{
    auto k = CONST_UCHAR_PTR(key);
    auto cipher = CONST_UCHAR_PTR(cipherText);

    unsigned char digest[HMAC_SHA256_BYTES];

    crypto_auth_hmacsha256_state state;

    crypto_auth_hmacsha256_init(&state, k, key.size());
    crypto_auth_hmacsha256_update(&state, cipher, cipherText.size());
    crypto_auth_hmacsha256_final(&state, digest);

    return std::string(digest, digest + HMAC_SHA256_BYTES);
}

bytes aes128ctrDecrypt(bytes const &key, std::string cipherText, std::string const &iv)
{
    auto k = CONST_UCHAR_PTR(key);
    auto initVector = CONST_UCHAR_PTR(iv);
    auto cipher = UCHAR_PTR(cipherText);
    auto cipherSize = cipherText.size();

    AES_ctx ctx{};

    AES_init_ctx_iv(&ctx, k, initVector);
    AES_CTR_xcrypt_buffer(&ctx, cipher, cipherSize);

    return bytes(cipher, cipher + cipherSize);
}

bytes aes256crypt(bytes const& key, std::string cipherText, std::string const& iv)
{
    auto k = CONST_UCHAR_PTR(key);
    auto initVector = CONST_UCHAR_PTR(iv);
    auto cipher = UCHAR_PTR(cipherText);
    auto cipherSize = cipherText.size();

    // ctx holds the state of the encryption algorithm so that it doesn't
    // reset back to its initial state while encrypting more than 1 block.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    //EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(ctx);

    std::vector<unsigned char> encrypted;
    size_t max_output_len = cipherText.length() + 16 - (cipherText.length() % 16);
    encrypted.resize(max_output_len);

    // Enc is 1 to encrypt, 0 to decrypt, or -1 (see documentation).
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, initVector, 1);

    // EVP_CipherUpdate can encrypt all your data at once, or you can do
    // small chunks at a time.
    int actual_size = 0;
    EVP_CipherUpdate(ctx,
        &encrypted[0], &actual_size,
        reinterpret_cast<unsigned char*>(&cipherText[0]), cipherText.size());

    // EVP_CipherFinal_ex is what applies the padding.  If your data is
    // a multiple of the block size, you'll get an extra AES block filled
    // with nothing but padding.
    int final_size;
    EVP_CipherFinal_ex(ctx, &encrypted[actual_size], &final_size);
    actual_size += final_size;

    encrypted.resize(actual_size);

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);


    // 7 Pour le padding de 7 : PKCS7Padding
    return bytes(encrypted.data(), encrypted.data() + actual_size);
}

void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

std::string aes256decrypt(bytes const& key, std::string cipherText, std::string const& iv)
{
    auto k = CONST_UCHAR_PTR(key);
    auto initVector = CONST_UCHAR_PTR(iv);
    auto cipher = UCHAR_PTR(cipherText);
    auto cipherSize = cipherText.size();


    //AES_ctx ctx{};

    //AES_init_ctx_iv(&ctx, k, initVector);
    //AES_CBC_decrypt_buffer(&ctx, cipher, cipherSize);

    //return nullptr;



    EVP_CIPHER_CTX* ctx;
    unsigned char* plaintexts;
    int len;
    int plaintext_len;
    unsigned char* plaintext = new unsigned char[cipherSize];
    memset(plaintext, 0, sizeof(plaintext));

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, initVector))
        handleOpenSSLErrors();

    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

    /* Provide the message to be decrypted, and obtain the plaintext output.
      * EVP_DecryptUpdate can be called multiple times if necessary
      */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipherSize))
        handleOpenSSLErrors();

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        handleOpenSSLErrors();
    plaintext_len += len;


    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    std::string ret = (char*)plaintext;
    delete[] plaintext;
    return ret;
}

std::string sha3Keccak(std::string const &message)
{
    auto msg = UCHAR_PTR(message);

    uint8_t out[SHA3_KECCAK_BYTES];
    sha3(msg, message.size(), out, SHA3_KECCAK_BYTES);

    return std::string(out, out + SHA3_KECCAK_BYTES);
}

}
}

#endif
