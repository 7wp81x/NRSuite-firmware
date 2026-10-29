#include "wps_crypto.h"

#include <cstring>

#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include "wps_dh_group5.h"

namespace wps::crypto {
namespace {

class Mpi {
public:
    Mpi() { mbedtls_mpi_init(&value_); }
    ~Mpi() { mbedtls_mpi_free(&value_); }

    Mpi(const Mpi&) = delete;
    Mpi& operator=(const Mpi&) = delete;

    mbedtls_mpi* get() { return &value_; }
    const mbedtls_mpi* get() const { return &value_; }

private:
    mbedtls_mpi value_{};
};

class MdContext {
public:
    MdContext() { mbedtls_md_init(&context_); }
    ~MdContext() { mbedtls_md_free(&context_); }

    MdContext(const MdContext&) = delete;
    MdContext& operator=(const MdContext&) = delete;

    mbedtls_md_context_t* get() { return &context_; }

private:
    mbedtls_md_context_t context_{};
};

}  // namespace

bool sha256(const uint8_t* data, size_t length, uint8_t output[kSha256Length]) {
    return mbedtls_sha256(data, length, output, 0) == 0;
}

bool hmacSha256(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* const* parts,
    const size_t* partLengths,
    size_t partCount,
    uint8_t output[kSha256Length]) {
    const mbedtls_md_info_t* info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == nullptr) {
        return false;
    }

    MdContext context;
    if (mbedtls_md_setup(context.get(), info, 1) != 0 ||
        mbedtls_md_hmac_starts(context.get(), key, keyLength) != 0) {
        return false;
    }

    for (size_t index = 0; index < partCount; ++index) {
        if (partLengths[index] == 0) {
            continue;
        }
        if (parts[index] == nullptr ||
            mbedtls_md_hmac_update(context.get(), parts[index], partLengths[index]) != 0) {
            return false;
        }
    }

    return mbedtls_md_hmac_finish(context.get(), output) == 0;
}

bool dhGeneratePublicKey(
    const uint8_t* privateKey,
    size_t privateKeyLength,
    uint8_t publicKey[kPublicKeyLength]) {
    if (privateKey == nullptr || privateKeyLength == 0) {
        return false;
    }

    Mpi prime;
    Mpi generator;
    Mpi privateValue;
    Mpi publicValue;

    if (mbedtls_mpi_read_binary(prime.get(), kDhGroup5Prime, sizeof(kDhGroup5Prime)) != 0 ||
        mbedtls_mpi_lset(generator.get(), 2) != 0 ||
        mbedtls_mpi_read_binary(privateValue.get(), privateKey, privateKeyLength) != 0) {
        return false;
    }

    if (mbedtls_mpi_cmp_int(privateValue.get(), 1) <= 0 ||
        mbedtls_mpi_cmp_mpi(privateValue.get(), prime.get()) >= 0) {
        return false;
    }

    if (mbedtls_mpi_exp_mod(publicValue.get(), generator.get(), privateValue.get(), prime.get(), nullptr) != 0) {
        return false;
    }
    return mbedtls_mpi_write_binary(publicValue.get(), publicKey, kPublicKeyLength) == 0;
}

bool dhComputeSharedSecret(
    const uint8_t* peerPublicKey,
    size_t peerPublicKeyLength,
    const uint8_t* privateKey,
    size_t privateKeyLength,
    uint8_t sharedSecret[kPublicKeyLength]) {
    if (peerPublicKey == nullptr || peerPublicKeyLength == 0 ||
        privateKey == nullptr || privateKeyLength == 0) {
        return false;
    }

    Mpi prime;
    Mpi peerValue;
    Mpi privateValue;
    Mpi sharedValue;

    if (mbedtls_mpi_read_binary(prime.get(), kDhGroup5Prime, sizeof(kDhGroup5Prime)) != 0 ||
        mbedtls_mpi_read_binary(peerValue.get(), peerPublicKey, peerPublicKeyLength) != 0 ||
        mbedtls_mpi_read_binary(privateValue.get(), privateKey, privateKeyLength) != 0) {
        return false;
    }

    if (mbedtls_mpi_cmp_int(peerValue.get(), 1) <= 0 ||
        mbedtls_mpi_cmp_mpi(peerValue.get(), prime.get()) >= 0 ||
        mbedtls_mpi_cmp_int(privateValue.get(), 1) <= 0 ||
        mbedtls_mpi_cmp_mpi(privateValue.get(), prime.get()) >= 0) {
        return false;
    }

    if (mbedtls_mpi_exp_mod(sharedValue.get(), peerValue.get(), privateValue.get(), prime.get(), nullptr) != 0) {
        return false;
    }
    return mbedtls_mpi_write_binary(sharedValue.get(), sharedSecret, kPublicKeyLength) == 0;
}


bool aes128CbcEncrypt(
    const uint8_t key[16],
    const uint8_t iv[16],
    const uint8_t* input,
    size_t length,
    uint8_t* output) {
    if (key == nullptr || iv == nullptr || input == nullptr || output == nullptr ||
        length == 0 || length % 16 != 0) {
        return false;
    }

    mbedtls_aes_context context;
    mbedtls_aes_init(&context);
    uint8_t ivCopy[16];
    std::memcpy(ivCopy, iv, sizeof(ivCopy));
    const bool ok =
        mbedtls_aes_setkey_enc(&context, key, 128) == 0 &&
        mbedtls_aes_crypt_cbc(
            &context, MBEDTLS_AES_ENCRYPT, length, ivCopy, input, output) == 0;
    mbedtls_aes_free(&context);
    return ok;
}

bool aes128CbcDecrypt(
    const uint8_t key[16],
    const uint8_t iv[16],
    const uint8_t* input,
    size_t length,
    uint8_t* output) {
    if (key == nullptr || iv == nullptr || input == nullptr || output == nullptr ||
        length == 0 || length % 16 != 0) {
        return false;
    }

    mbedtls_aes_context context;
    mbedtls_aes_init(&context);
    uint8_t ivCopy[16];
    std::memcpy(ivCopy, iv, sizeof(ivCopy));
    const bool ok =
        mbedtls_aes_setkey_dec(&context, key, 128) == 0 &&
        mbedtls_aes_crypt_cbc(
            &context, MBEDTLS_AES_DECRYPT, length, ivCopy, input, output) == 0;
    mbedtls_aes_free(&context);
    return ok;
}

void secureZero(void* data, size_t length) {
    if (data == nullptr) {
        return;
    }
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(data);
    while (length-- > 0) {
        *bytes++ = 0;
    }
}

}  // namespace wps::crypto
