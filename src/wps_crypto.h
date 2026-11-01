#pragma once

#include <cstddef>
#include <cstdint>

namespace wps::crypto {

constexpr size_t kSha256Length = 32;
constexpr size_t kPublicKeyLength = 192;

bool sha256(const uint8_t* data, size_t length, uint8_t output[kSha256Length]);

// HMAC-SHA256 over a sequence of non-contiguous input chunks.
bool hmacSha256(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* const* parts,
    const size_t* partLengths,
    size_t partCount,
    uint8_t output[kSha256Length]);

bool dhGeneratePublicKey(
    const uint8_t* privateKey,
    size_t privateKeyLength,
    uint8_t publicKey[kPublicKeyLength]);

bool dhComputeSharedSecret(
    const uint8_t* peerPublicKey,
    size_t peerPublicKeyLength,
    const uint8_t* privateKey,
    size_t privateKeyLength,
    uint8_t sharedSecret[kPublicKeyLength]);

// AES-128-CBC without implicit padding. `length` must be a non-zero multiple
// of the 16-byte AES block size.
bool aes128CbcEncrypt(
    const uint8_t key[16],
    const uint8_t iv[16],
    const uint8_t* input,
    size_t length,
    uint8_t* output);

bool aes128CbcDecrypt(
    const uint8_t key[16],
    const uint8_t iv[16],
    const uint8_t* input,
    size_t length,
    uint8_t* output);

void secureZero(void* data, size_t length);

}  // namespace wps::crypto
