#pragma once

#include <cstddef>
#include <cstdint>

#include "wps_crypto.h"
#include "wps_parser.h"

namespace wps {

constexpr size_t kRegistrarM2MaxLength = 512;
constexpr size_t kRegistrarM4MaxLength = 384;
constexpr size_t kRegistrarM6MaxLength = 384;
constexpr size_t kRegistrarM8MaxLength = 512;
constexpr size_t kEncryptedSettingsMaxLength = 512;
constexpr size_t kRegistrarSecretNonceLength = 16;
constexpr size_t kWpsPskLength = 16;
constexpr size_t kPinMaxLength = 8;

struct RegistrarM4Result {
    uint8_t attributes[kRegistrarM4MaxLength]{};
    size_t attributesLength = 0;
    uint8_t psk1[kWpsPskLength]{};
    uint8_t psk2[kWpsPskLength]{};
    uint8_t registrarSecretNonce2[kRegistrarSecretNonceLength]{};
};

struct RegistrarM6Result {
    uint8_t attributes[kRegistrarM6MaxLength]{};
    size_t attributesLength = 0;
};

struct RegistrarM7Result {
    uint8_t ssid[32]{};
    size_t ssidLength = 0;
    uint8_t networkKey[64]{};
    size_t networkKeyLength = 0;
    uint16_t authenticationType = 0;
    uint16_t encryptionType = 0;
    uint8_t networkKeyIndex = 0;
    uint8_t apMacAddress[6]{};
    bool hasApMacAddress = false;
};

struct RegistrarM8Result {
    uint8_t attributes[kRegistrarM8MaxLength]{};
    size_t attributesLength = 0;
};

struct RegistrarM2Result {
    uint8_t attributes[kRegistrarM2MaxLength]{};
    size_t attributesLength = 0;
    uint8_t registrarPublicKey[crypto::kPublicKeyLength]{};
    uint8_t dhSharedSecret[crypto::kPublicKeyLength]{};
    uint8_t dhKey[crypto::kSha256Length]{};
    uint8_t kdk[crypto::kSha256Length]{};
    uint8_t authKey[crypto::kSha256Length]{};
    uint8_t keyWrapKey[16]{};
};

// Builds a registrar-side WPS M2 response from a received M1 WPS attribute
// payload. The private key is a big-endian DH exponent. The generated M2
// includes the Authenticator attribute and is suitable for EAP-WSC transport.
bool buildRegistrarM2(
    const uint8_t* m1Attributes,
    size_t m1Length,
    const uint8_t* registrarPrivateKey,
    size_t registrarPrivateKeyLength,
    const uint8_t registrarNonce[16],
    const uint8_t uuidR[16],
    RegistrarM2Result& result,
    const char** error = nullptr);

// Verifies that the final Authenticator attribute in an M3 WPS payload is
// HMAC-SHA256(AuthKey, M2 || M3-without-Authenticator), truncated to 8 bytes.
bool verifyM3Authenticator(
    const uint8_t* m2Attributes,
    size_t m2Length,
    const uint8_t* m3Attributes,
    size_t m3Length,
    const uint8_t authKey[crypto::kSha256Length],
    bool& matches,
    const char** error = nullptr);

// Derives the two PIN proof keys from the WPS PIN:
// PSK1 = HMAC-SHA256(AuthKey, first half of PIN)[:16]
// PSK2 = HMAC-SHA256(AuthKey, second half of PIN)[:16]
bool derivePinPsks(
    const uint8_t* pin,
    size_t pinLength,
    const uint8_t authKey[crypto::kSha256Length],
    uint8_t psk1[kWpsPskLength],
    uint8_t psk2[kWpsPskLength],
    const char** error = nullptr);

// Builds registrar-side WPS M4 from the received M3 and the PIN. The caller
// supplies the two registrar secret nonces and the AES-CBC IV so the result
// is deterministic in tests. The returned M4 includes its Authenticator.
bool buildRegistrarM4(
    const uint8_t* m3Attributes,
    size_t m3Length,
    const uint8_t enrolleeNonce[16],
    const uint8_t enrolleePublicKey[crypto::kPublicKeyLength],
    const uint8_t registrarPublicKey[crypto::kPublicKeyLength],
    const uint8_t* pin,
    size_t pinLength,
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    const uint8_t registrarSecretNonce1[kRegistrarSecretNonceLength],
    const uint8_t registrarSecretNonce2[kRegistrarSecretNonceLength],
    const uint8_t iv[16],
    RegistrarM4Result& result,
    const char** error = nullptr);

// Processes M5: verifies its chained Authenticator and R-Nonce, decrypts the
// Encrypted Settings, validates Key Wrap Authenticator, and extracts E-SNonce1.
bool processRegistrarM5(
    const uint8_t* m4Attributes,
    size_t m4Length,
    const uint8_t* m5Attributes,
    size_t m5Length,
    const uint8_t registrarNonce[16],
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    uint8_t eSnonce1[kRegistrarSecretNonceLength],
    const char** error = nullptr);

// Builds registrar-side M6 carrying encrypted R-SNonce2.
bool buildRegistrarM6(
    const uint8_t* m5Attributes,
    size_t m5Length,
    const uint8_t enrolleeNonce[16],
    const uint8_t registrarSecretNonce2[kRegistrarSecretNonceLength],
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    const uint8_t iv[16],
    RegistrarM6Result& result,
    const char** error = nullptr);

// Processes M7: verifies its chained Authenticator and R-Nonce, decrypts the
// AP settings/credential payload, validates Key Wrap Authenticator, and
// extracts SSID/authentication/encryption/network-key material.
bool processRegistrarM7(
    const uint8_t* m6Attributes,
    size_t m6Length,
    const uint8_t* m7Attributes,
    size_t m7Length,
    const uint8_t registrarNonce[16],
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    RegistrarM7Result& result,
    const char** error = nullptr);

// Builds the registrar-side WSC_ACK response sent after receiving the
// enrollee's WSC_Done. Hostap builds Version, Message Type, Enrollee Nonce,
// Registrar Nonce and the WFA extension, without an Authenticator attribute.
bool buildRegistrarWscAck(
    const uint8_t enrolleeNonce[16],
    const uint8_t registrarNonce[16],
    uint8_t* attributes,
    size_t capacity,
    size_t& length,
    const char** error = nullptr);

// Builds registrar-side M8. The credential fields extracted from M7 are
// echoed back as AP settings, with the M7 Authenticator as the previous
// message in the WPS authentication chain.
bool buildRegistrarM8(
    const uint8_t* m7Attributes,
    size_t m7Length,
    const uint8_t enrolleeNonce[16],
    const RegistrarM7Result& credentials,
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    const uint8_t iv[16],
    RegistrarM8Result& result,
    const char** error = nullptr);

}  // namespace wps
