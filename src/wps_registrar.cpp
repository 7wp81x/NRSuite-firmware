#include "wps_registrar.h"

#include <cstring>

#include "wps_crypto.h"

namespace wps {
namespace {

bool fail(const char** error, const char* message) {
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

void writeBe16(uint8_t* output, uint16_t value) {
    output[0] = static_cast<uint8_t>(value >> 8);
    output[1] = static_cast<uint8_t>(value & 0xff);
}

void writeBe32(uint8_t* output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value >> 24);
    output[1] = static_cast<uint8_t>((value >> 16) & 0xff);
    output[2] = static_cast<uint8_t>((value >> 8) & 0xff);
    output[3] = static_cast<uint8_t>(value & 0xff);
}

class BufferWriter {
public:
    BufferWriter(uint8_t* data, size_t capacity) : data_(data), capacity_(capacity) {}

    bool append(const uint8_t* data, size_t length) {
        if (length > capacity_ - length_) {
            return false;
        }
        if (length != 0) {
            std::memcpy(data_ + length_, data, length);
        }
        length_ += length;
        return true;
    }

    bool appendByte(uint8_t value) { return append(&value, 1); }

    bool appendBe16(uint16_t value) {
        uint8_t bytes[2];
        writeBe16(bytes, value);
        return append(bytes, sizeof(bytes));
    }

    bool appendAttribute(uint16_t type, const uint8_t* value, size_t length) {
        if (length > 0xffff || !appendBe16(type) || !appendBe16(static_cast<uint16_t>(length))) {
            return false;
        }
        return append(value, length);
    }

    uint8_t* data() { return data_; }
    size_t length() const { return length_; }

private:
    uint8_t* data_;
    size_t capacity_;
    size_t length_ = 0;
};

bool findAttribute(
    const WpsAttributes& attributes,
    uint16_t type,
    size_t expectedLength,
    const uint8_t** value,
    const char** error,
    const char* name) {
    const WpsAttribute* attribute = attributes.find(type);
    if (attribute == nullptr) {
        return fail(error, name);
    }
    if (attribute->length != expectedLength || attribute->value == nullptr) {
        return fail(error, name);
    }
    *value = attribute->value;
    return true;
}


constexpr uint8_t kWfaExtension[] = {0x00, 0x37, 0x2a, 0x00, 0x01, 0x20};
constexpr size_t kAuthenticatorAttributeLength = 12;
constexpr size_t kKeyWrapAuthenticatorLength = 8;

bool computeChainedAuthenticator(
    const uint8_t* previous,
    size_t previousLength,
    const uint8_t* currentWithoutAuthenticator,
    size_t currentLength,
    const uint8_t authKey[crypto::kSha256Length],
    uint8_t output[crypto::kSha256Length]) {
    const uint8_t* parts[] = {previous, currentWithoutAuthenticator};
    const size_t lengths[] = {previousLength, currentLength};
    return crypto::hmacSha256(
        authKey,
        crypto::kSha256Length,
        parts,
        lengths,
        2,
        output);
}

bool verifyChainedAuthenticator(
    const uint8_t* previous,
    size_t previousLength,
    const uint8_t* current,
    size_t currentLength,
    const uint8_t authKey[crypto::kSha256Length],
    bool& matches,
    const char** error,
    const char* name) {
    matches = false;
    if (previous == nullptr || previousLength == 0 ||
        current == nullptr || currentLength < kAuthenticatorAttributeLength ||
        authKey == nullptr) {
        return fail(error, "invalid chained Authenticator input");
    }
    const size_t offset = currentLength - kAuthenticatorAttributeLength;
    if (readBe16(current + offset) != ATTR_AUTHENTICATOR ||
        readBe16(current + offset + 2) != 8) {
        return fail(error, "Authenticator attribute is not at the end");
    }
    uint8_t expected[crypto::kSha256Length];
    if (!computeChainedAuthenticator(
            previous,
            previousLength,
            current,
            offset,
            authKey,
            expected)) {
        return fail(error, "failed to compute chained Authenticator");
    }
    uint8_t difference = 0;
    for (size_t index = 0; index < 8; ++index) {
        difference |= expected[index] ^ current[offset + 4 + index];
    }
    matches = difference == 0;
    if (!matches) {
        return fail(error, name);
    }
    return true;
}

bool appendKeyWrapAuthenticator(
    BufferWriter& writer,
    const uint8_t authKey[crypto::kSha256Length]) {
    uint8_t hmac[crypto::kSha256Length];
    const uint8_t* parts[] = {writer.data()};
    const size_t lengths[] = {writer.length()};
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            parts,
            lengths,
            1,
            hmac)) {
        return false;
    }
    return writer.appendAttribute(
        ATTR_KEY_WRAP_AUTH,
        hmac,
        kKeyWrapAuthenticatorLength);
}

bool appendEncryptedSettings(
    BufferWriter& writer,
    const uint8_t* plain,
    size_t plainLength,
    const uint8_t keyWrapKey[16],
    const uint8_t iv[16]) {
    if (plain == nullptr || plainLength == 0 ||
        keyWrapKey == nullptr || iv == nullptr) {
        return false;
    }
    const size_t paddedLength = plainLength + (16 - (plainLength % 16));
    if (paddedLength > kEncryptedSettingsMaxLength) {
        return false;
    }
    uint8_t padded[kEncryptedSettingsMaxLength];
    uint8_t encrypted[16 + kEncryptedSettingsMaxLength];
    std::memcpy(padded, plain, plainLength);
    const uint8_t pad = static_cast<uint8_t>(paddedLength - plainLength);
    std::memset(padded + plainLength, pad, pad);
    if (!crypto::aes128CbcEncrypt(
            keyWrapKey,
            iv,
            padded,
            paddedLength,
            encrypted + 16)) {
        crypto::secureZero(padded, paddedLength);
        return false;
    }
    std::memcpy(encrypted, iv, 16);
    const bool appended = writer.appendAttribute(
        ATTR_ENCRYPTED_SETTINGS,
        encrypted,
        paddedLength + 16);
    crypto::secureZero(padded, paddedLength);
    crypto::secureZero(encrypted, paddedLength + 16);
    return appended;
}

bool decryptEncryptedSettings(
    const uint8_t* encrypted,
    size_t encryptedLength,
    const uint8_t keyWrapKey[16],
    uint8_t* plain,
    size_t plainCapacity,
    size_t& plainLength,
    const char** error) {
    plainLength = 0;
    if (encrypted == nullptr || encryptedLength < 32 ||
        encryptedLength % 16 != 0 || keyWrapKey == nullptr ||
        plain == nullptr) {
        return fail(error, "invalid Encrypted Settings input");
    }
    const size_t cipherLength = encryptedLength - 16;
    if (cipherLength > plainCapacity) {
        return fail(error, "Encrypted Settings output too small");
    }
    if (!crypto::aes128CbcDecrypt(
            keyWrapKey,
            encrypted,
            encrypted + 16,
            cipherLength,
            plain)) {
        return fail(error, "AES-CBC decrypt failed");
    }
    const uint8_t pad = plain[cipherLength - 1];
    if (pad == 0 || pad > 16 || pad > cipherLength) {
        crypto::secureZero(plain, cipherLength);
        return fail(error, "invalid PKCS#5 padding");
    }
    for (size_t index = 0; index < pad; ++index) {
        if (plain[cipherLength - 1 - index] != pad) {
            crypto::secureZero(plain, cipherLength);
            return fail(error, "invalid PKCS#5 padding");
        }
    }
    plainLength = cipherLength - pad;
    return true;
}

bool verifyKeyWrapAuthenticator(
    const uint8_t* plain,
    size_t plainLength,
    const uint8_t authKey[crypto::kSha256Length],
    const char** error) {
    if (plain == nullptr || plainLength < kAuthenticatorAttributeLength ||
        authKey == nullptr) {
        return fail(error, "invalid Key Wrap Authenticator input");
    }
    const size_t offset = plainLength - kAuthenticatorAttributeLength;
    if (readBe16(plain + offset) != ATTR_KEY_WRAP_AUTH ||
        readBe16(plain + offset + 2) != kKeyWrapAuthenticatorLength) {
        return fail(error, "Key Wrap Authenticator attribute is not at the end");
    }
    uint8_t expected[crypto::kSha256Length];
    const uint8_t* parts[] = {plain};
    const size_t lengths[] = {offset};
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            parts,
            lengths,
            1,
            expected)) {
        return fail(error, "failed to compute Key Wrap Authenticator");
    }
    uint8_t difference = 0;
    for (size_t index = 0; index < kKeyWrapAuthenticatorLength; ++index) {
        difference |= expected[index] ^ plain[offset + 4 + index];
    }
    if (difference != 0) {
        return fail(error, "Key Wrap Authenticator mismatch");
    }
    return true;
}


}  // namespace

bool buildRegistrarM2(
    const uint8_t* m1Attributes,
    size_t m1Length,
    const uint8_t* registrarPrivateKey,
    size_t registrarPrivateKeyLength,
    const uint8_t registrarNonce[16],
    const uint8_t uuidR[16],
    RegistrarM2Result& result,
    const char** error) {
    result = RegistrarM2Result{};

    if (m1Attributes == nullptr || m1Length == 0) {
        return fail(error, "empty M1 payload");
    }
    if (registrarPrivateKey == nullptr || registrarPrivateKeyLength == 0) {
        return fail(error, "empty registrar private key");
    }
    if (registrarNonce == nullptr || uuidR == nullptr) {
        return fail(error, "missing registrar nonce or UUID-R");
    }

    WpsAttributes m1{};
    if (!m1.parse(m1Attributes, m1Length)) {
        return fail(error, "invalid M1 WPS attributes");
    }
    if (!isMessageType(m1, MSG_M1)) {
        return fail(error, "input is not WPS M1");
    }

    const uint8_t* enrolleeNonce = nullptr;
    const uint8_t* enrolleeMac = nullptr;
    const uint8_t* enrolleePublicKey = nullptr;
    if (!findAttribute(m1, ATTR_ENROLLEE_NONCE, 16, &enrolleeNonce, error, "M1 missing E-Nonce") ||
        !findAttribute(m1, 0x1020, 6, &enrolleeMac, error, "M1 missing enrollee MAC") ||
        !findAttribute(
            m1,
            ATTR_PUBLIC_KEY,
            crypto::kPublicKeyLength,
            &enrolleePublicKey,
            error,
            "M1 missing enrollee public key")) {
        return false;
    }

    if (!crypto::dhGeneratePublicKey(
            registrarPrivateKey,
            registrarPrivateKeyLength,
            result.registrarPublicKey)) {
        return fail(error, "failed to generate registrar DH public key");
    }
    if (!crypto::dhComputeSharedSecret(
            enrolleePublicKey,
            crypto::kPublicKeyLength,
            registrarPrivateKey,
            registrarPrivateKeyLength,
            result.dhSharedSecret)) {
        return fail(error, "failed to derive DH shared secret");
    }
    if (!crypto::sha256(
            result.dhSharedSecret,
            sizeof(result.dhSharedSecret),
            result.dhKey)) {
        return fail(error, "failed to derive DHKey");
    }

    const uint8_t* kdkParts[] = {enrolleeNonce, enrolleeMac, registrarNonce};
    const size_t kdkLengths[] = {16, 6, 16};
    if (!crypto::hmacSha256(
            result.dhKey,
            sizeof(result.dhKey),
            kdkParts,
            kdkLengths,
            3,
            result.kdk)) {
        return fail(error, "failed to derive KDK");
    }

    static constexpr uint8_t kdfLabel[] = {
        'W', 'i', '-', 'F', 'i', ' ', 'E', 'a', 's', 'y', ' ', 'a', 'n', 'd',
        ' ', 'S', 'e', 'c', 'u', 'r', 'e', ' ', 'K', 'e', 'y', ' ', 'D', 'e',
        'r', 'i', 'v', 'a', 't', 'i', 'o', 'n',
    };
    uint8_t keyMaterial[80]{};
    for (uint32_t block = 1; block <= 3; ++block) {
        uint8_t blockIndex[4];
        uint8_t keyBits[4];
        writeBe32(blockIndex, block);
        writeBe32(keyBits, sizeof(keyMaterial) * 8);
        const uint8_t* kdfParts[] = {blockIndex, kdfLabel, keyBits};
        const size_t kdfLengths[] = {sizeof(blockIndex), sizeof(kdfLabel), sizeof(keyBits)};
        uint8_t digest[crypto::kSha256Length];
        if (!crypto::hmacSha256(
                result.kdk,
                sizeof(result.kdk),
                kdfParts,
                kdfLengths,
                3,
                digest)) {
            crypto::secureZero(keyMaterial, sizeof(keyMaterial));
            return fail(error, "failed to derive WPS key material");
        }
        const size_t offset = static_cast<size_t>(block - 1) * crypto::kSha256Length;
        const size_t remaining = sizeof(keyMaterial) - offset;
        const size_t copyLength = remaining < sizeof(digest) ? remaining : sizeof(digest);
        std::memcpy(keyMaterial + offset, digest, copyLength);
    }
    std::memcpy(result.authKey, keyMaterial, sizeof(result.authKey));
    std::memcpy(
        result.keyWrapKey,
        keyMaterial + sizeof(result.authKey),
        sizeof(result.keyWrapKey));
    crypto::secureZero(keyMaterial, sizeof(keyMaterial));

    BufferWriter writer(result.attributes, sizeof(result.attributes));
    const uint8_t version = 0x10;
    const uint8_t messageType = MSG_M2;
    const uint8_t authTypeFlags[] = {0x00, 0x23};
    const uint8_t encrTypeFlags[] = {0x00, 0x0d};
    const uint8_t connectionType = 0x01;
    const uint8_t configMethods[] = {0x31, 0x08};
    const uint8_t placeholder = 0x20;
    const uint8_t primaryDeviceType[8]{};
    const uint8_t rfBands = 0x01;
    const uint8_t associationState[] = {0x00, 0x00};
    const uint8_t configError[] = {0x00, 0x00};
    const uint8_t devicePasswordId[] = {0x00, 0x00};
    const uint8_t osVersion[] = {0x80, 0x00, 0x00, 0x00};
    const uint8_t wfaExtension[] = {0x00, 0x37, 0x2a, 0x00, 0x01, 0x20};

    const bool built =
        writer.appendAttribute(ATTR_VERSION, &version, 1) &&
        writer.appendAttribute(ATTR_MESSAGE_TYPE, &messageType, 1) &&
        writer.appendAttribute(ATTR_ENROLLEE_NONCE, enrolleeNonce, 16) &&
        writer.appendAttribute(ATTR_REGISTRAR_NONCE, registrarNonce, 16) &&
        writer.appendAttribute(ATTR_UUID_R, uuidR, 16) &&
        writer.appendAttribute(
            ATTR_PUBLIC_KEY,
            result.registrarPublicKey,
            sizeof(result.registrarPublicKey)) &&
        writer.appendAttribute(0x1004, authTypeFlags, sizeof(authTypeFlags)) &&
        writer.appendAttribute(0x1010, encrTypeFlags, sizeof(encrTypeFlags)) &&
        writer.appendAttribute(0x100d, &connectionType, 1) &&
        writer.appendAttribute(0x1008, configMethods, sizeof(configMethods)) &&
        writer.appendAttribute(0x1021, &placeholder, 1) &&
        writer.appendAttribute(0x1023, &placeholder, 1) &&
        writer.appendAttribute(0x1024, &placeholder, 1) &&
        writer.appendAttribute(0x1042, &placeholder, 1) &&
        writer.appendAttribute(0x1054, primaryDeviceType, sizeof(primaryDeviceType)) &&
        writer.appendAttribute(0x1011, &placeholder, 1) &&
        writer.appendAttribute(0x103c, &rfBands, 1) &&
        writer.appendAttribute(0x1002, associationState, sizeof(associationState)) &&
        writer.appendAttribute(0x1009, configError, sizeof(configError)) &&
        writer.appendAttribute(0x1012, devicePasswordId, sizeof(devicePasswordId)) &&
        writer.appendAttribute(0x102d, osVersion, sizeof(osVersion)) &&
        writer.appendAttribute(0x1049, wfaExtension, sizeof(wfaExtension));
    if (!built) {
        return fail(error, "M2 payload exceeded buffer");
    }

    const size_t m2WithoutAuthenticatorLength = writer.length();
    const uint8_t* authParts[] = {m1Attributes, writer.data()};
    const size_t authLengths[] = {m1Length, m2WithoutAuthenticatorLength};
    uint8_t authenticator[crypto::kSha256Length];
    if (!crypto::hmacSha256(
            result.authKey,
            sizeof(result.authKey),
            authParts,
            authLengths,
            2,
            authenticator)) {
        return fail(error, "failed to compute M2 Authenticator");
    }
    if (!writer.appendAttribute(0x1005, authenticator, 8)) {
        return fail(error, "M2 payload exceeded buffer while adding Authenticator");
    }

    result.attributesLength = writer.length();
    return true;
}

bool verifyM3Authenticator(
    const uint8_t* m2Attributes,
    size_t m2Length,
    const uint8_t* m3Attributes,
    size_t m3Length,
    const uint8_t authKey[crypto::kSha256Length],
    bool& matches,
    const char** error) {
    matches = false;
    if (m2Attributes == nullptr || m2Length == 0 ||
        m3Attributes == nullptr || m3Length < 12 ||
        authKey == nullptr) {
        return fail(error, "invalid M3 Authenticator input");
    }

    const size_t authenticatorAttributeOffset = m3Length - 12;
    if (readBe16(m3Attributes + authenticatorAttributeOffset) != 0x1005 ||
        readBe16(m3Attributes + authenticatorAttributeOffset + 2) != 8) {
        return fail(error, "M3 Authenticator attribute is not at the end");
    }

    const uint8_t* authParts[] = {m2Attributes, m3Attributes};
    const size_t authLengths[] = {m2Length, authenticatorAttributeOffset};
    uint8_t expected[crypto::kSha256Length];
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            authParts,
            authLengths,
            2,
            expected)) {
        return fail(error, "failed to compute M3 Authenticator");
    }

    uint8_t difference = 0;
    for (size_t index = 0; index < 8; ++index) {
        difference |= expected[index] ^ m3Attributes[authenticatorAttributeOffset + 4 + index];
    }
    matches = difference == 0;
    return true;
}

bool derivePinPsks(
    const uint8_t* pin,
    size_t pinLength,
    const uint8_t authKey[crypto::kSha256Length],
    uint8_t psk1[kWpsPskLength],
    uint8_t psk2[kWpsPskLength],
    const char** error) {
    if (pin == nullptr || authKey == nullptr || psk1 == nullptr || psk2 == nullptr ||
        (pinLength != 4 && pinLength != 8)) {
        return fail(error, "invalid WPS PIN / AuthKey input");
    }
    const size_t firstLength = (pinLength + 1) / 2;
    const size_t secondLength = pinLength / 2;
    uint8_t digest[crypto::kSha256Length];
    const uint8_t* firstParts[] = {pin};
    const size_t firstLengths[] = {firstLength};
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            firstParts,
            firstLengths,
            1,
            digest)) {
        return fail(error, "failed to derive PSK1");
    }
    std::memcpy(psk1, digest, kWpsPskLength);
    const uint8_t* secondParts[] = {pin + firstLength};
    const size_t secondLengths[] = {secondLength};
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            secondParts,
            secondLengths,
            1,
            digest)) {
        crypto::secureZero(digest, sizeof(digest));
        return fail(error, "failed to derive PSK2");
    }
    std::memcpy(psk2, digest, kWpsPskLength);
    crypto::secureZero(digest, sizeof(digest));
    return true;
}

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
    const char** error) {
    result = RegistrarM4Result{};
    if (m3Attributes == nullptr || m3Length < kAuthenticatorAttributeLength ||
        enrolleeNonce == nullptr || enrolleePublicKey == nullptr ||
        registrarPublicKey == nullptr || authKey == nullptr ||
        keyWrapKey == nullptr || registrarSecretNonce1 == nullptr ||
        registrarSecretNonce2 == nullptr || iv == nullptr) {
        return fail(error, "invalid M4 input");
    }

    WpsAttributes m3{};
    if (!m3.parse(m3Attributes, m3Length) || !isMessageType(m3, MSG_M3)) {
        return fail(error, "input is not WPS M3");
    }
    if (!derivePinPsks(
            pin,
            pinLength,
            authKey,
            result.psk1,
            result.psk2,
            error)) {
        return false;
    }
    std::memcpy(
        result.registrarSecretNonce2,
        registrarSecretNonce2,
        kRegistrarSecretNonceLength);

    uint8_t rHash1[crypto::kSha256Length];
    uint8_t rHash2[crypto::kSha256Length];
    const uint8_t* rHash1Parts[] = {
        registrarSecretNonce1,
        result.psk1,
        enrolleePublicKey,
        registrarPublicKey,
    };
    const size_t rHash1Lengths[] = {
        kRegistrarSecretNonceLength,
        kWpsPskLength,
        crypto::kPublicKeyLength,
        crypto::kPublicKeyLength,
    };
    const uint8_t* rHash2Parts[] = {
        registrarSecretNonce2,
        result.psk2,
        enrolleePublicKey,
        registrarPublicKey,
    };
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            rHash1Parts,
            rHash1Lengths,
            4,
            rHash1) ||
        !crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            rHash2Parts,
            rHash1Lengths,
            4,
            rHash2)) {
        crypto::secureZero(rHash1, sizeof(rHash1));
        crypto::secureZero(rHash2, sizeof(rHash2));
        return fail(error, "failed to compute M4 R-Hashes");
    }

    uint8_t plain[128];
    BufferWriter plainWriter(plain, sizeof(plain));
    const bool plainBuilt =
        plainWriter.appendAttribute(
            ATTR_R_SNONCE1,
            registrarSecretNonce1,
            kRegistrarSecretNonceLength) &&
        appendKeyWrapAuthenticator(plainWriter, authKey);

    BufferWriter writer(result.attributes, sizeof(result.attributes));
    const uint8_t version = 0x10;
    const uint8_t messageType = MSG_M4;
    const bool built =
        plainBuilt &&
        writer.appendAttribute(ATTR_VERSION, &version, 1) &&
        writer.appendAttribute(ATTR_MESSAGE_TYPE, &messageType, 1) &&
        writer.appendAttribute(ATTR_ENROLLEE_NONCE, enrolleeNonce, 16) &&
        writer.appendAttribute(ATTR_R_HASH1, rHash1, sizeof(rHash1)) &&
        writer.appendAttribute(ATTR_R_HASH2, rHash2, sizeof(rHash2)) &&
        appendEncryptedSettings(
            writer,
            plainWriter.data(),
            plainWriter.length(),
            keyWrapKey,
            iv) &&
        writer.appendAttribute(ATTR_VENDOR_EXT, kWfaExtension, sizeof(kWfaExtension));
    crypto::secureZero(rHash1, sizeof(rHash1));
    crypto::secureZero(rHash2, sizeof(rHash2));
    crypto::secureZero(plain, sizeof(plain));
    if (!built) {
        return fail(error, "M4 payload exceeded buffer");
    }

    const size_t withoutAuthenticatorLength = writer.length();
    uint8_t authenticator[crypto::kSha256Length];
    const uint8_t* parts[] = {m3Attributes, writer.data()};
    const size_t lengths[] = {m3Length, withoutAuthenticatorLength};
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            parts,
            lengths,
            2,
            authenticator) ||
        !writer.appendAttribute(
            ATTR_AUTHENTICATOR,
            authenticator,
            kKeyWrapAuthenticatorLength)) {
        crypto::secureZero(authenticator, sizeof(authenticator));
        return fail(error, "failed to append M4 Authenticator");
    }
    crypto::secureZero(authenticator, sizeof(authenticator));
    result.attributesLength = writer.length();
    return true;
}

bool processRegistrarM5(
    const uint8_t* m4Attributes,
    size_t m4Length,
    const uint8_t* m5Attributes,
    size_t m5Length,
    const uint8_t registrarNonce[16],
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    uint8_t eSnonce1[kRegistrarSecretNonceLength],
    const char** error) {
    if (m4Attributes == nullptr || m4Length == 0 ||
        m5Attributes == nullptr || m5Length == 0 ||
        registrarNonce == nullptr || authKey == nullptr ||
        keyWrapKey == nullptr || eSnonce1 == nullptr) {
        return fail(error, "invalid M5 input");
    }
    WpsAttributes m5{};
    if (!m5.parse(m5Attributes, m5Length) || !isMessageType(m5, MSG_M5)) {
        return fail(error, "input is not WPS M5");
    }
    const WpsAttribute* registrarNonceAttribute = m5.find(ATTR_REGISTRAR_NONCE);
    if (registrarNonceAttribute == nullptr ||
        registrarNonceAttribute->length != 16 ||
        std::memcmp(registrarNonceAttribute->value, registrarNonce, 16) != 0) {
        return fail(error, "M5 R-Nonce mismatch");
    }
    bool authMatches = false;
    if (!verifyChainedAuthenticator(
            m4Attributes,
            m4Length,
            m5Attributes,
            m5Length,
            authKey,
            authMatches,
            error,
            "M5 Authenticator mismatch")) {
        return false;
    }
    const WpsAttribute* encrypted = m5.find(ATTR_ENCRYPTED_SETTINGS);
    if (encrypted == nullptr || encrypted->value == nullptr) {
        return fail(error, "M5 missing Encrypted Settings");
    }
    uint8_t plain[kEncryptedSettingsMaxLength];
    size_t plainLength = 0;
    if (!decryptEncryptedSettings(
            encrypted->value,
            encrypted->length,
            keyWrapKey,
            plain,
            sizeof(plain),
            plainLength,
            error)) {
        return false;
    }
    if (!verifyKeyWrapAuthenticator(plain, plainLength, authKey, error)) {
        crypto::secureZero(plain, sizeof(plain));
        return false;
    }
    WpsAttributes decrypted{};
    if (!decrypted.parse(plain, plainLength)) {
        crypto::secureZero(plain, sizeof(plain));
        return fail(error, "invalid decrypted M5 attributes");
    }
    const WpsAttribute* eSnonce1Attribute = decrypted.find(ATTR_E_SNONCE1);
    if (eSnonce1Attribute == nullptr ||
        eSnonce1Attribute->length != kRegistrarSecretNonceLength) {
        crypto::secureZero(plain, sizeof(plain));
        return fail(error, "M5 missing E-SNonce1");
    }
    std::memcpy(eSnonce1, eSnonce1Attribute->value, kRegistrarSecretNonceLength);
    crypto::secureZero(plain, sizeof(plain));
    return true;
}

bool buildRegistrarM6(
    const uint8_t* m5Attributes,
    size_t m5Length,
    const uint8_t enrolleeNonce[16],
    const uint8_t registrarSecretNonce2[kRegistrarSecretNonceLength],
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    const uint8_t iv[16],
    RegistrarM6Result& result,
    const char** error) {
    result = RegistrarM6Result{};
    if (m5Attributes == nullptr || m5Length == 0 ||
        enrolleeNonce == nullptr || registrarSecretNonce2 == nullptr ||
        authKey == nullptr || keyWrapKey == nullptr || iv == nullptr) {
        return fail(error, "invalid M6 input");
    }
    uint8_t plain[128];
    BufferWriter plainWriter(plain, sizeof(plain));
    const bool plainBuilt =
        plainWriter.appendAttribute(
            ATTR_R_SNONCE2,
            registrarSecretNonce2,
            kRegistrarSecretNonceLength) &&
        appendKeyWrapAuthenticator(plainWriter, authKey);

    BufferWriter writer(result.attributes, sizeof(result.attributes));
    const uint8_t version = 0x10;
    const uint8_t messageType = MSG_M6;
    const bool built =
        plainBuilt &&
        writer.appendAttribute(ATTR_VERSION, &version, 1) &&
        writer.appendAttribute(ATTR_MESSAGE_TYPE, &messageType, 1) &&
        writer.appendAttribute(ATTR_ENROLLEE_NONCE, enrolleeNonce, 16) &&
        appendEncryptedSettings(
            writer,
            plainWriter.data(),
            plainWriter.length(),
            keyWrapKey,
            iv) &&
        writer.appendAttribute(ATTR_VENDOR_EXT, kWfaExtension, sizeof(kWfaExtension));
    crypto::secureZero(plain, sizeof(plain));
    if (!built) {
        return fail(error, "M6 payload exceeded buffer");
    }
    const size_t withoutAuthenticatorLength = writer.length();
    uint8_t authenticator[crypto::kSha256Length];
    const uint8_t* parts[] = {m5Attributes, writer.data()};
    const size_t lengths[] = {m5Length, withoutAuthenticatorLength};
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            parts,
            lengths,
            2,
            authenticator) ||
        !writer.appendAttribute(
            ATTR_AUTHENTICATOR,
            authenticator,
            kKeyWrapAuthenticatorLength)) {
        crypto::secureZero(authenticator, sizeof(authenticator));
        return fail(error, "failed to append M6 Authenticator");
    }
    crypto::secureZero(authenticator, sizeof(authenticator));
    result.attributesLength = writer.length();
    return true;
}

bool processRegistrarM7(
    const uint8_t* m6Attributes,
    size_t m6Length,
    const uint8_t* m7Attributes,
    size_t m7Length,
    const uint8_t registrarNonce[16],
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    RegistrarM7Result& result,
    const char** error) {
    result = RegistrarM7Result{};
    if (m6Attributes == nullptr || m6Length == 0 ||
        m7Attributes == nullptr || m7Length == 0 ||
        registrarNonce == nullptr || authKey == nullptr || keyWrapKey == nullptr) {
        return fail(error, "invalid M7 input");
    }
    WpsAttributes m7{};
    if (!m7.parse(m7Attributes, m7Length) || !isMessageType(m7, MSG_M7)) {
        return fail(error, "input is not WPS M7");
    }
    const WpsAttribute* registrarNonceAttribute = m7.find(ATTR_REGISTRAR_NONCE);
    if (registrarNonceAttribute == nullptr ||
        registrarNonceAttribute->length != 16 ||
        std::memcmp(registrarNonceAttribute->value, registrarNonce, 16) != 0) {
        return fail(error, "M7 R-Nonce mismatch");
    }
    bool authMatches = false;
    if (!verifyChainedAuthenticator(
            m6Attributes,
            m6Length,
            m7Attributes,
            m7Length,
            authKey,
            authMatches,
            error,
            "M7 Authenticator mismatch")) {
        return false;
    }
    const WpsAttribute* encrypted = m7.find(ATTR_ENCRYPTED_SETTINGS);
    if (encrypted == nullptr || encrypted->value == nullptr) {
        return fail(error, "M7 missing Encrypted Settings");
    }
    uint8_t plain[kEncryptedSettingsMaxLength];
    size_t plainLength = 0;
    if (!decryptEncryptedSettings(
            encrypted->value,
            encrypted->length,
            keyWrapKey,
            plain,
            sizeof(plain),
            plainLength,
            error)) {
        return false;
    }
    if (!verifyKeyWrapAuthenticator(plain, plainLength, authKey, error)) {
        crypto::secureZero(plain, sizeof(plain));
        return false;
    }
    WpsAttributes decrypted{};
    if (!decrypted.parse(plain, plainLength)) {
        crypto::secureZero(plain, sizeof(plain));
        return fail(error, "invalid decrypted M7 attributes");
    }
    const WpsAttribute* ssid = decrypted.find(ATTR_SSID);
    const WpsAttribute* authType = decrypted.find(ATTR_AUTH_TYPE);
    const WpsAttribute* encrType = decrypted.find(ATTR_ENCR_TYPE);
    const WpsAttribute* networkKey = decrypted.find(ATTR_NETWORK_KEY);
    if (ssid == nullptr || ssid->length == 0 || ssid->length > sizeof(result.ssid) ||
        authType == nullptr || authType->length != 2 ||
        encrType == nullptr || encrType->length != 2 ||
        networkKey == nullptr || networkKey->length == 0 ||
        networkKey->length > sizeof(result.networkKey)) {
        crypto::secureZero(plain, sizeof(plain));
        return fail(error, "M7 missing AP settings");
    }
    std::memcpy(result.ssid, ssid->value, ssid->length);
    result.ssidLength = ssid->length;
    result.authenticationType = readBe16(authType->value);
    result.encryptionType = readBe16(encrType->value);
    std::memcpy(result.networkKey, networkKey->value, networkKey->length);
    result.networkKeyLength = networkKey->length;
    const WpsAttribute* networkKeyIndex = decrypted.find(ATTR_NETWORK_KEY_INDEX);
    if (networkKeyIndex != nullptr && networkKeyIndex->length == 1) {
        result.networkKeyIndex = networkKeyIndex->value[0];
    }
    const WpsAttribute* macAddress = decrypted.find(ATTR_MAC_ADDR);
    if (macAddress != nullptr && macAddress->length == 6) {
        std::memcpy(result.apMacAddress, macAddress->value, 6);
        result.hasApMacAddress = true;
    }
    crypto::secureZero(plain, sizeof(plain));
    return true;
}

bool buildRegistrarWscAck(
    const uint8_t enrolleeNonce[16],
    const uint8_t registrarNonce[16],
    uint8_t* attributes,
    size_t capacity,
    size_t& length,
    const char** error) {
    length = 0;
    if (enrolleeNonce == nullptr || registrarNonce == nullptr || attributes == nullptr) {
        return fail(error, "invalid WSC_ACK input");
    }
    BufferWriter writer(attributes, capacity);
    const uint8_t version = 0x10;
    const uint8_t messageType = MSG_WSC_ACK;
    const uint8_t wfaExtension[] = {0x00, 0x37, 0x2a, 0x00, 0x01, 0x20};
    if (!writer.appendAttribute(ATTR_VERSION, &version, 1) ||
        !writer.appendAttribute(ATTR_MESSAGE_TYPE, &messageType, 1) ||
        !writer.appendAttribute(ATTR_ENROLLEE_NONCE, enrolleeNonce, 16) ||
        !writer.appendAttribute(ATTR_REGISTRAR_NONCE, registrarNonce, 16) ||
        !writer.appendAttribute(ATTR_VENDOR_EXT, wfaExtension, sizeof(wfaExtension))) {
        return fail(error, "WSC_ACK payload exceeded buffer");
    }
    length = writer.length();
    return true;
}

bool buildRegistrarM8(
    const uint8_t* m7Attributes,
    size_t m7Length,
    const uint8_t enrolleeNonce[16],
    const RegistrarM7Result& credentials,
    const uint8_t authKey[crypto::kSha256Length],
    const uint8_t keyWrapKey[16],
    const uint8_t iv[16],
    RegistrarM8Result& result,
    const char** error) {
    result = RegistrarM8Result{};
    if (m7Attributes == nullptr || m7Length == 0 || enrolleeNonce == nullptr ||
        authKey == nullptr || keyWrapKey == nullptr || iv == nullptr ||
        credentials.ssidLength == 0 || credentials.ssidLength > sizeof(credentials.ssid) ||
        credentials.networkKeyLength == 0 ||
        credentials.networkKeyLength > sizeof(credentials.networkKey)) {
        return fail(error, "invalid M8 input");
    }
    uint8_t plain[256];
    BufferWriter plainWriter(plain, sizeof(plain));
    const uint8_t authType[] = {
        static_cast<uint8_t>(credentials.authenticationType >> 8),
        static_cast<uint8_t>(credentials.authenticationType & 0xff),
    };
    const uint8_t encrType[] = {
        static_cast<uint8_t>(credentials.encryptionType >> 8),
        static_cast<uint8_t>(credentials.encryptionType & 0xff),
    };
    const bool plainBuilt =
        plainWriter.appendAttribute(ATTR_SSID, credentials.ssid, credentials.ssidLength) &&
        (credentials.hasApMacAddress
             ? plainWriter.appendAttribute(ATTR_MAC_ADDR, credentials.apMacAddress, 6)
             : true) &&
        plainWriter.appendAttribute(ATTR_AUTH_TYPE, authType, sizeof(authType)) &&
        plainWriter.appendAttribute(ATTR_ENCR_TYPE, encrType, sizeof(encrType)) &&
        plainWriter.appendAttribute(
            ATTR_NETWORK_KEY,
            credentials.networkKey,
            credentials.networkKeyLength) &&
        appendKeyWrapAuthenticator(plainWriter, authKey);

    BufferWriter writer(result.attributes, sizeof(result.attributes));
    const uint8_t version = 0x10;
    const uint8_t messageType = MSG_M8;
    const bool built =
        plainBuilt &&
        writer.appendAttribute(ATTR_VERSION, &version, 1) &&
        writer.appendAttribute(ATTR_MESSAGE_TYPE, &messageType, 1) &&
        writer.appendAttribute(ATTR_ENROLLEE_NONCE, enrolleeNonce, 16) &&
        appendEncryptedSettings(
            writer,
            plainWriter.data(),
            plainWriter.length(),
            keyWrapKey,
            iv) &&
        writer.appendAttribute(ATTR_VENDOR_EXT, kWfaExtension, sizeof(kWfaExtension));
    crypto::secureZero(plain, sizeof(plain));
    if (!built) {
        return fail(error, "M8 payload exceeded buffer");
    }
    const size_t withoutAuthenticatorLength = writer.length();
    uint8_t authenticator[crypto::kSha256Length];
    const uint8_t* parts[] = {m7Attributes, writer.data()};
    const size_t lengths[] = {m7Length, withoutAuthenticatorLength};
    if (!crypto::hmacSha256(
            authKey,
            crypto::kSha256Length,
            parts,
            lengths,
            2,
            authenticator) ||
        !writer.appendAttribute(
            ATTR_AUTHENTICATOR,
            authenticator,
            kKeyWrapAuthenticatorLength)) {
        crypto::secureZero(authenticator, sizeof(authenticator));
        return fail(error, "failed to append M8 Authenticator");
    }
    crypto::secureZero(authenticator, sizeof(authenticator));
    result.attributesLength = writer.length();
    return true;
}

}  // namespace wps
