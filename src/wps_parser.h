#pragma once

#include <cstddef>
#include <cstdint>

namespace wps {

// WPS attribute identifiers used by the registration protocol.
constexpr uint16_t ATTR_AUTHENTICATOR = 0x1005;
constexpr uint16_t ATTR_AUTH_TYPE = 0x1003;
constexpr uint16_t ATTR_ENCRYPTED_SETTINGS = 0x1018;
constexpr uint16_t ATTR_ENROLLEE_NONCE = 0x101a;
constexpr uint16_t ATTR_DEVICE_PASSWORD_ID = 0x1012;
constexpr uint16_t ATTR_MESSAGE_TYPE = 0x1022;
constexpr uint16_t ATTR_PUBLIC_KEY = 0x1032;
constexpr uint16_t ATTR_REGISTRAR_NONCE = 0x1039;
constexpr uint16_t ATTR_RF_BANDS = 0x103c;
constexpr uint16_t ATTR_E_HASH1 = 0x1014;
constexpr uint16_t ATTR_E_HASH2 = 0x1015;
constexpr uint16_t ATTR_E_SNONCE1 = 0x1016;
constexpr uint16_t ATTR_E_SNONCE2 = 0x1017;
constexpr uint16_t ATTR_KEY_WRAP_AUTH = 0x101e;
constexpr uint16_t ATTR_MAC_ADDR = 0x1020;
constexpr uint16_t ATTR_NETWORK_KEY = 0x1027;
constexpr uint16_t ATTR_NETWORK_KEY_INDEX = 0x1028;
constexpr uint16_t ATTR_R_HASH1 = 0x103d;
constexpr uint16_t ATTR_R_HASH2 = 0x103e;
constexpr uint16_t ATTR_R_SNONCE1 = 0x103f;
constexpr uint16_t ATTR_R_SNONCE2 = 0x1040;
constexpr uint16_t ATTR_SSID = 0x1045;
constexpr uint16_t ATTR_UUID_E = 0x1047;
constexpr uint16_t ATTR_UUID_R = 0x1048;
constexpr uint16_t ATTR_VENDOR_EXT = 0x1049;
constexpr uint16_t ATTR_VERSION = 0x104a;
constexpr uint16_t ATTR_ENCR_TYPE = 0x100f;
constexpr uint16_t ATTR_CREDENTIAL = 0x100e;

// WSC Message Type values.
constexpr uint8_t MSG_M1 = 0x04;
constexpr uint8_t MSG_M2 = 0x05;
constexpr uint8_t MSG_M2D = 0x06;
constexpr uint8_t MSG_M3 = 0x07;
constexpr uint8_t MSG_M4 = 0x08;
constexpr uint8_t MSG_M5 = 0x09;
constexpr uint8_t MSG_M6 = 0x0a;
constexpr uint8_t MSG_M7 = 0x0b;
constexpr uint8_t MSG_M8 = 0x0c;
constexpr uint8_t MSG_WSC_ACK = 0x0d;
constexpr uint8_t MSG_WSC_NACK = 0x0e;
constexpr uint8_t MSG_WSC_DONE = 0x0f;

// EAP-WSC OP-Code values.
constexpr uint8_t WSC_OP_START = 0x01;
constexpr uint8_t WSC_OP_ACK = 0x02;
constexpr uint8_t WSC_OP_NACK = 0x03;
constexpr uint8_t WSC_OP_MSG = 0x04;
constexpr uint8_t WSC_OP_DONE = 0x05;
constexpr uint8_t WSC_OP_FRAG_ACK = 0x06;

constexpr size_t MAX_ATTRIBUTES = 64;

struct WpsAttribute {
    uint16_t type = 0;
    uint16_t length = 0;
    const uint8_t* value = nullptr;
};

struct EapWscFrame {
    uint8_t eap_code = 0;
    uint8_t eap_id = 0;
    uint8_t opcode = 0;
    uint8_t flags = 0;
    uint16_t total_length = 0;
    const uint8_t* wps_data = nullptr;
    size_t wps_length = 0;
};

class WpsAttributes {
public:
    bool parse(const uint8_t* data, size_t length);
    const WpsAttribute* find(uint16_t type) const;
    const WpsAttribute& at(size_t index) const { return attributes_[index]; }
    size_t size() const { return count_; }

private:
    WpsAttribute attributes_[MAX_ATTRIBUTES];
    size_t count_ = 0;
};

// Parses an EAPOL/EAP-WSC packet and locates the WPS TLV payload.
// `data` must point at the EAPOL header (version, type, length).
bool parseEapolWsc(const uint8_t* data, size_t length, EapWscFrame& frame, const char** error = nullptr);

uint16_t readBe16(const uint8_t* data);
uint32_t readBe32(const uint8_t* data);

bool isMessageType(const WpsAttributes& attributes, uint8_t expected);

}  // namespace wps
