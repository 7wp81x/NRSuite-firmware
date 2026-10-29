#include "wps_parser.h"

namespace wps {
namespace {

bool fail(const char** error, const char* message) {
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

}  // namespace

uint16_t readBe16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t readBe32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

bool WpsAttributes::parse(const uint8_t* data, size_t length) {
    count_ = 0;
    if (data == nullptr && length != 0) {
        return false;
    }

    size_t offset = 0;
    while (offset < length) {
        if (length - offset < 4) {
            return false;
        }
        const uint16_t type = readBe16(data + offset);
        const uint16_t attributeLength = readBe16(data + offset + 2);
        offset += 4;
        if (attributeLength > length - offset) {
            return false;
        }
        if (count_ >= MAX_ATTRIBUTES) {
            return false;
        }
        attributes_[count_++] = WpsAttribute{
            .type = type,
            .length = attributeLength,
            .value = data + offset,
        };
        offset += attributeLength;
    }
    return true;
}

const WpsAttribute* WpsAttributes::find(uint16_t type) const {
    for (size_t index = 0; index < count_; ++index) {
        if (attributes_[index].type == type) {
            return &attributes_[index];
        }
    }
    return nullptr;
}

bool parseEapolWsc(const uint8_t* data, size_t length, EapWscFrame& frame, const char** error) {
    frame = EapWscFrame{};
    if (data == nullptr || length < 4) {
        return fail(error, "short EAPOL header");
    }
    if (data[1] != 0x00) {
        return fail(error, "EAPOL is not an EAP packet");
    }

    const uint16_t eapolLength = readBe16(data + 2);
    if (eapolLength < 4 || static_cast<size_t>(eapolLength) + 4 > length) {
        return fail(error, "invalid EAPOL length");
    }

    const uint8_t* eap = data + 4;
    const size_t eapAvailable = eapolLength;
    if (eapAvailable < 5) {
        return fail(error, "short EAP header");
    }

    const uint16_t eapLength = readBe16(eap + 2);
    if (eapLength < 5 || eapLength > eapAvailable) {
        return fail(error, "invalid EAP length");
    }
    if (eap[4] != 0xfe) {
        return fail(error, "EAP type is not expanded");
    }

    // Expanded EAP: vendor-id (3), vendor-type (4), WSC opcode (1), flags (1).
    if (eapLength < 14) {
        return fail(error, "short EAP-WSC header");
    }
    if (eap[5] != 0x00 || eap[6] != 0x37 || eap[7] != 0x2a) {
        return fail(error, "not a Wi-Fi Alliance expanded EAP frame");
    }
    if (readBe32(eap + 8) != 0x00000001) {
        return fail(error, "expanded EAP type is not WSC SimpleConfig");
    }

    frame.eap_code = eap[0];
    frame.eap_id = eap[1];
    frame.opcode = eap[12];
    frame.flags = eap[13];
    if ((frame.flags & ~0x03) != 0) {
        return fail(error, "unsupported EAP-WSC fragment flags");
    }

    size_t wpsOffset = 14;
    size_t wpsLength = eapLength - wpsOffset;
    if ((frame.flags & 0x02) != 0) {
        if (eapLength < 16) {
            return fail(error, "missing EAP-WSC length field");
        }
        frame.total_length = readBe16(eap + 14);
        wpsOffset = 16;
        wpsLength = eapLength - wpsOffset;
        if (frame.total_length == 0) {
            return fail(error, "invalid EAP-WSC total length");
        }
        if ((frame.flags & 0x01) == 0 && frame.total_length != wpsLength) {
            return fail(error, "EAP-WSC total length mismatch");
        }
    }

    frame.wps_data = eap + wpsOffset;
    frame.wps_length = wpsLength;
    return true;
}

bool isMessageType(const WpsAttributes& attributes, uint8_t expected) {
    const WpsAttribute* messageType = attributes.find(ATTR_MESSAGE_TYPE);
    return messageType != nullptr &&
           messageType->length == 1 &&
           messageType->value != nullptr &&
           messageType->value[0] == expected;
}

}  // namespace wps
