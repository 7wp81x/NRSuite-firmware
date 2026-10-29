#include "wps_eapol.h"

#include <cstring>

namespace wps {
namespace {

void writeBe16(uint8_t* output, uint16_t value) {
    output[0] = static_cast<uint8_t>(value >> 8);
    output[1] = static_cast<uint8_t>(value & 0xff);
}

bool append(uint8_t* output, size_t capacity, size_t& offset,
            const uint8_t* data, size_t length) {
    if (length > capacity - offset) {
        return false;
    }
    std::memcpy(output + offset, data, length);
    offset += length;
    return true;
}

}  // namespace

bool buildEapolStart(uint8_t* eapol, size_t capacity, size_t& length) {
    if (eapol == nullptr || capacity < 4) {
        return false;
    }
    eapol[0] = 0x01;  // 802.1X-2001
    eapol[1] = 0x01;  // EAPOL-Start
    eapol[2] = 0x00;
    eapol[3] = 0x00;
    length = 4;
    return true;
}

bool buildEapIdentityResponse(
    uint8_t* eapol,
    size_t capacity,
    uint8_t eapId,
    const char* identity,
    size_t& length) {
    if (eapol == nullptr || identity == nullptr) {
        return false;
    }
    const size_t identityLength = std::strlen(identity);
    const size_t eapLength = 5 + identityLength;
    const size_t eapolLength = 4 + eapLength;
    if (eapLength > 0xffff || eapolLength > capacity) {
        return false;
    }

    size_t offset = 0;
    const uint8_t header[] = {0x01, 0x00};
    if (!append(eapol, capacity, offset, header, sizeof(header))) {
        return false;
    }
    uint8_t eapolLengthBytes[2];
    writeBe16(eapolLengthBytes, static_cast<uint16_t>(eapLength));
    if (!append(eapol, capacity, offset, eapolLengthBytes, sizeof(eapolLengthBytes))) {
        return false;
    }

    const uint8_t eapHeader[] = {
        0x02,  // Response
        eapId,
        0x00,  // length high byte, filled below
        0x00,  // length low byte, filled below
        0x01,  // Identity
    };
    if (!append(eapol, capacity, offset, eapHeader, sizeof(eapHeader))) {
        return false;
    }
    eapol[6] = static_cast<uint8_t>(eapLength >> 8);
    eapol[7] = static_cast<uint8_t>(eapLength & 0xff);
    if (!append(eapol, capacity, offset,
                reinterpret_cast<const uint8_t*>(identity), identityLength)) {
        return false;
    }
    length = offset;
    return true;
}

bool buildEapWscMessage(
    uint8_t* eapol,
    size_t capacity,
    uint8_t eapCode,
    uint8_t eapId,
    uint8_t opcode,
    const uint8_t* wpsAttributes,
    size_t wpsLength,
    size_t& length) {
    if (eapol == nullptr || (wpsAttributes == nullptr && wpsLength != 0)) {
        return false;
    }
    const size_t eapLength = 14 + wpsLength;
    const size_t eapolLength = 4 + eapLength;
    if (eapLength > 0xffff || eapolLength > capacity) {
        return false;
    }

    size_t offset = 0;
    const uint8_t eapolHeader[] = {0x01, 0x00, 0x00, 0x00};
    if (!append(eapol, capacity, offset, eapolHeader, sizeof(eapolHeader))) {
        return false;
    }
    writeBe16(eapol + 2, static_cast<uint16_t>(eapLength));

    const uint8_t eapPrefix[] = {
        eapCode,
        eapId,
        0x00,
        0x00,
        0xfe,  // Expanded EAP
        WFA_VENDOR_ID_0,
        WFA_VENDOR_ID_1,
        WFA_VENDOR_ID_2,
        0x00,
        0x00,
        0x00,
        0x01,  // WSC SimpleConfig vendor type
        opcode,
        0x00,  // flags: no fragmentation, no length field
    };
    if (!append(eapol, capacity, offset, eapPrefix, sizeof(eapPrefix))) {
        return false;
    }
    eapol[6] = static_cast<uint8_t>(eapLength >> 8);
    eapol[7] = static_cast<uint8_t>(eapLength & 0xff);
    if (!append(eapol, capacity, offset, wpsAttributes, wpsLength)) {
        return false;
    }
    length = offset;
    return true;
}

bool buildWlanAuthenticationRequest(
    uint8_t* frame,
    size_t capacity,
    const uint8_t bssid[6],
    const uint8_t station[6],
    size_t& frameLength) {
    constexpr size_t kAuthenticationFrameLength = 30;
    if (frame == nullptr || bssid == nullptr || station == nullptr ||
        capacity < kAuthenticationFrameLength) {
        return false;
    }
    std::memset(frame, 0, kAuthenticationFrameLength);
    frame[0] = 0xb0;  // Management: Authentication
    frame[1] = 0x00;
    std::memcpy(frame + 4, bssid, 6);
    std::memcpy(frame + 10, station, 6);
    std::memcpy(frame + 16, bssid, 6);
    // Fixed authentication body: Open System, sequence 1, status 0.
    frame[24] = 0x00;
    frame[25] = 0x00;
    frame[26] = 0x01;  // authentication transaction sequence 1 (little-endian)
    frame[27] = 0x00;
    frame[28] = 0x00;
    frame[29] = 0x00;
    frameLength = kAuthenticationFrameLength;
    return true;
}

bool buildWlanAssociationRequest(
    uint8_t* frame,
    size_t capacity,
    const uint8_t bssid[6],
    const uint8_t station[6],
    const uint8_t* informationElements,
    size_t informationElementsLength,
    size_t& frameLength) {
    constexpr size_t kAssociationFixedLength = 28;
    const size_t totalLength = kAssociationFixedLength + informationElementsLength;
    if (frame == nullptr || bssid == nullptr || station == nullptr ||
        (informationElements == nullptr && informationElementsLength != 0) ||
        capacity < totalLength) {
        return false;
    }
    std::memset(frame, 0, totalLength);
    frame[0] = 0x00;  // Management: Association Request
    frame[1] = 0x00;
    std::memcpy(frame + 4, bssid, 6);
    std::memcpy(frame + 10, station, 6);
    std::memcpy(frame + 16, bssid, 6);
    // Capabilities 0x1411 and listen interval 2, matching the successful
    // OneShot association request capture.
    frame[24] = 0x11;
    frame[25] = 0x14;
    frame[26] = 0x02;
    frame[27] = 0x00;
    if (informationElementsLength != 0) {
        std::memcpy(frame + kAssociationFixedLength, informationElements,
                    informationElementsLength);
    }
    frameLength = totalLength;
    return true;
}

bool buildWlanEapolFrame(
    uint8_t* frame,
    size_t capacity,
    const uint8_t destination[6],
    const uint8_t source[6],
    const uint8_t bssid[6],
    const uint8_t* eapol,
    size_t eapolLength,
    size_t& frameLength) {
    if (frame == nullptr || destination == nullptr || source == nullptr ||
        bssid == nullptr || eapol == nullptr) {
        return false;
    }
    constexpr size_t kQosDataHeaderLength = 26;
    const size_t totalLength = kQosDataHeaderLength + kLlcSnapLength + eapolLength;
    if (totalLength > capacity) {
        return false;
    }

    std::memset(frame, 0, totalLength);
    frame[0] = 0x88;  // QoS Data
    frame[1] = 0x01;  // To DS
    frame[2] = 0x2c;
    frame[3] = 0x00;
    std::memcpy(frame + 4, destination, 6);
    std::memcpy(frame + 10, source, 6);
    std::memcpy(frame + 16, bssid, 6);
    // frame[24..25] = QoS control 0.

    const uint8_t llcSnap[] = {
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
    };
    std::memcpy(frame + kQosDataHeaderLength, llcSnap, sizeof(llcSnap));
    std::memcpy(frame + kQosDataHeaderLength + kLlcSnapLength, eapol, eapolLength);
    frameLength = totalLength;
    return true;
}

}  // namespace wps
