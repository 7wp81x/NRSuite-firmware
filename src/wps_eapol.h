#pragma once

#include <cstddef>
#include <cstdint>

namespace wps {

constexpr uint8_t WFA_VENDOR_ID_0 = 0x00;
constexpr uint8_t WFA_VENDOR_ID_1 = 0x37;
constexpr uint8_t WFA_VENDOR_ID_2 = 0x2a;
constexpr uint32_t WSC_VENDOR_TYPE = 0x00000001;

constexpr size_t kWlanHeaderLength = 24;
constexpr size_t kLlcSnapLength = 8;
constexpr size_t kEapolHeaderLength = 4;

bool buildEapolStart(uint8_t* eapol, size_t capacity, size_t& length);

bool buildEapIdentityResponse(
    uint8_t* eapol,
    size_t capacity,
    uint8_t eapId,
    const char* identity,
    size_t& length);

bool buildEapWscMessage(
    uint8_t* eapol,
    size_t capacity,
    uint8_t eapCode,
    uint8_t eapId,
    uint8_t opcode,
    const uint8_t* wpsAttributes,
    size_t wpsLength,
    size_t& length);

bool buildWlanAuthenticationRequest(
    uint8_t* frame,
    size_t capacity,
    const uint8_t bssid[6],
    const uint8_t station[6],
    size_t& frameLength);

bool buildWlanAssociationRequest(
    uint8_t* frame,
    size_t capacity,
    const uint8_t bssid[6],
    const uint8_t station[6],
    const uint8_t* informationElements,
    size_t informationElementsLength,
    size_t& frameLength);

bool buildWlanEapolFrame(
    uint8_t* frame,
    size_t capacity,
    const uint8_t destination[6],
    const uint8_t source[6],
    const uint8_t bssid[6],
    const uint8_t* eapol,
    size_t eapolLength,
    size_t& frameLength);

}  // namespace wps
