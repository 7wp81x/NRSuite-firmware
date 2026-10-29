#include "wps_attempt_detector.h"
#include "wps_parser.h"

#include <ArduinoJson.h>
#include <cstring>

namespace {
constexpr uint8_t WIFI_2G_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
constexpr uint8_t WIFI_5G_CHANNELS[] = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
};

const char* stageNameForMessage(uint8_t messageType) {
    switch (messageType) {
        case wps::MSG_M1: return "M1";
        case wps::MSG_M2: return "M2";
        case wps::MSG_M2D: return "M2D";
        case wps::MSG_M3: return "M3";
        case wps::MSG_M4: return "M4";
        case wps::MSG_M5: return "M5";
        case wps::MSG_M6: return "M6";
        case wps::MSG_M7: return "M7";
        case wps::MSG_M8: return "M8";
        case wps::MSG_WSC_ACK: return "ACK";
        case wps::MSG_WSC_NACK: return "NACK";
        case wps::MSG_WSC_DONE: return "DONE";
        default: return nullptr;
    }
}

bool isQosDataFrame(uint8_t frameControl0) {
    return ((frameControl0 >> 2) & 0x03) == 2 &&
        (((frameControl0 >> 4) & 0x0f) & 0x08) != 0;
}

uint8_t findWscMessageType(const uint8_t* data, size_t length) {
    if (data == nullptr || length < 5) return 0;
    for (size_t index = 0; index + 5 <= length; ++index) {
        if (data[index] == 0x10 && data[index + 1] == 0x22 &&
            data[index + 2] == 0x00 && data[index + 3] == 0x01) {
            return data[index + 4];
        }
    }
    return 0;
}

void formatMac(char out[18], const uint8_t mac[6]) {
    snprintf(
        out,
        18,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}
}

WpsAttemptDetector* WpsAttemptDetector::instance_ = nullptr;

void WpsAttemptDetector::begin(BridgeProtocol& proto) {
    proto_ = &proto;
    instance_ = this;
    if (eventQueue_ == nullptr) {
        eventQueue_ = xQueueCreate(48, sizeof(AttemptEvent));
    }
}

void WpsAttemptDetector::promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (instance_ == nullptr || buf == nullptr) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    instance_->handlePacket(static_cast<const wifi_promiscuous_pkt_t*>(buf));
}

void WpsAttemptDetector::rememberApName(const uint8_t bssid[6], const char* ssid) {
    if (ssid == nullptr || ssid[0] == '\0') return;
    for (auto& entry : apNames_) {
        if (entry.used && memcmp(entry.bssid, bssid, 6) == 0) {
            strncpy(entry.ssid, ssid, sizeof(entry.ssid) - 1);
            entry.ssid[sizeof(entry.ssid) - 1] = '\0';
            return;
        }
    }
    for (auto& entry : apNames_) {
        if (!entry.used) {
            entry.used = true;
            memcpy(entry.bssid, bssid, 6);
            strncpy(entry.ssid, ssid, sizeof(entry.ssid) - 1);
            entry.ssid[sizeof(entry.ssid) - 1] = '\0';
            return;
        }
    }
}

void WpsAttemptDetector::enqueueAttempt(
    const uint8_t bssid[6],
    const uint8_t client[6],
    uint8_t channel,
    int8_t rssi,
    uint8_t stage,
    const char* stageName
) {
    if (eventQueue_ == nullptr) return;
    AttemptEvent event;
    memcpy(event.bssid, bssid, 6);
    memcpy(event.client, client, 6);
    event.channel = channel;
    event.rssi = rssi;
    event.stage = stage;
    event.seenMs = millis();
    if (stageName != nullptr) {
        strncpy(event.stageName, stageName, sizeof(event.stageName) - 1);
        event.stageName[sizeof(event.stageName) - 1] = '\0';
    }
    for (const auto& name : apNames_) {
        if (name.used && memcmp(name.bssid, bssid, 6) == 0) {
            strncpy(event.ssid, name.ssid, sizeof(event.ssid) - 1);
            event.ssid[sizeof(event.ssid) - 1] = '\0';
            break;
        }
    }
    xQueueSend(eventQueue_, &event, 0);
}

void WpsAttemptDetector::handlePacket(const wifi_promiscuous_pkt_t* pkt) {
    const uint8_t* frame = pkt->payload;
    const size_t length = pkt->rx_ctrl.sig_len;
    if (frame == nullptr || length < 24) return;

    const uint8_t frameControl0 = frame[0];
    const uint8_t type = (frameControl0 >> 2) & 0x03;
    const uint8_t subtype = (frameControl0 >> 4) & 0x0f;

    // Learn SSIDs from beacons/probe responses so attempt events can identify
    // the target AP without needing a separate active scan.
    if (type == 0 && (subtype == 8 || subtype == 5) && length >= 38) {
        size_t offset = 36;
        while (offset + 2 <= length) {
            const uint8_t elementId = frame[offset];
            const uint8_t elementLength = frame[offset + 1];
            offset += 2;
            if (elementLength > length - offset) break;
            if (elementId == 0) {
                char ssid[33] = {};
                const size_t copyLength = elementLength > 32 ? 32 : elementLength;
                if (copyLength > 0) {
                    memcpy(ssid, frame + offset, copyLength);
                }
                ssid[copyLength] = '\0';
                rememberApName(frame + 16, ssid);
                break;
            }
            offset += elementLength;
        }
        return;
    }

    if (type != 2) return;

    size_t offset = 24;
    if (isQosDataFrame(frameControl0)) offset += 2;
    if (length < offset + 8) return;
    size_t eapolOffset = 0;
    for (size_t index = offset; index + 8 <= length; ++index) {
        if (frame[index] == 0xAA && frame[index + 1] == 0xAA &&
            frame[index + 2] == 0x03 && frame[index + 3] == 0x00 &&
            frame[index + 4] == 0x00 && frame[index + 5] == 0x00 &&
            frame[index + 6] == 0x88 && frame[index + 7] == 0x8E) {
            eapolOffset = index + 8;
            break;
        }
    }
    if (eapolOffset == 0 || eapolOffset + 4 > length) return;

    const uint8_t* eapol = frame + eapolOffset;
    const size_t available = length - eapolOffset;
    if (available < 4 || eapol[1] != 0x00) return;

    const uint8_t frameControl1 = frame[1];
    const bool toDs = (frameControl1 & 0x01) != 0;
    const bool fromDs = (frameControl1 & 0x02) != 0;
    if (toDs == fromDs) return;

    const uint8_t* bssid = nullptr;
    const uint8_t* client = nullptr;
    if (toDs) {
        bssid = frame + 4;
        client = frame + 10;
    } else {
        client = frame + 4;
        bssid = frame + 10;
    }

    // EAP-Request/Response Identity is a useful early signal, especially when
    // immediately followed by WSC M1. Keep it as a low-risk observed session.
    if (available >= 9) {
        const uint8_t* eap = eapol + 4;
        const uint16_t eapLength = wps::readBe16(eap + 2);
        if (eapLength >= 5 && eapLength <= available - 4 && eap[4] == 0x01) {
            if (!matchesTarget(bssid)) return;
            enqueueAttempt(
                bssid,
                client,
                pkt->rx_ctrl.channel != 0 ? pkt->rx_ctrl.channel : channel_,
                pkt->rx_ctrl.rssi,
                1,
                "Identity"
            );
            return;
        }
    }

    uint8_t messageTypeValue = 0;

    // Prefer the strict parser when the frame is a complete, well-formed
    // EAP-WSC message.
    wps::EapWscFrame wscFrame;
    if (wps::parseEapolWsc(eapol, available, wscFrame)) {
        wps::WpsAttributes attributes;
        if (attributes.parse(wscFrame.wps_data, wscFrame.wps_length)) {
            const wps::WpsAttribute* messageType = attributes.find(wps::ATTR_MESSAGE_TYPE);
            if (messageType != nullptr && messageType->length >= 1) {
                messageTypeValue = messageType->value[0];
            }
        }
    }

    // Fallback: some APs send fragmented or vendor-padded WSC payloads that
    // fail strict whole-frame parsing. The Message Type attribute is still
    // plaintext in the first fragment and is enough for passive detection.
    if (messageTypeValue == 0 && available >= 18) {
        const uint8_t* eap = eapol + 4;
        const bool expandedWsc =
            eap[4] == 0xfe &&
            eap[5] == 0x00 && eap[6] == 0x37 && eap[7] == 0x2a &&
            wps::readBe32(eap + 8) == 0x00000001;
        if (expandedWsc) {
            const uint16_t eapLength = wps::readBe16(eap + 2);
            const size_t availableEap = available - 4;
            const size_t searchLength = eapLength >= 12
                ? (eapLength < availableEap ? eapLength : availableEap)
                : 0;
            if (searchLength > 12) {
                messageTypeValue = findWscMessageType(eap + 12, searchLength - 12);
            }
        }
    }

    const char* stageName = stageNameForMessage(messageTypeValue);
    if (stageName == nullptr) return;

    if (!matchesTarget(bssid)) return;
    enqueueAttempt(
        bssid,
        client,
        pkt->rx_ctrl.channel != 0 ? pkt->rx_ctrl.channel : channel_,
        pkt->rx_ctrl.rssi,
        messageTypeValue,
        stageName
    );
}

void WpsAttemptDetector::processEvent(const AttemptEvent& event) {
    Session* session = nullptr;
    for (auto& candidate : sessions_) {
        if (candidate.used &&
            memcmp(candidate.bssid, event.bssid, 6) == 0 &&
            memcmp(candidate.client, event.client, 6) == 0) {
            session = &candidate;
            break;
        }
    }
    if (session != nullptr && event.stage == wps::MSG_M1 &&
        session->lastStage != wps::MSG_M1 &&
        (session->lastStage == wps::MSG_M8 ||
         session->lastStage == wps::MSG_WSC_NACK ||
         session->lastStage == wps::MSG_WSC_DONE ||
         event.seenMs - session->lastSeenMs > 3000)) {
        session = nullptr;
    }

    bool started = false;
    if (session == nullptr) {
        for (auto& candidate : sessions_) {
            if (!candidate.used) {
                session = &candidate;
                break;
            }
        }
        if (session == nullptr) session = &sessions_[0];
        *session = Session{};
        session->used = true;
        session->id = nextSessionId_++;
        memcpy(session->bssid, event.bssid, 6);
        memcpy(session->client, event.client, 6);
        session->firstSeenMs = event.seenMs;
        sessionCount_++;
        started = true;
    }

    if (event.ssid[0] != '\0') {
        strncpy(session->ssid, event.ssid, sizeof(session->ssid) - 1);
        session->ssid[sizeof(session->ssid) - 1] = '\0';
    }
    session->channel = event.channel;
    session->rssi = event.rssi;
    session->lastStage = event.stage;
    strncpy(session->lastStageName, event.stageName, sizeof(session->lastStageName) - 1);
    session->lastStageName[sizeof(session->lastStageName) - 1] = '\0';
    session->lastSeenMs = event.seenMs;
    session->frames++;
    frameCount_++;

    if (proto_ == nullptr) return;
    char bssid[18];
    char client[18];
    formatMac(bssid, session->bssid);
    formatMac(client, session->client);
    JsonDocument doc;
    doc["state"] = started ? "started" : "progress";
    doc["session_id"] = session->id;
    doc["bssid"] = bssid;
    doc["client"] = client;
    doc["ssid"] = session->ssid;
    doc["channel"] = session->channel;
    doc["rssi"] = session->rssi;
    doc["stage"] = session->lastStageName;
    doc["message_type"] = session->lastStage;
    doc["frames"] = session->frames;
    doc["first_seen_ms"] = session->firstSeenMs;
    doc["last_seen_ms"] = session->lastSeenMs;
    doc["duration_ms"] = session->lastSeenMs - session->firstSeenMs;
    proto_->sendEvent("wps_attempt_session", doc);
}

bool WpsAttemptDetector::matchesTarget(const uint8_t bssid[6]) const {
    if (targetCount_ == 0) return true;
    for (size_t index = 0; index < targetCount_; ++index) {
        if (memcmp(targetBssids_[index], bssid, 6) == 0) return true;
    }
    return false;
}

void WpsAttemptDetector::hop() {
    if (!active_ || !hopping_) return;
    if (millis() - lastHopMs_ < hopIntervalMs_) return;
    if (hopChannelCount_ == 0) return;
    lastHopMs_ = millis();
    hopIndex_ = (uint8_t)((hopIndex_ + 1) % hopChannelCount_);
    channel_ = hopChannels_[hopIndex_];
    esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
}

bool WpsAttemptDetector::start(
    const uint8_t* channels,
    size_t channelCount,
    const uint8_t* targetBssids,
    size_t targetCount,
    uint16_t hopIntervalMs,
    bool include5ghz
) {
    stop();
    hopChannelCount_ = 0;
    if (channelCount > 0) {
        for (size_t index = 0; index < channelCount && hopChannelCount_ < 64; ++index) {
            const uint8_t channel = channels[index];
            bool duplicate = false;
            for (size_t existing = 0; existing < hopChannelCount_; ++existing) {
                if (hopChannels_[existing] == channel) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) hopChannels_[hopChannelCount_++] = channel;
        }
    }
    if (hopChannelCount_ == 0) {
        for (uint8_t channel : WIFI_2G_CHANNELS) {
            hopChannels_[hopChannelCount_++] = channel;
        }
        if (include5ghz) {
            for (uint8_t channel : WIFI_5G_CHANNELS) {
                if (hopChannelCount_ < 64) hopChannels_[hopChannelCount_++] = channel;
            }
        }
    }
    if (hopChannelCount_ == 0) return false;

    targetCount_ = 0;
    if (targetBssids != nullptr && targetCount > 0) {
        targetCount_ = targetCount > 32 ? 32 : targetCount;
        memcpy(targetBssids_, targetBssids, targetCount_ * 6);
    }

    active_ = true;
    hopping_ = hopChannelCount_ > 1;
    include5ghz_ = include5ghz;
    channel_ = hopChannels_[0];
    hopIndex_ = 0;
    hopIntervalMs_ = constrain(hopIntervalMs, 100, 2000);
    lastHopMs_ = millis();
    sessionCount_ = 0;
    frameCount_ = 0;
    nextSessionId_ = 1;
    memset(sessions_, 0, sizeof(sessions_));
    memset(apNames_, 0, sizeof(apNames_));
    if (eventQueue_ != nullptr) xQueueReset(eventQueue_);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&WpsAttemptDetector::promiscuousCb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
    return true;
}

void WpsAttemptDetector::stop() {
    active_ = false;
    hopping_ = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}

void WpsAttemptDetector::update() {
    if (!active_) return;
    hop();
    if (eventQueue_ == nullptr) return;
    AttemptEvent event;
    while (xQueueReceive(eventQueue_, &event, 0) == pdTRUE) {
        processEvent(event);
    }
}
