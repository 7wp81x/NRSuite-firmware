#pragma once

#include <Arduino.h>
#include <esp_wifi.h>

#include "BridgeProtocol.h"
#include "wps_crypto.h"
#include "wps_parser.h"
#include "wps_registrar.h"

#ifndef WPS_PIXIE_SUPPORTED
#define WPS_PIXIE_SUPPORTED 0
#endif

bool wpsPixieSupported();

class WpsPixieManager {
public:
    void begin(BridgeProtocol& proto);
    bool startAttempt(
        const String& bssid,
        const String& ssid,
        uint8_t channel,
        const String& pin,
        const String& runId,
        bool captureOnly,
        bool reuseMac,
        String& error);
    bool continueWithRecoveredPin(
        const String& runId,
        const String& pin,
        String& error);
    void stop();
    void update();
    bool active() const;

private:
    enum class State : uint8_t {
        Idle,
        StartPending,
        WaitLockCheck,
        WaitAuthResponse,
        WaitAssocResponse,
        WaitIdentity,
        WaitM1,
        WaitM3,
        WaitRecoveredPin,
        WaitM5,
        WaitM7,
        WaitWscDone,
        Complete,
        Failed,
    };

    struct RxFrame {
        bool management;
        uint8_t data[768];
        uint16_t length;
    };

    static void promiscuousCallbackStatic(void* buffer, wifi_promiscuous_pkt_type_t type);
    void promiscuousCallback(void* buffer, wifi_promiscuous_pkt_type_t type);
    void processManagementFrame(const uint8_t* frame, size_t length);
    void processEapol(const uint8_t* data, size_t length);
    void drainQueue();

    bool prepareRadio(String& error);
    bool sendRawFrame(const uint8_t* frame, size_t length, const char* label);
    bool sendAuthenticationRequest();
    bool sendAssociationRequest();
    bool sendNullFrame();
    bool sendEapol(const uint8_t* eapol, size_t length, const char* label);
    bool sendEapolStart();
    bool sendIdentityResponse(uint8_t eapId);
    bool sendWscAttributes(uint8_t eapId, const uint8_t* attributes, size_t length, const char* label);
    bool sendWscOpcode(uint8_t eapId, uint8_t opcode, const uint8_t* attributes, size_t length, const char* label);
    bool sendWscFragmentAck(uint8_t eapId);
    bool sendWscNack(uint8_t eapId);
    bool sendDeauthFrame();
    bool sendDisassocFrame();
    void handleLockBeacon(const uint8_t* frame, size_t length);
    bool startRawAssociation();
    int reassembleWscFragment(const wps::EapWscFrame& frame, wps::EapWscFrame& complete);
    void rememberWscRequest(const wps::EapWscFrame& frame);
    void rememberWscReply(const uint8_t* attributes, size_t length);
    void enablePromiscuous();
    void disablePromiscuous();
    void cleanupRadioState();

    void handleM1(const wps::EapWscFrame& frame);
    void handleM2D();
    void handleM3(const wps::EapWscFrame& frame);
    void handleM5(const wps::EapWscFrame& frame);
    void handleM7(const wps::EapWscFrame& frame);
    void rotateStationMacForRetry();
    void handleWscDone(const wps::EapWscFrame& frame);
    void handleWscNack(const wps::EapWscFrame& frame);

    void emitProgress(const char* stage, const String& message);
    void appendRxDiagnostics(JsonDocument& doc) const;
    void emitWrongPin(bool firstHalfValid, bool firstHalfKnown, bool m3Only);
    void emitPsk(const uint8_t* key, size_t keyLength);
    void emitError(const char* code, const String& message);
    void fail(const char* code, const String& message);
    void finish();
    String bytesToHex(const uint8_t* data, size_t length) const;
    String pskText(const uint8_t* data, size_t length) const;

    BridgeProtocol* proto_ = nullptr;
    State state_ = State::Idle;
    QueueHandle_t rxQueue_ = nullptr;
    bool promiscuous_ = false;
    bool resultSent_ = false;
    bool captureOnly_ = false;
    bool associated_ = false;
    bool reuseMac_ = false;
    bool reusableMacValid_ = false;
    bool sawLock_ = false;
    bool sawWpsBeacon_ = false;
    bool lockKnown_ = false;
    bool lockSet_ = false;
    bool fragmentActive_ = false;

    String runId_;
    String ssid_;
    String pin_;
    uint8_t targetBssid_[6]{};
    uint8_t channel_ = 3;
    uint8_t stationMac_[6]{};
    uint8_t originalStationMac_[6]{};
    uint8_t reusableMac_[6]{};
    uint8_t reusableMacBssid_[6]{};
    bool macChanged_ = false;

    uint32_t startedMs_ = 0;
    uint32_t lastActivityMs_ = 0;
    uint32_t lastManagementTxMs_ = 0;
    uint32_t lastEapolTxMs_ = 0;
    uint32_t m3WaitStartedMs_ = 0;
    uint32_t m1WaitStartedMs_ = 0;
    uint32_t recoveredPinWaitStartedMs_ = 0;
    uint32_t wscDoneWaitStartedMs_ = 0;
    uint32_t lockCheckStartedMs_ = 0;
    uint32_t lockSeenMs_ = 0;
    uint8_t m3RetryCount_ = 0;

    // Bounded receive diagnostics. These are included in WPS error events so a
    // timeout can be distinguished from a filter/queue/parser failure.
    uint32_t rxEapolSeen_ = 0;
    uint32_t rxEapolQueued_ = 0;
    uint32_t rxEapolDropped_ = 0;
    uint32_t rxEapolParsed_ = 0;
    uint32_t rxM1Count_ = 0;
    uint32_t rxM2DCount_ = 0;
    uint32_t rxM3Count_ = 0;
    uint32_t rxM5Count_ = 0;
    uint32_t rxM7Count_ = 0;
    uint32_t rxAckCount_ = 0;
    uint32_t rxNackCount_ = 0;
    uint32_t lastRxMs_ = 0;
    uint16_t lastRxEapolLength_ = 0;
    uint8_t lastRxEapCode_ = 0;
    uint8_t lastRxEapId_ = 0;
    uint8_t lastRxWpsMessage_ = 0;
    uint8_t lastRxFlags_ = 0;
    uint32_t rxEapolUnparsed_ = 0;
    uint8_t lastUnparsedEapCode_ = 0;
    uint8_t lastUnparsedEapId_ = 0;
    uint8_t lastUnparsedEapType_ = 0;
    uint32_t m2TxCount_ = 0;
    uint8_t lastM2EapId_ = 0;
    uint32_t lastM2TxMs_ = 0;

    uint8_t enrolleeNonce_[16]{};
    uint8_t registrarNonce_[16]{};
    uint8_t uuidR_[16]{};
    uint8_t enrolleePublicKey_[wps::crypto::kPublicKeyLength]{};
    uint8_t registrarPublicKey_[wps::crypto::kPublicKeyLength]{};
    uint8_t authKey_[wps::crypto::kSha256Length]{};
    uint8_t keyWrapKey_[16]{};
    uint8_t registrarSecretNonce2_[wps::kRegistrarSecretNonceLength]{};
    uint8_t eHash1_[32]{};
    uint8_t eHash2_[32]{};

    uint8_t lastM2_[wps::kRegistrarM2MaxLength]{};
    size_t lastM2Length_ = 0;
    uint8_t lastM3_[512]{};
    size_t lastM3Length_ = 0;
    uint8_t lastM3EapId_ = 0;
    uint8_t lastM4_[wps::kRegistrarM4MaxLength]{};
    size_t lastM4Length_ = 0;
    uint8_t lastM5_[512]{};
    size_t lastM5Length_ = 0;
    uint8_t lastM6_[wps::kRegistrarM6MaxLength]{};
    size_t lastM6Length_ = 0;
    wps::RegistrarM7Result pendingCredentials_{};

    uint8_t wscFragment_[1024]{};
    size_t wscFragmentLength_ = 0;
    size_t wscFragmentTotal_ = 0;
    uint8_t wscFragmentEapId_ = 0;
    uint8_t wscFragmentFlags_ = 0;
    uint8_t lastFragmentData_[768]{};
    size_t lastFragmentLength_ = 0;
    uint8_t lastFragmentEapId_ = 0;
    uint8_t lastFragmentFlags_ = 0;

    uint8_t lastWscRequest_[1024]{};
    size_t lastWscRequestLength_ = 0;
    bool haveLastWscRequest_ = false;
    uint8_t lastWscReply_[wps::kRegistrarM8MaxLength]{};
    size_t lastWscReplyLength_ = 0;
};
