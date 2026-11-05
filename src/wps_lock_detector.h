#pragma once

#include <Arduino.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"
#include "scan_results.h"
#include "wps_scan_merge.h"

class WpsLockDetector {
public:
    void begin(BridgeProtocol& proto);
    int scan(bool include5ghz, uint16_t dwellMs, bool emitEvents = true);
    size_t resultCount() const { return recordCount_; }
    void appendResults(ScanResultStore& store) const;

private:
    using ApRecord = WpsScanRecord;

    static WpsLockDetector* instance_;
    static void promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type);

    BridgeProtocol* proto_ = nullptr;
    ApRecord records_[64];
    size_t recordCount_ = 0;
    uint8_t currentChannel_ = 0;

    void handlePacket(const wifi_promiscuous_pkt_t* pkt);
    void discoverActiveWpsCandidates(bool include5ghz);
    void upsert(const ApRecord& record);
};
