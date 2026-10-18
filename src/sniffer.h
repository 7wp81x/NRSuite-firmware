#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"

// Tunables
#define SNIFF_SNAPLEN      400
#define SNIFF_QUEUE_DEPTH  24
#define SNIFF_MAX_INFLIGHT 4
#define CLIENT_EVENT_QUEUE_DEPTH 24

struct CapturedFrame {
    uint16_t cap_len;
    uint16_t orig_len;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  data[SNIFF_SNAPLEN];
};

struct ClientEvent {
    uint8_t  client[6];
    uint8_t  bssid[6];
    bool     hasBssid;
    char     ssid[33];
    uint8_t  subtype;
    int8_t   rssi;
    uint8_t  channel;
};

struct SniffStats {
    uint32_t captured = 0;
    uint32_t sent     = 0;
    uint32_t dropped  = 0;
};

class Sniffer {
public:
    void begin(BridgeProtocol& proto);
    static Sniffer* instance() { return _instance; }

    bool startFixed(uint8_t channel, bool include5ghz = false);
    bool startHop(uint16_t intervalMs, bool include5ghz = false);
    bool startClientFixed(uint8_t channel, bool include5ghz = false);
    bool startClientHop(uint16_t intervalMs, bool include5ghz = false);
    void stop();
    bool setChannel(uint8_t channel);

    void setEapolFilter(bool enable, const uint8_t bssid[6] = nullptr, bool allBeacons = false);

    void processQueue();
    void handleHop();
    void onAck(uint32_t chunkIndex);

    bool       active()  const { return _active; }
    uint8_t    channel() const { return _channel; }
    bool       hopping() const { return _hopMode; }
    bool       clientOnly() const { return _clientOnly; }
    SniffStats stats()   const { return _stats; }

private:
    BridgeProtocol* _proto = nullptr;
    QueueHandle_t   _queue = nullptr;
    QueueHandle_t   _clientQueue = nullptr;

    bool     _active       = false;
    bool     _hopMode      = false;
    bool     _clientOnly   = false;
    uint8_t  _channel      = 1;
    uint16_t _hopIntervalMs = 300;
    uint32_t _lastHopMs    = 0;
    bool     _include5ghz  = false;
    const uint8_t* _hopChannels = nullptr;
    uint8_t  _hopCount     = 0;
    uint8_t  _hopIndex     = 0;

    volatile int _inFlight = 0;
    uint8_t      _chunkCtr = 0;

    bool    _eapolOnly      = false;
    bool    _beaconCaptured = false;
    bool    _captureAllBeacons = false;
    static const uint8_t MAX_BEACON_BSSIDS = 24;
    uint8_t _beaconBssids[MAX_BEACON_BSSIDS][6] = {};
    uint8_t _beaconBssidCount = 0;
    bool    _hasTargetBssid = false;
    uint8_t _targetBssid[6] = {0};
    
    SniffStats _stats;

    static Sniffer* _instance;
    static void promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type);
    void   handlePacket(wifi_promiscuous_pkt_t* pkt);
    size_t buildRadiotap(uint8_t* out, uint8_t channel, int8_t rssi);
    bool   isEapolFrame(const wifi_promiscuous_pkt_t* pkt) const;
    bool   isBeaconFrame(const wifi_promiscuous_pkt_t* pkt) const;
    bool   isAssociationRequest(const wifi_promiscuous_pkt_t* pkt) const;
    bool   matchesTargetBssid(const wifi_promiscuous_pkt_t* pkt) const;
    bool   startFixedInternal(uint8_t channel, bool clientOnly, bool include5ghz);
    bool   startHopInternal(uint16_t intervalMs, bool clientOnly, bool include5ghz);
    bool   isValidChannel(uint8_t channel, bool include5ghz) const;
    void   processClientEvents();
    bool   enqueueClientEvent(wifi_promiscuous_pkt_t* pkt);
};