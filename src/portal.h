// portal.h
#pragma once
#include <Arduino.h>
#include <FS.h>
#include <ESPAsyncWebServer.h>
#include <DNSServer.h>
#include "BridgeProtocol.h"
#include "sniffer.h"

class PortalManager {
public:
    void begin(BridgeProtocol& proto);
    bool start(const char* ssid, uint8_t channel, const uint8_t* targetBssid = nullptr,
               bool showNotice = true, String* error = nullptr);
    void stop();
    bool setHtmlChunk(const uint8_t* data, size_t len, bool isLast = false,
                      size_t offset = 0, bool hasOffset = false);
    bool isRunning() const { return _running; }
    void update();   // call in loop()

    bool isComplete() const { return _htmlComplete; }
    size_t getBufferSize() const { return _htmlLen; }
    size_t getExpectedSize() const { return _htmlExpected; }
    bool resetHtml(size_t expectedSize = 0);


private:
    AsyncWebServer* _server = nullptr;
    DNSServer* _dnsServer = nullptr;
    BridgeProtocol* _proto = nullptr;
    bool _running = false;
    bool _showNotice = true;
    bool _storageMounted = false;
    bool _apStarted = false;
    File _htmlFile;
    uint8_t _targetBssid[6] = {0};
    bool _hasTarget = false;
    bool _htmlComplete = false;
    size_t   _htmlLen    = 0;
    size_t   _htmlExpected = 0;
    int      _loginAttempts = 0;
    TaskHandle_t _deauthTaskHandle = nullptr;
    static String _servedSnapshot;
    static void deauthTaskFn(void* pvParameters);

    bool setupDNSSpoof();
    bool setupHttpServer(String* error);
    void setupRoutes();
    void teardownServerAndDns();
    void cleanupFailedStart();
    bool restoreIdleAp();
    void emitClientSeen(AsyncWebServerRequest* request, const char* requestType);
    bool emitCaptiveData(AsyncWebServerRequest* request, const char* requestType,
                         bool ignoreAttemptArg = false);
    String loadingPlaceholder() const;
    String noticePage() const;
    void sendPortalContent(AsyncWebServerRequest* request);
    bool mountPortalStorage();
    void unmountPortalStorage();

};

extern PortalManager portal;