#include "ble_scanner.h"

#ifdef ENABLE_BLE_HID

#include "ble_hid.h"

BleScanner* BleScanner::_instance = nullptr;

class ScannerCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) override {
        if (BleScanner::instance()) {
            BleScanner::instance()->onAdvertised(advertisedDevice);
        }
    }
};

static ScannerCallbacks scannerCallbacks;

void BleScanner::begin(BridgeProtocol& proto) {
    _proto = &proto;
    _instance = this;
    if (!_queue) {
        _queue = xQueueCreate(BLE_SCAN_QUEUE_DEPTH, sizeof(Event));
    }
}

bool BleScanner::start(
    bool active,
    uint16_t intervalMs,
    uint16_t windowMs,
    uint32_t minEmitMs
) {
    if (BleHid::isAdvertising() || BleHid::isConnected()) {
        return false;
    }

    if (_active) stop();

    BLEDevice::init("NRSuiteScanner");
    _scan = NimBLEDevice::getScan();
    if (!_scan) {
        BLEDevice::deinit(true);
        return false;
    }

    _minEmitMs = minEmitMs < 250 ? 250 : minEmitMs;
    memset(_recent, 0, sizeof(_recent));
    if (_queue) xQueueReset(_queue);

    _scan->setScanCallbacks(&scannerCallbacks, true);
    _scan->setActiveScan(active);
    _scan->setInterval(intervalMs);
    _scan->setWindow(windowMs > intervalMs ? intervalMs : windowMs);
    _scan->setDuplicateFilter(false);
    _scan->clearResults();

    _startedMs = millis();
    _active = _scan->start(0, false, true);
    return _active;
}

void BleScanner::stop() {
    bool hadScanner = _active || (_scan != nullptr);
    if (_scan) {
        if (_scan->isScanning()) _scan->stop();
        _scan->clearResults();
    }
    _active = false;
    _scan = nullptr;
    if (hadScanner) {
        BLEDevice::deinit(true);
    }
}

bool BleScanner::scanning() const {
    return _active && _scan && _scan->isScanning();
}

bool BleScanner::shouldEmit(const char* address) {
    if (!address || !address[0]) return false;

    uint32_t now = millis();
    int emptyIndex = -1;
    int oldestIndex = 0;
    uint32_t oldestMs = 0xFFFFFFFF;

    for (int i = 0; i < BLE_SCAN_RECENT_CACHE; i++) {
        RecentEntry& entry = _recent[i];
        if (entry.used && strcmp(entry.address, address) == 0) {
            if (now - entry.lastMs < _minEmitMs) return false;
            entry.lastMs = now;
            return true;
        }
        if (!entry.used && emptyIndex < 0) emptyIndex = i;
        if (entry.used && entry.lastMs < oldestMs) {
            oldestMs = entry.lastMs;
            oldestIndex = i;
        }
    }

    int index = emptyIndex >= 0 ? emptyIndex : oldestIndex;
    RecentEntry& entry = _recent[index];
    strncpy(entry.address, address, sizeof(entry.address) - 1);
    entry.address[sizeof(entry.address) - 1] = '\0';
    entry.lastMs = now;
    entry.used = true;
    return true;
}

void BleScanner::macToHexString(const uint8_t* data, size_t len, char* out, size_t outSize) {
    if (!out || outSize == 0) return;
    out[0] = '\0';
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 2 < outSize; i++) {
        pos += snprintf(out + pos, outSize - pos, "%02X", data[i]);
    }
}

void BleScanner::onAdvertised(const NimBLEAdvertisedDevice* device) {
    if (!_active || !device || !_queue) return;

    String address = device->getAddress().toString().c_str();
    address.toUpperCase();
    if (address.length() == 0) return;
    if (!shouldEmit(address.c_str())) return;

    Event event{};
    strncpy(event.address, address.c_str(), sizeof(event.address) - 1);
    event.address[sizeof(event.address) - 1] = '\0';

    String name = device->getName().c_str();
    if (name.length() > 0) {
        strncpy(event.name, name.c_str(), sizeof(event.name) - 1);
        event.name[sizeof(event.name) - 1] = '\0';
    }

    event.addressType = device->getAddressType();
    event.rssi = device->getRSSI();
    event.connectable = device->isConnectable();
    event.txPower = device->getTXPower();
    event.appearance = device->getAppearance();
    event.uptimeMs = millis();

    std::string manufacturer = device->getManufacturerData();
    if (!manufacturer.empty() && manufacturer.length() <= sizeof(event.manufacturer)) {
        event.manufacturerLength = manufacturer.length();
        memcpy(event.manufacturer, manufacturer.data(), event.manufacturerLength);
    }

    const std::vector<uint8_t>& rawPayload = device->getPayload();
    if (!rawPayload.empty() && rawPayload.size() <= sizeof(event.rawPayload)) {
        event.rawPayloadLength = rawPayload.size();
        memcpy(event.rawPayload, rawPayload.data(), event.rawPayloadLength);
    }

    for (uint8_t i = 0; i < device->getServiceUUIDCount() && i < BLE_SCAN_MAX_SERVICES; i++) {
        String uuid = device->getServiceUUID(i).toString().c_str();
        uuid.toUpperCase();
        strncpy(event.services[event.serviceCount], uuid.c_str(), sizeof(event.services[event.serviceCount]) - 1);
        event.services[event.serviceCount][sizeof(event.services[event.serviceCount]) - 1] = '\0';
        event.serviceCount++;
    }

    if (xQueueSend(_queue, &event, 0) != pdTRUE) {
        // Drop silently; the app can rescan if needed.
    }
}

void BleScanner::update() {
    if (!_proto || !_queue) return;

    Event event;
    while (xQueueReceive(_queue, &event, 0) == pdTRUE) {
        JsonDocument doc;
        doc["address"] = event.address;
        doc["address_type"] = event.addressType;
        doc["rssi"] = event.rssi;
        doc["connectable"] = event.connectable;
        doc["tx_power"] = event.txPower;
        doc["appearance"] = event.appearance;
        doc["uptime_ms"] = event.uptimeMs;

        if (event.name[0] != '\0') {
            doc["name"] = event.name;
        }
        if (event.manufacturerLength > 0) {
            char hex[65];
            macToHexString(event.manufacturer, event.manufacturerLength, hex, sizeof(hex));
            doc["manufacturer_data"] = hex;
        }
        if (event.rawPayloadLength > 0) {
            char hex[129];
            macToHexString(event.rawPayload, event.rawPayloadLength, hex, sizeof(hex));
            doc["raw_payload"] = hex;
        }
        if (event.serviceCount > 0) {
            JsonArray services = doc["services"].to<JsonArray>();
            for (uint8_t i = 0; i < event.serviceCount; i++) {
                services.add(event.services[i]);
            }
        }

        _proto->sendEvent("ble_device", doc);
    }
}

#endif // ENABLE_BLE_HID
