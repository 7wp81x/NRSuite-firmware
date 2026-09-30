#include "ble_profile.h"

#ifdef ENABLE_BLE_HID

#include "ble_hid.h"
#include "ble_scanner.h"

BleProfile* BleProfile::_instance = nullptr;

void BleProfile::begin(BridgeProtocol& proto) {
    _proto = &proto;
    _instance = this;
    if (!_queue) {
        _queue = xQueueCreate(BLE_PROFILE_QUEUE_DEPTH, sizeof(Event));
    }
}

bool BleProfile::start(const char* address, uint8_t addressType) {
    if (_active || !address || !address[0]) return false;
    if (BleHid::isAdvertising() || BleHid::isConnected()) return false;
    if (BleScanner::instance() && BleScanner::instance()->active()) return false;

    strncpy(_address, address, sizeof(_address) - 1);
    _address[sizeof(_address) - 1] = '\0';
    _addressType = addressType;
    _abort = false;
    _active = true;
    if (_queue) xQueueReset(_queue);

    BaseType_t ok = xTaskCreatePinnedToCore(
        taskEntry,
        "ble_profile",
        8192,
        this,
        1,
        &_task,
        1
    );
    if (ok != pdPASS) {
        _active = false;
        _task = nullptr;
        return false;
    }
    return true;
}

void BleProfile::stop() {
    _abort = true;
}

void BleProfile::queueEvent(const Event& event) {
    if (!_queue) return;
    xQueueSend(_queue, &event, 0);
}

void BleProfile::taskEntry(void* arg) {
    static_cast<BleProfile*>(arg)->taskLoop();
    vTaskDelete(nullptr);
}

void BleProfile::taskLoop() {
    Event event{};
    event.type = EventType::PROFILE;
    strncpy(event.address, _address, sizeof(event.address) - 1);
    strncpy(event.message, "connecting", sizeof(event.message) - 1);
    queueEvent(event);

    NimBLEDevice::init("NRSuiteProfiler");
    NimBLEClient* client = NimBLEDevice::createClient();
    if (!client) {
        Event failed{};
        failed.type = EventType::FAILED;
        strncpy(failed.address, _address, sizeof(failed.address) - 1);
        strncpy(failed.message, "failed to create BLE client", sizeof(failed.message) - 1);
        queueEvent(failed);
        _active = false;
        return;
    }

    client->setConnectTimeout(10000);
    bool connected = client->connect(NimBLEAddress(std::string(_address), _addressType), true);
    if (!connected || _abort) {
        client->disconnect();
        NimBLEDevice::deleteClient(client);
        NimBLEDevice::deinit(true);
        Event failed{};
        failed.type = EventType::FAILED;
        strncpy(failed.address, _address, sizeof(failed.address) - 1);
        strncpy(failed.message, _abort ? "profile stopped" : "connection failed", sizeof(failed.message) - 1);
        queueEvent(failed);
        _active = false;
        return;
    }

    Event connectedEvent{};
    connectedEvent.type = EventType::PROFILE;
    strncpy(connectedEvent.address, _address, sizeof(connectedEvent.address) - 1);
    strncpy(connectedEvent.message, "connected", sizeof(connectedEvent.message) - 1);
    queueEvent(connectedEvent);

    const std::vector<NimBLERemoteService*>& services = client->getServices(true);
    for (NimBLERemoteService* service : services) {
        if (_abort) break;

        std::string serviceUuid = service->getUUID().toString();
        Event serviceEvent{};
        serviceEvent.type = EventType::SERVICE;
        strncpy(serviceEvent.serviceUuid, serviceUuid.c_str(), sizeof(serviceEvent.serviceUuid) - 1);
        queueEvent(serviceEvent);

        const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
        for (NimBLERemoteCharacteristic* characteristic : chars) {
            if (_abort) break;

            Event chrEvent{};
            chrEvent.type = EventType::CHARACTERISTIC;
            strncpy(chrEvent.serviceUuid, serviceUuid.c_str(), sizeof(chrEvent.serviceUuid) - 1);
            std::string charUuid = characteristic->getUUID().toString();
            strncpy(chrEvent.characteristicUuid, charUuid.c_str(), sizeof(chrEvent.characteristicUuid) - 1);

            uint8_t props = 0;
            if (characteristic->canRead())            props |= 0x01;
            if (characteristic->canWrite())           props |= 0x02;
            if (characteristic->canWriteNoResponse()) props |= 0x04;
            if (characteristic->canNotify())          props |= 0x08;
            if (characteristic->canIndicate())        props |= 0x10;
            if (characteristic->canBroadcast())       props |= 0x20;
            chrEvent.properties = props;
            queueEvent(chrEvent);
        }
    }

    client->disconnect();
    NimBLEDevice::deleteClient(client);
    NimBLEDevice::deinit(true);
    _active = false;

    Event done{};
    done.type = _abort ? EventType::FAILED : EventType::DONE;
    strncpy(done.address, _address, sizeof(done.address) - 1);
    strncpy(done.message, _abort ? "profile stopped" : "profile complete", sizeof(done.message) - 1);
    queueEvent(done);
}

void BleProfile::update() {
    if (!_proto || !_queue) return;

    Event event;
    while (xQueueReceive(_queue, &event, 0) == pdTRUE) {
        JsonDocument doc;
        if (event.type == EventType::SERVICE) {
            doc["service_uuid"] = event.serviceUuid;
            _proto->sendEvent("ble_service", doc);
        } else if (event.type == EventType::CHARACTERISTIC) {
            doc["service_uuid"] = event.serviceUuid;
            doc["uuid"] = event.characteristicUuid;
            JsonObject props = doc["properties"].to<JsonObject>();
            props["read"] = (event.properties & 0x01) != 0;
            props["write"] = (event.properties & 0x02) != 0;
            props["write_no_response"] = (event.properties & 0x04) != 0;
            props["notify"] = (event.properties & 0x08) != 0;
            props["indicate"] = (event.properties & 0x10) != 0;
            props["broadcast"] = (event.properties & 0x20) != 0;
            _proto->sendEvent("ble_characteristic", doc);
        } else {
            doc["address"] = event.address;
            doc["status"] = event.type == EventType::DONE ? "done"
                             : event.type == EventType::FAILED ? "failed"
                             : event.message;
            _proto->sendEvent("ble_profile", doc);
        }
    }
}

#endif // ENABLE_BLE_HID
