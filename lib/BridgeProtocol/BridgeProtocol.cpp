#include "BridgeProtocol.h"

void BridgeProtocol::addTransport(Stream& stream, const char* transportName) {
    if (_transportCount >= PROTO_MAX_TRANSPORTS) return;
    for (uint8_t i = 0; i < _transportCount; ++i) {
        if (_transports[i].stream == &stream) return;
    }
    _transports[_transportCount].stream = &stream;
    _transports[_transportCount].name = transportName ? transportName : "unknown";
    _transports[_transportCount].bufLen = 0;
    ++_transportCount;
}

void BridgeProtocol::begin() {
    if (!_txMutex) {
        _txMutex = xSemaphoreCreateMutex();
    }
}

void BridgeProtocol::update() {
    for (uint8_t i = 0; i < _transportCount; ++i) {
        Transport& transport = _transports[i];
        if (transport.stream == nullptr) continue;

        while (transport.stream->available()) {
            if (transport.bufLen < sizeof(transport.buf)) {
                transport.buf[transport.bufLen++] = transport.stream->read();
            } else {
                _resync(transport);
                if (transport.bufLen >= sizeof(transport.buf)) {
                    memmove(transport.buf, transport.buf + 1, --transport.bufLen);
                }
            }
            while (_tryParse(transport));
        }
    }
}

bool BridgeProtocol::_tryParse(Transport& transport) {
    if (transport.bufLen < PROTO_HEADER_SZ) return false;

    uint8_t  ptype = 0;
    uint8_t  pid   = 0;
    uint32_t len   = 0;
    if (!protoDecodeHeader(transport.buf, transport.bufLen, ptype, pid, len)) {
        _resync(transport);
        return false;
    }

    if (len > PROTO_MAX_CHUNK) {
        _oversizedFrames++;
        _resync(transport);
        return false;
    }

    uint32_t total = PROTO_HEADER_SZ + len;
    if (total > sizeof(transport.buf)) {
        _oversizedFrames++;
        _resync(transport);
        return false;
    }

    if (transport.bufLen < total) {
        return false;
    }

    ProtoFrame f;
    f.type    = ptype;
    f.id      = pid;
    f.length  = len;
    f.payload = transport.buf + PROTO_HEADER_SZ;
    f.valid   = true;

    _dispatch(f, transport);

    // Shift buffer
    memmove(transport.buf, transport.buf + total, transport.bufLen - total);
    transport.bufLen -= total;
    return true;
}

void BridgeProtocol::_resync(Transport& transport) {
    if (transport.bufLen < 2) {
        transport.bufLen = 0;
        return;
    }
    for (uint32_t i = 1; i < transport.bufLen - 1; i++) {
        if (transport.buf[i] == PROTO_MAGIC_0 && transport.buf[i+1] == PROTO_MAGIC_1) {
            memmove(transport.buf, transport.buf + i, transport.bufLen - i);
            transport.bufLen -= i;
            return;
        }
    }
    transport.bufLen = 0;  // nothing found, discard everything
}

// ── _dispatch — route frame to correct callback ───────────────────────────────
void BridgeProtocol::_dispatch(ProtoFrame& f, Transport& transport) {
    // The most recent valid frame selects the transport for responses and
    // asynchronous events. The app only opens one physical port at a time.
    for (uint8_t i = 0; i < _transportCount; ++i) {
        if (&_transports[i] == &transport) {
            _activeTransport = i;
            break;
        }
    }

    if (f.type == TYPE_CMD && _onCmd) {
        JsonDocument* doc = new JsonDocument();
        if (!doc) return;  // OOM
        
        DeserializationError err = deserializeJson(*doc, f.payload, f.length);
        if (!err) {
            _onCmd(f.id, *doc);
        }
        delete doc;
    }
    else if (f.type == TYPE_ACK && _onAck) {
        JsonDocument* doc = new JsonDocument();
        if (!doc) return;

        DeserializationError err = deserializeJson(*doc, f.payload, f.length);
        if (!err && (*doc)["chunk"].is<uint32_t>()) {
            _onAck((*doc)["chunk"].as<uint32_t>());
        }
        delete doc;
    }

    else if (f.type == TYPE_HTML) {
        if (_onHtml) {
            _onHtml(f.payload, f.length);
        }
    }
}

// ── sendResp ──────────────────────────────────────────────────────────────────
void BridgeProtocol::sendResp(uint8_t id, bool ok, const char* msg) {
    JsonDocument doc;
    doc["ok"] = ok;
    if (msg) doc["msg"] = msg;
    doc["transport"] = activeTransportName();
    String json;
    serializeJson(doc, json);
    sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
}

// ── sendEvent ─────────────────────────────────────────────────────────────────
void BridgeProtocol::sendEvent(const char* type, JsonDocument& doc) {
    doc["type"] = type;
    String json;
    serializeJson(doc, json);
    sendRaw(TYPE_EVENT, 0, (const uint8_t*)json.c_str(), json.length());
}

// ── sendPcapChunk ─────────────────────────────────────────────────────────────
void BridgeProtocol::sendPcapChunk(uint8_t chunk_idx, const uint8_t* data, uint32_t len) {
    sendRaw(TYPE_PCAP, chunk_idx, data, len);
}

// ── sendRaw — write a complete frame to the active stream ────────────────────
void BridgeProtocol::sendRaw(uint8_t type, uint8_t id, const uint8_t* payload, uint32_t len) {
    if (_transportCount == 0) return;
    if (_activeTransport >= _transportCount) _activeTransport = 0;
    Stream* stream = _transports[_activeTransport].stream;
    if (stream == nullptr) return;

    // AsyncWebServer callbacks and the main loop can emit frames concurrently.
    // Keep header+payload contiguous so PCAP/event frames cannot interleave.
    if (_txMutex) xSemaphoreTake(_txMutex, portMAX_DELAY);

    uint8_t header[PROTO_HEADER_SZ];
    header[0] = PROTO_MAGIC_0;
    header[1] = PROTO_MAGIC_1;
    header[2] = type;
    header[3] = id;
    memcpy(header + 4, &len, 4);  // little-endian
    stream->write(header, PROTO_HEADER_SZ);
    if (len > 0 && payload) {
        stream->write(payload, len);
    }

    if (_txMutex) xSemaphoreGive(_txMutex);
}

void BridgeProtocol::flushActive() {
    if (_transportCount == 0) return;
    if (_activeTransport >= _transportCount) _activeTransport = 0;
    Stream* stream = _transports[_activeTransport].stream;
    if (stream == nullptr) return;
    if (_txMutex) xSemaphoreTake(_txMutex, portMAX_DELAY);
    stream->flush();
    if (_txMutex) xSemaphoreGive(_txMutex);
}

const char* BridgeProtocol::activeTransportName() const {
    if (_transportCount == 0) return "unknown";
    const uint8_t index = _activeTransport < _transportCount ? _activeTransport : 0;
    return _transports[index].name;
}
