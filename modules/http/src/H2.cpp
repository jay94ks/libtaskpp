// HTTP/2: framing, HPACK wiring, flow control, client + server sessions.
#include <taskpp/http/H2.hpp>

#include <taskpp/core/Worker.hpp>
#include <taskpp/tls/Tls.hpp>

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>

namespace taskpp::http {
using namespace taskpp::tls;
namespace {

// ------------------------------------------------------------ wire consts

constexpr uint8_t kData = 0x0;
constexpr uint8_t kHeaders = 0x1;
constexpr uint8_t kPriority = 0x2;
constexpr uint8_t kRst = 0x3;
constexpr uint8_t kSettings = 0x4;
constexpr uint8_t kPush = 0x5;
constexpr uint8_t kPing = 0x6;
constexpr uint8_t kGoAway = 0x7;
constexpr uint8_t kWindowUpdate = 0x8;
constexpr uint8_t kContinuation = 0x9;

constexpr uint8_t kFlagEndStream = 0x1;
constexpr uint8_t kFlagEndHeaders = 0x4;
constexpr uint8_t kFlagPadded = 0x8;
constexpr uint8_t kFlagAck = 0x1;

constexpr uint32_t kErrNoError = 0x0;
constexpr uint32_t kErrProtocol = 0x1;
constexpr uint32_t kErrFlowControl = 0x3;
constexpr uint32_t kErrRefusedStream = 0x7;
constexpr uint32_t kErrCancel = 0x8;
constexpr uint32_t kErrInternal = 0x2;
constexpr uint32_t kErrEnhanceYourCalm = 0xb;

constexpr uint16_t kSettingsHeaderTableSize = 0x1;
constexpr uint16_t kSettingsEnablePush = 0x2;
constexpr uint16_t kSettingsMaxConcurrentStreams = 0x3;
constexpr uint16_t kSettingsInitialWindowSize = 0x4;
constexpr uint16_t kSettingsMaxFrameSize = 0x5;
constexpr uint16_t kSettingsMaxHeaderListSize = 0x6;

constexpr uint32_t kDefaultWindow = 65535;
constexpr uint32_t kDefaultMaxFrame = 16384;
constexpr uint32_t kMaxWindow = 0x7FFFFFFF;

constexpr char kClientMagic[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr size_t kClientMagicLen = 24;

// ------------------------------------------------------------ frames

struct Frame {
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t stream = 0;
    std::vector<uint8_t> payload;
};

uint32_t getU32(const uint8_t* p) noexcept {
    return uint32_t { p[0] } << 24 | uint32_t { p[1] } << 16 | uint32_t { p[2] } << 8 | p[3];
}

void putU32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

Task<Frame> readFrame(Stream* stream, uint32_t maxFrame, Canceller canceller) {
    uint8_t hdr[9];
    try {
        co_await stream->readExact(std::span(reinterpret_cast<char*>(hdr), 9), canceller);
    }
    catch (const SocketClosed&) {
        throw H2Error("connection closed", kErrNoError);
    }
    const uint32_t length = uint32_t { hdr[0] } << 16 | uint32_t { hdr[1] } << 8 | hdr[2];
    if (length > maxFrame) {
        throw H2Error("frame too large", kErrProtocol);
    }
    Frame frame;
    frame.type = hdr[3];
    frame.flags = hdr[4];
    frame.stream = getU32(hdr + 5) & 0x7FFFFFFFu;
    if (hdr[5] & 0x80) {
        throw H2Error("reserved bit set", kErrProtocol);
    }
    frame.payload.resize(length);
    if (length > 0) {
        try {
            co_await stream->readExact(std::span(reinterpret_cast<char*>(frame.payload.data()), length),
                canceller);
        }
        catch (const SocketClosed&) {
            throw H2Error("connection closed", kErrNoError);
        }
    }
    co_return frame;
}

Task<void> writeFrame(Stream* stream, uint8_t type, uint8_t flags, uint32_t streamId,
    const uint8_t* payload, size_t n, Canceller canceller) {
    uint8_t hdr[9] = {
        static_cast<uint8_t>(n >> 16),
        static_cast<uint8_t>(n >> 8),
        static_cast<uint8_t>(n),
        type,
        flags,
        static_cast<uint8_t>(streamId >> 24),
        static_cast<uint8_t>(streamId >> 16),
        static_cast<uint8_t>(streamId >> 8),
        static_cast<uint8_t>(streamId),
    };
    co_await stream->write(std::span(reinterpret_cast<const char*>(hdr), 9), canceller);
    if (n > 0) {
        co_await stream->write(std::span(reinterpret_cast<const char*>(payload), n), canceller);
    }
    co_return;
}

Task<void> writeFrame(Stream* stream, uint8_t type, uint8_t flags, uint32_t streamId,
    const std::vector<uint8_t>& payload, Canceller canceller) {
    co_await writeFrame(stream, type, flags, streamId,
        payload.empty() ? nullptr : payload.data(), payload.size(), std::move(canceller));
    co_return;
}

// Strips padding; returns {data, consumedIncludingPad}.
std::span<const uint8_t> stripPadding(const std::vector<uint8_t>& payload, uint8_t flags) {
    if (!(flags & kFlagPadded)) {
        return { payload.data(), payload.size() };
    }
    if (payload.empty()) {
        throw H2Error("bad padding", kErrProtocol);
    }
    const size_t pad = payload[0];
    if (pad + 1 > payload.size()) {
        throw H2Error("bad padding", kErrProtocol);
    }
    return { payload.data() + 1, payload.size() - 1 - pad };
}

// ------------------------------------------------------------ hpack glue

std::string lower(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

bool isConnectionSpecific(const std::string& name) noexcept {
    return name == "connection" || name == "keep-alive" || name == "proxy-connection"
        || name == "transfer-encoding" || name == "upgrade";
}

std::vector<hpack::HeaderField> toFields(const H2Request& req) {
    if (req.method.empty() || req.authority.empty() || req.path.empty()) {
        throw H2Error("missing pseudo-header", kErrProtocol);
    }
    std::vector<hpack::HeaderField> fields = {
        { ":method", req.method },
        { ":scheme", req.scheme.empty() ? "http" : req.scheme },
        { ":authority", req.authority },
        { ":path", req.path },
    };
    for (const auto& h : req.headers) {
        const std::string name = lower(h.name);
        if (name.empty() || name[0] == ':' || isConnectionSpecific(name)) {
            if (!name.empty() && name[0] == ':') {
                throw H2Error("pseudo-header in headers", kErrProtocol);
            }
            continue; // drop connection-specific (curl does the same).
        }
        if (name == "te" && lower(h.value) != "trailers") {
            throw H2Error("bad te", kErrProtocol);
        }
        fields.push_back({ name, h.value });
    }
    return fields;
}

std::vector<hpack::HeaderField> toFields(const H2Response& res) {
    std::vector<hpack::HeaderField> fields = { { ":status", std::to_string(res.status) } };
    for (const auto& h : res.headers) {
        const std::string name = lower(h.name);
        if (name.empty() || name[0] == ':' || isConnectionSpecific(name)) {
            if (!name.empty() && name[0] == ':') {
                throw H2Error("pseudo-header in headers", kErrProtocol);
            }
            continue;
        }
        fields.push_back({ name, h.value });
    }
    return fields;
}

H2Request fromRequestFields(std::vector<hpack::HeaderField> fields) {
    H2Request req;
    bool seenRegular = false;
    bool method = false, scheme = false, authority = false, path = false;
    for (auto& f : fields) {
        if (!f.name.empty() && f.name[0] == ':') {
            if (seenRegular) {
                throw H2Error("pseudo after regular", kErrProtocol);
            }
            if (f.name == ":method" && !method) {
                req.method = std::move(f.value);
                method = true;
            }
            else if (f.name == ":scheme" && !scheme) {
                req.scheme = std::move(f.value);
                scheme = true;
            }
            else if (f.name == ":authority" && !authority) {
                req.authority = std::move(f.value);
                authority = true;
            }
            else if (f.name == ":path" && !path) {
                req.path = std::move(f.value);
                path = true;
            }
            else {
                throw H2Error("bad pseudo-header", kErrProtocol);
            }
        }
        else {
            seenRegular = true;
            if (f.name.empty() || isConnectionSpecific(f.name)) {
                throw H2Error("bad header", kErrProtocol);
            }
            req.headers.push_back({ std::move(f.name), std::move(f.value) });
        }
    }
    if (!method || !scheme || !authority || req.path.empty()) {
        throw H2Error("missing pseudo-header", kErrProtocol);
    }
    return req;
}

H2Response fromResponseFields(std::vector<hpack::HeaderField> fields) {
    H2Response res;
    bool seenRegular = false, status = false;
    for (auto& f : fields) {
        if (!f.name.empty() && f.name[0] == ':') {
            if (seenRegular || f.name != ":status" || status) {
                throw H2Error("bad pseudo-header", kErrProtocol);
            }
            status = true;
            if (f.value.size() != 3) {
                throw H2Error("bad status", kErrProtocol);
            }
            res.status = 0;
            for (char c : f.value) {
                if (c < '0' || c > '9') {
                    throw H2Error("bad status", kErrProtocol);
                }
                res.status = res.status * 10 + (c - '0');
            }
        }
        else {
            seenRegular = true;
            if (f.name.empty() || isConnectionSpecific(f.name)) {
                throw H2Error("bad header", kErrProtocol);
            }
            res.headers.push_back({ std::move(f.name), std::move(f.value) });
        }
    }
    if (!status) {
        throw H2Error("missing :status", kErrProtocol);
    }
    return res;
}

} // namespace

// ------------------------------------------------------------ client session

namespace {

// Per-stream state shared between the reader pump (producer) and the task
// awaiting the response (consumer).
struct ClientStream {
    H2Response response;
    std::string body;
    bool headersDone = false;
    bool done = false;
    bool failed = false;
    bool refused = false; // GOAWAY says this id was never processed.
    uint32_t error = 0;
    uint32_t id = 0;
    int64_t recvWnd = kDefaultWindow;
    int64_t sendWnd = kDefaultWindow;
    Channel<Frame> frames { 8 };
};

using ClientStreamPtr = std::shared_ptr<ClientStream>;

struct ClientSession {
    Stream* stream = nullptr;
    H2Limits limits;
    hpack::Encoder encoder;
    hpack::Decoder decoder;

    // One writer on the wire at a time; the pump shares it for control frames.
    AsyncMutex writeLock;
    AsyncMutex codecLock; // HPACK state, both directions.
    std::mutex mutex; // guards the fields below.
    std::map<uint32_t, ClientStreamPtr> streams;
    std::vector<H2Push> pushes;
    size_t reserved = 0; // slots handed out, not yet written.

    uint32_t nextId = 1;
    int64_t connSendWnd = kDefaultWindow;
    int64_t connRecvWnd = kDefaultWindow;
    uint32_t peerMaxFrame = kDefaultMaxFrame;
    uint32_t peerInitWnd = kDefaultWindow;
    uint32_t peerMaxConcurrent = 1; // raised to limits.maxStreams on first use
    bool goaway = false;
    uint32_t goawayLastId = 0;
    uint32_t goawayCode = 0;

    // Broadcast-ish wakeup for capacity and flow-control parking. Capacity is
    // sized well above the stream limit, so a dropped poke is impossible: a
    // full buffer already holds tokens for the waiters.
    Channel<char> wake { 64 };

    void poke() noexcept { wake.trySend(1); }

    // Must be called with `codecLock` held (the pump and `request` both do).
    void applySettings(const std::vector<uint8_t>& payload) {
        if (payload.size() % 6 != 0) {
            throw H2Error("bad settings", kErrProtocol);
        }
        std::vector<std::pair<uint16_t, uint32_t>> grants;
        for (size_t i = 0; i < payload.size(); i += 6) {
            const uint16_t id = uint16_t { payload[i] } << 8 | payload[i + 1];
            uint32_t value = getU32(payload.data() + i + 2);
            switch (id) {
            case kSettingsHeaderTableSize:
                grants.emplace_back(id, value);
                break;
            case kSettingsEnablePush:
                break; // informational: our own ENABLE_PUSH is already 0.
            case kSettingsMaxConcurrentStreams:
                if (value == 0) {
                    value = 1; // never sit below one, that would stall us.
                }
                if (value > limits.maxStreams) {
                    value = static_cast<uint32_t>(limits.maxStreams);
                }
                grants.emplace_back(id, value);
                break;
            case kSettingsInitialWindowSize:
                if (value > kMaxWindow) {
                    throw H2Error("bad window", kErrFlowControl);
                }
                grants.emplace_back(id, value);
                break;
            case kSettingsMaxFrameSize:
                if (value < kDefaultMaxFrame || value > 16777215) {
                    throw H2Error("bad max frame", kErrProtocol);
                }
                grants.emplace_back(id, value);
                break;
            case kSettingsMaxHeaderListSize:
            default:
                break; // ignore.
            }
        }
        std::lock_guard lock(mutex);
        for (const auto& [id, value] : grants) {
            switch (id) {
            case kSettingsHeaderTableSize:
                decoder.setMaxTableBytes(value);
                break;
            case kSettingsMaxConcurrentStreams:
                peerMaxConcurrent = value;
                break;
            case kSettingsInitialWindowSize: {
                // Live streams absorb the delta (RFC 9113 6.9.2).
                const int64_t delta = static_cast<int64_t>(value) - peerInitWnd;
                peerInitWnd = value;
                for (auto& entry : streams) {
                    entry.second->sendWnd += delta;
                    if (entry.second->sendWnd > kMaxWindow
                        || entry.second->sendWnd < -static_cast<int64_t>(kMaxWindow)) {
                        throw H2Error("window overflow", kErrFlowControl);
                    }
                }
                break;
            }
            case kSettingsMaxFrameSize:
                peerMaxFrame = value;
                break;
            default:
                break;
            }
        }
    }

    // Snapshot of every live stream, then empties the registry.
    std::vector<ClientStreamPtr> drain() {
        std::vector<ClientStreamPtr> out;
        std::lock_guard lock(mutex);
        out.reserve(streams.size());
        for (auto& entry : streams) {
            out.push_back(entry.second);
        }
        streams.clear();
        return out;
    }

    ClientStreamPtr find(uint32_t id) {
        std::lock_guard lock(mutex);
        const auto it = streams.find(id);
        return it == streams.end() ? nullptr : it->second;
    }

    void forget(uint32_t id) {
        ClientStreamPtr st;
        {
            std::lock_guard lock(mutex);
            const auto it = streams.find(id);
            if (it == streams.end()) {
                return;
            }
            st = it->second;
            streams.erase(it);
        }
        st->frames.close();
        poke(); // a slot just freed up: wake anyone parked on capacity.
    }
};

Task<void> sendControlFrame(ClientSession& s, uint8_t type, uint8_t flags, uint32_t stream,
    const std::vector<uint8_t>& payload, Canceller canceller) {
    auto guard = co_await s.writeLock.lock(canceller);
    co_await writeFrame(s.stream, type, flags, stream, payload, canceller);
    co_return;
}

std::vector<uint8_t> u32Payload(uint32_t v) {
    std::vector<uint8_t> out(4);
    out[0] = static_cast<uint8_t>(v >> 24);
    out[1] = static_cast<uint8_t>(v >> 16);
    out[2] = static_cast<uint8_t>(v >> 8);
    out[3] = static_cast<uint8_t>(v);
    return out;
}

// Writes one DATA run, releasing the wire lock while waiting for credit.
// END_STREAM goes on the final frame when `endStream` is set.
Task<void> sendData(ClientSession& s, ClientStream* st, const std::string& data,
    bool endStream, Canceller canceller) {
    size_t off = 0;
    while (off < data.size()) {
        size_t n = 0;
        {
            auto guard = co_await s.writeLock.lock(canceller);
            int64_t streamWnd = 0;
            int64_t connWnd = 0;
            uint32_t maxFrame = kDefaultMaxFrame;
            {
                std::lock_guard lock(s.mutex);
                streamWnd = st->sendWnd;
                connWnd = s.connSendWnd;
                maxFrame = s.peerMaxFrame;
            }
            n = std::min({ data.size() - off, size_t { maxFrame },
                connWnd > 0 ? static_cast<size_t>(connWnd) : size_t { 0 },
                streamWnd > 0 ? static_cast<size_t>(streamWnd) : size_t { 0 } });
            if (n == 0) {
                guard.unlock();
            }
            else {
                const bool last = endStream && off + n == data.size();
                co_await writeFrame(s.stream, kData, last ? kFlagEndStream : 0, st->id,
                    reinterpret_cast<const uint8_t*>(data.data() + off), n, canceller);
                std::lock_guard lock(s.mutex);
                st->sendWnd -= static_cast<int64_t>(n);
                s.connSendWnd -= static_cast<int64_t>(n);
            }
        }
        if (n == 0) {
            // No credit: park until the pump pokes us for a WINDOW_UPDATE.
            while (true) {
                co_await s.wake.receive(canceller);
                int64_t avail = 0;
                bool gone = false;
                {
                    std::lock_guard lock(s.mutex);
                    avail = std::min<int64_t>(st->sendWnd, s.connSendWnd);
                    gone = s.goaway;
                }
                if (avail > 0 || gone) {
                    break;
                }
            }
        }
        off += n;
    }
    co_return;
}

// Reads a header block that may be split over CONTINUATION frames. Padding is
// stripped from the first frame only; the result is the raw block.
Task<std::vector<uint8_t>> gatherHeaderBlock(ClientSession& s, uint32_t streamId, Frame first) {
    std::vector<uint8_t> block;
    const auto data = stripPadding(first.payload, first.flags);
    block.insert(block.end(), data.begin(), data.end());
    uint8_t flags = first.flags;
    while (!(flags & kFlagEndHeaders)) {
        if (block.size() > s.limits.maxHeaderBytes) {
            throw H2Error("header block too large", kErrEnhanceYourCalm);
        }
        uint32_t maxFrame = kDefaultMaxFrame;
        {
            std::lock_guard lock(s.mutex);
            maxFrame = s.peerMaxFrame;
        }
        Frame next = co_await readFrame(s.stream, maxFrame, { });
        if (next.type != kContinuation || next.stream != streamId) {
            throw H2Error("expected continuation", kErrProtocol);
        }
        flags = next.flags;
        block.insert(block.end(), next.payload.begin(), next.payload.end());
    }
    co_return block;
}

// Streams a pipe body as DATA frames, keeping one chunk of lookahead so the
// last frame can carry END_STREAM.
Task<void> sendPipe(ClientSession& s, ClientStream* st, const Body& body,
    Canceller canceller) {
    auto chunk = co_await body.next(canceller);
    if (!chunk) {
        // An empty pipe still has to close the stream.
        auto guard = co_await s.writeLock.lock(canceller);
        co_await writeFrame(s.stream, kData, kFlagEndStream, st->id, nullptr, 0, canceller);
        co_return;
    }
    while (chunk) {
        auto lookahead = co_await body.next(canceller);
        const bool last = !lookahead;
        co_await sendData(s, st, *chunk, last, canceller);
        chunk = std::move(lookahead);
    }
    co_return;
}

// The single reader for a client connection. Owns every inbound frame, routes
// stream frames to their owner and answers connection-level frames itself.
Task<void> pumpLoop(std::shared_ptr<ClientSession> s) {
    std::vector<ClientStreamPtr> onExit;
    try {
        while (true) {
            uint32_t maxFrame = kDefaultMaxFrame;
            {
                std::lock_guard lock(s->mutex);
                maxFrame = s->peerMaxFrame;
            }
            Frame frame;
            try {
                frame = co_await readFrame(s->stream, maxFrame, { });
            }
            catch (const SocketClosed&) {
                throw H2Error("connection closed", kErrNoError);
            }

            switch (frame.type) {
            case kSettings: {
                if (frame.stream != 0) {
                    throw H2Error("settings on stream", kErrProtocol);
                }
                if (frame.flags & kFlagAck) {
                    break;
                }
                {
                    auto codec = co_await s->codecLock.lock();
                    s->applySettings(frame.payload);
                }
                co_await sendControlFrame(*s, kSettings, kFlagAck, 0, { }, { });
                s->poke();
                break;
            }
            case kPing: {
                if (frame.stream != 0 || frame.payload.size() != 8) {
                    throw H2Error("bad ping", kErrProtocol);
                }
                if (!(frame.flags & kFlagAck)) {
                    co_await sendControlFrame(*s, kPing, kFlagAck, 0, frame.payload, { });
                }
                break;
            }
            case kGoAway: {
                if (frame.stream != 0 || frame.payload.size() < 8) {
                    throw H2Error("bad goaway", kErrProtocol);
                }
                std::vector<ClientStreamPtr> doomed;
                {
                    std::lock_guard lock(s->mutex);
                    s->goaway = true;
                    s->goawayLastId = getU32(frame.payload.data()) & 0x7FFFFFFFu;
                    s->goawayCode = getU32(frame.payload.data() + 4);
                    // Streams above the limit were never processed (RFC 9113 6.8).
                    for (auto& entry : s->streams) {
                        if (entry.first > s->goawayLastId) {
                            entry.second->refused = true;
                            doomed.push_back(entry.second);
                        }
                    }
                }
                for (const auto& st : doomed) {
                    st->frames.close();
                }
                s->poke();
                break;
            }
            case kWindowUpdate: {
                if (frame.payload.size() != 4) {
                    throw H2Error("bad window update", kErrProtocol);
                }
                const uint32_t inc = getU32(frame.payload.data()) & 0x7FFFFFFFu;
                if (inc == 0) {
                    throw H2Error("zero window increment", kErrProtocol);
                }
                {
                    std::lock_guard lock(s->mutex);
                    if (frame.stream == 0) {
                        s->connSendWnd += inc;
                        if (s->connSendWnd > kMaxWindow) {
                            throw H2Error("window overflow", kErrFlowControl);
                        }
                    }
                    else if (const auto st = s->find(frame.stream)) {
                        st->sendWnd += inc;
                        if (st->sendWnd > kMaxWindow) {
                            throw H2Error("window overflow", kErrFlowControl);
                        }
                    }
                }
                s->poke();
                break;
            }
            case kRst: {
                if (const auto st = s->find(frame.stream)) {
                    st->failed = true;
                    st->error = frame.payload.size() == 4
                        ? getU32(frame.payload.data()) : kErrInternal;
                    st->frames.close();
                    s->forget(frame.stream);
                    s->poke();
                }
                break;
            }
            case kPush: {
                // Pushes are refused (RFC 9113 8.4): record the promise, reset
                // the promised stream, keep the connection usable.
                if (frame.payload.size() < 4) {
                    throw H2Error("bad push promise", kErrProtocol);
                }
                const uint32_t promised = getU32(frame.payload.data()) & 0x7FFFFFFFu;
                if (promised == 0 || (promised % 2 != 0)) {
                    throw H2Error("bad push promise", kErrProtocol); // pushed ids are even
                }
                const uint32_t promisedOn = frame.stream;
                {
                    std::lock_guard lock(s->mutex);
                    if (s->goaway) {
                        break; // GOAWAY forbids further pushes.
                    }
                }
                const auto block = co_await gatherHeaderBlock(*s, promisedOn, std::move(frame));
                auto codec = co_await s->codecLock.lock();
                const auto fields = s->decoder.decode(block);
                codec.unlock();
                H2Push push;
                push.stream = promisedOn;
                push.promised = promised;
                for (const auto& f : fields) {
                    if (f.name == ":method") {
                        push.method = f.value;
                    }
                    else if (f.name == ":scheme") {
                        push.scheme = f.value;
                    }
                    else if (f.name == ":authority") {
                        push.authority = f.value;
                    }
                    else if (f.name == ":path") {
                        push.path = f.value;
                    }
                    else if (!f.name.empty() && f.name.front() != ':') {
                        push.headers.push_back({ f.name, f.value });
                    }
                }
                {
                    std::lock_guard lock(s->mutex);
                    s->pushes.push_back(std::move(push));
                }
                co_await sendControlFrame(*s, kRst, 0, promised, u32Payload(kErrCancel), { });
                break;
            }
            case kHeaders: {
                // Assembled here so CONTINUATION never interleaves (RFC 9113 4.3).
                const uint32_t id = frame.stream;
                frame.payload = co_await gatherHeaderBlock(*s, id, std::move(frame));
                if (const auto st = s->find(id)) {
                    st->frames.trySend(std::move(frame));
                }
                else if (id % 2 == 0 && !(frame.flags & kFlagEndStream)) {
                    co_await sendControlFrame(*s, kRst, 0, id, u32Payload(kErrCancel), { });
                }
                break;
            }
            case kData: {
                if (const auto st = s->find(frame.stream)) {
                    st->frames.trySend(std::move(frame));
                }
                else if (frame.stream % 2 == 0 && !(frame.flags & kFlagEndStream)) {
                    // A refused push still owes us its window credit back.
                    co_await sendControlFrame(
                        *s, kRst, 0, frame.stream, u32Payload(kErrCancel), { });
                }
                break;
            }
            case kPriority:
                break; // advisory only.
            case kContinuation:
                // Only legal inside gatherHeaderBlock, which consumes them.
                throw H2Error("unexpected continuation", kErrProtocol);
            default:
                break; // unknown frame types are ignored (RFC 9113 4.1).
            }
        }
    }
    catch (...) {
        onExit = s->drain();
    }

    s->wake.close();
    for (const auto& st : onExit) {
        st->frames.close();
    }
    co_return;
}

} // namespace

// ------------------------------------------------------------ H2Connection

struct H2Connection::State {
    std::unique_ptr<Stream> transport;
    std::shared_ptr<ClientSession> session;
};

H2Connection::~H2Connection() = default;
H2Connection::H2Connection(H2Connection&&) noexcept = default;
H2Connection& H2Connection::operator=(H2Connection&&) noexcept = default;

Task<H2Connection> H2Connection::connect(std::unique_ptr<Stream> stream,
    H2Limits limits, Canceller canceller, bool sendMagic) {
    if (!stream) {
        throw std::invalid_argument("H2Connection needs a stream.");
    }
    H2Connection conn;
    conn.state_ = std::make_unique<State>();
    conn.state_->transport = std::move(stream);
    auto s = std::make_shared<ClientSession>();
    s->stream = conn.state_->transport.get();
    s->limits = limits;
    // RFC 9113 6.5.2: absent MAX_CONCURRENT_STREAMS means unlimited, so our
    // own cap is the only limit until the peer says otherwise.
    s->peerMaxConcurrent = limits.maxStreams == 0
        ? 1u : static_cast<uint32_t>(limits.maxStreams);
    conn.state_->session = s;

    // Client preface: magic (h2c only) + SETTINGS. ENABLE_PUSH = 0 says we
    // never accept server push (RFC 9113 6.5.2).
    if (sendMagic) {
        co_await s->stream->write(std::span(kClientMagic, kClientMagicLen), canceller);
    }
    {
        std::vector<uint8_t> settings = { 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 };
        co_await writeFrame(s->stream, kSettings, 0, 0, settings, canceller);
    }

    // The first frame from the server MUST be SETTINGS.
    Frame first = co_await readFrame(s->stream, s->peerMaxFrame, canceller);
    if (first.type != kSettings) {
        throw H2Error("first frame is not settings", kErrProtocol);
    }
    if (first.flags & kFlagAck) {
        throw H2Error("unexpected settings ack", kErrProtocol);
    }
    s->applySettings(first.payload);
    co_await writeFrame(s->stream, kSettings, kFlagAck, 0, nullptr, 0, canceller);

    // From here on the pump owns every inbound frame.
    auto worker = Worker::currentWorker();
    if (!worker) {
        worker = Worker::defaultWorker();
    }
    worker->push(pumpLoop(s));
    co_return std::move(conn);
}

Task<H2Response> H2Connection::request(H2Request req, Canceller canceller) {
    if (!state_ || !state_->session) {
        throw H2Error("connection closed", kErrNoError);
    }
    ClientSession& s = *state_->session;

    // Take a concurrency slot: at most peerMaxConcurrent streams in flight. The
    // stream id is NOT assigned here -- it is assigned under the wire lock just
    // before HEADERS goes out, because RFC 9113 5.1.1 requires request
    // streams to be opened in strictly increasing id order, and concurrent
    // callers would otherwise race onto the socket out of order.
    auto st = std::make_shared<ClientStream>();
    {
        std::lock_guard lock(s.mutex);
        ++s.reserved;
    }
    bool registered = false;
    try {
        while (true) {
            {
                std::lock_guard lock(s.mutex);
                if (s.goaway && s.streams.empty() && s.reserved <= 1) {
                    throw H2Error("server sent GOAWAY", kErrRefusedStream);
                }
                if (!s.goaway && s.streams.size() + s.reserved <= s.peerMaxConcurrent) {
                    break;
                }
            }
            co_await s.wake.receive(canceller);
        }

        // The HPACK encoder is inherently sequential, and RFC 9113 5.1.1 wants
        // request streams opened in increasing id order. Taking both locks
        // together (always in this order) makes encode order, id order and
        // wire order the same sequence.
        {
            auto codec = co_await s.codecLock.lock(canceller);
            auto guard = co_await s.writeLock.lock(canceller);
            const std::vector<uint8_t> block = s.encoder.encode(toFields(req));
            {
                std::lock_guard lock(s.mutex);
                st->id = s.nextId;
                s.nextId += 2;
                st->sendWnd = s.peerInitWnd;
                if (s.reserved > 0) {
                    --s.reserved;
                }
                s.streams.emplace(st->id, st);
                registered = true;
            }
            uint8_t flags = kFlagEndHeaders;
            const bool pipe = req.body.isPipe();
            // A pipe has no known length, so END_STREAM rides on the last
            // DATA frame instead of the head.
            if (req.body.empty() && !pipe) {
                flags |= kFlagEndStream;
            }
            co_await writeFrame(s.stream, kHeaders, flags, st->id, block, canceller);
        }
        if (!req.body.isPipe()) {
            if (!req.body.bytes().empty()) {
                co_await sendData(s, st.get(), req.body.bytes(), true, canceller);
            }
        }
        else {
            co_await sendPipe(s, st.get(), req.body, canceller);
        }
    }
    catch (...) {
        {
            std::lock_guard lock(s.mutex);
            if (!registered && s.reserved > 0) {
                --s.reserved;
            }
        }
        if (registered) {
            s.forget(st->id);
        }
        throw;
    }
    s.poke(); // a slot is in flight; let queued requests through.

    try {
        while (!st->done && !st->failed && !st->refused) {
            const auto frame = co_await st->frames.receive(canceller);
            switch (frame.type) {
            case kHeaders: {
                auto codec = co_await s.codecLock.lock(canceller);
                const auto fields = s.decoder.decode(frame.payload);
                codec.unlock();
                if (!st->headersDone) {
                    st->response = fromResponseFields(fields);
                    st->headersDone = true;
                    st->done = (frame.flags & kFlagEndStream) != 0;
                }
                else if (frame.flags & kFlagEndStream) {
                    st->done = true; // trailers
                }
                break;
            }
            case kData: {
                const auto data = stripPadding(frame.payload, frame.flags);
                const auto n = static_cast<int64_t>(data.size());
                uint32_t streamInc = 0;
                uint32_t connInc = 0;
                {
                    std::lock_guard lock(s.mutex);
                    s.connRecvWnd -= n;
                    st->recvWnd -= n;
                    if (st->recvWnd <= 32768) {
                        streamInc = static_cast<uint32_t>(kDefaultWindow - st->recvWnd);
                        st->recvWnd = kDefaultWindow;
                    }
                    if (s.connRecvWnd <= 32768) {
                        connInc = static_cast<uint32_t>(kDefaultWindow - s.connRecvWnd);
                        s.connRecvWnd = kDefaultWindow;
                    }
                }
                if (streamInc != 0) {
                    co_await sendControlFrame(
                        s, kWindowUpdate, 0, st->id, u32Payload(streamInc), canceller);
                }
                if (connInc != 0) {
                    co_await sendControlFrame(
                        s, kWindowUpdate, 0, 0, u32Payload(connInc), canceller);
                }
                st->body.append(reinterpret_cast<const char*>(data.data()), data.size());
                if (frame.flags & kFlagEndStream) {
                    st->done = true;
                }
                break;
            }
            case kRst: {
                st->failed = true;
                st->error = frame.payload.size() == 4
                    ? getU32(frame.payload.data()) : kErrInternal;
                st->done = true;
                break;
            }
            case kWindowUpdate: {
                if (frame.payload.size() != 4) {
                    throw H2Error("bad window update", kErrProtocol);
                }
                const uint32_t inc = getU32(frame.payload.data()) & 0x7FFFFFFFu;
                if (inc == 0) {
                    throw H2Error("zero window increment", kErrProtocol);
                }
                {
                    std::lock_guard lock(s.mutex);
                    st->sendWnd += inc;
                    if (st->sendWnd > kMaxWindow) {
                        throw H2Error("window overflow", kErrFlowControl);
                    }
                }
                s.poke();
                break;
            }
            default:
                break; // connection-level frames are handled by the pump.
            }
        }
    }
    catch (const ChannelClosed&) {
        s.forget(st->id);
        if (st->refused) {
            throw H2Error("server will not process this stream", kErrRefusedStream);
        }
        throw H2Error("connection closed", kErrNoError);
    }
    catch (...) {
        s.forget(st->id);
        throw;
    }
    s.forget(st->id);

    if (st->refused) {
        throw H2Error("GOAWAY arrived before this stream was processed", kErrRefusedStream);
    }
    if (st->failed) {
        throw H2Error("stream reset by peer", st->error);
    }
    if (!st->headersDone) {
        throw H2Error("stream ended without headers", kErrProtocol);
    }
    H2Response response = std::move(st->response);
    response.body = std::move(st->body);
    co_return response;
}

bool H2Connection::goaway() const noexcept {
    if (!state_ || !state_->session) {
        return false;
    }
    std::lock_guard lock(state_->session->mutex);
    return state_->session->goaway;
}

uint32_t H2Connection::goawayCode() const noexcept {
    if (!state_ || !state_->session) {
        return 0;
    }
    std::lock_guard lock(state_->session->mutex);
    return state_->session->goawayCode;
}

uint32_t H2Connection::goawayLastStream() const noexcept {
    if (!state_ || !state_->session) {
        return 0;
    }
    std::lock_guard lock(state_->session->mutex);
    return state_->session->goawayLastId;
}

uint32_t H2Connection::maxConcurrentStreams() const noexcept {
    if (!state_ || !state_->session) {
        return 0;
    }
    std::lock_guard lock(state_->session->mutex);
    return state_->session->peerMaxConcurrent;
}

std::vector<H2Push> H2Connection::pushPromises() const {
    if (!state_ || !state_->session) {
        return { };
    }
    std::lock_guard lock(state_->session->mutex);
    return state_->session->pushes;
}

void H2Connection::close() noexcept {
    if (state_ && state_->transport) {
        state_->transport->close();
    }
}

// ------------------------------------------------------------ server session

namespace {

struct ServerStreamFlow {
    int64_t sendWnd = kDefaultWindow;
    int64_t recvWnd = kDefaultWindow;
    bool closed = false; // response sent or reset.
};

struct ServerSession : public std::enable_shared_from_this<ServerSession> {
    std::unique_ptr<Stream> transport;
    H2Limits limits;
    H2Handler handler;
    Canceller canceller;
    hpack::Encoder encoder;
    hpack::Decoder decoder;
    AsyncMutex writeMutex;
    Channel<char> wake { 1 };
    std::mutex mutex; // guards flows, streams, counters below.
    std::map<uint32_t, ServerStreamFlow> flows;
    std::map<uint32_t, H2Request> pending; // fully received, handler running.
    uint32_t lastStreamId = 0;
    size_t openStreams = 0;
    int64_t connSendWnd = kDefaultWindow;
    int64_t connRecvWnd = kDefaultWindow;
    uint32_t peerMaxFrame = kDefaultMaxFrame;
    uint32_t peerInitWnd = kDefaultWindow;
    bool goawayReceived = false;
    bool closing = false;

    void pokeWake() {
        wake.trySend(0);
    }

    Task<void> sendGoAway(uint32_t code, Canceller ct) {
        auto lock = co_await writeMutex.lock(ct);
        std::vector<uint8_t> payload;
        putU32(payload, lastStreamId);
        putU32(payload, code);
        co_await writeFrame(transport.get(), kGoAway, 0, 0, payload, ct);
        co_return;
    }

    Task<void> sendRst(uint32_t id, uint32_t code, Canceller ct) {
        auto lock = co_await writeMutex.lock(std::move(ct));
        std::vector<uint8_t> payload;
        putU32(payload, code);
        co_await writeFrame(transport.get(), kRst, 0, id, payload, ct);
        co_return;
    }

    // Sends a full response on an open stream (END_STREAM always set). A pipe
    // body becomes one DATA frame per chunk; HTTP/2 needs no length header.
    Task<void> sendResponse(uint32_t id, H2Response response, Canceller ct) {
        std::vector<uint8_t> block;
        {
            auto lock = co_await writeMutex.lock(ct);
            block = encoder.encode(toFields(response));
        }
        {
            auto lock = co_await writeMutex.lock(std::move(ct));
            uint8_t flags = kFlagEndHeaders;
            if (response.body.empty()) {
                flags |= kFlagEndStream;
            }
            co_await writeFrame(transport.get(), kHeaders, flags, id, block, ct);
        }

        auto emit = [this, id](std::string_view data, bool endStream, Canceller& ct2) -> Task<void> {
            size_t off = 0;
            while (off < data.size()) {
                size_t n = 0;
                {
                    std::lock_guard guard(mutex);
                    auto it = flows.find(id);
                    if (it == flows.end() || it->second.closed) {
                        co_return; // reset meanwhile: drop the response.
                    }
                    n = std::min({ data.size() - off, size_t { peerMaxFrame },
                        connSendWnd > 0 ? static_cast<size_t>(connSendWnd) : size_t { 0 },
                        it->second.sendWnd > 0 ? static_cast<size_t>(it->second.sendWnd)
                                              : size_t { 0 } });
                }
                if (n == 0) {
                    Canceller waitCt;
                    co_await wake.receive(waitCt);
                    continue;
                }
                const bool last = endStream && off + n == data.size();
                auto lock = co_await writeMutex.lock(ct2);
                co_await writeFrame(transport.get(), kData, last ? kFlagEndStream : 0, id,
                    reinterpret_cast<const uint8_t*>(data.data()) + off, n, ct2);
                {
                    std::lock_guard guard(mutex);
                    connSendWnd -= static_cast<int64_t>(n);
                    if (auto it = flows.find(id); it != flows.end()) {
                        it->second.sendWnd -= static_cast<int64_t>(n);
                    }
                }
                off += n;
            }
            co_return;
        };

        if (!response.body.isPipe()) {
            const std::string_view view(response.body.bytes());
            if (!view.empty()) {
                co_await emit(view, true, ct);
            }
        }
        else {
            // One chunk of lookahead so END_STREAM rides on the final frame.
            auto chunk = co_await response.body.next(ct);
            if (!chunk) {
                co_await emit(std::string_view { }, true, ct);
            }
            while (chunk) {
                auto lookahead = co_await response.body.next(ct);
                const bool last = !lookahead;
                co_await emit(std::string_view(*chunk), last, ct);
                chunk = std::move(lookahead);
            }
        }

        {
            std::lock_guard guard(mutex);
            flows.erase(id);
            pending.erase(id);
            if (openStreams > 0) {
                --openStreams;
            }
        }
        co_return;
    }
};

Task<void> runServerStream(std::shared_ptr<ServerSession> session, uint32_t id, H2Request request) {
    H2Response response;
    try {
        response = co_await session->handler(std::move(request));
    }
    catch (...) {
        response.status = 500;
        response.body.clear();
    }
    try {
        co_await session->sendResponse(id, std::move(response), { });
    }
    catch (...) {
    }
    co_return;
}

Task<void> readHeaderBlockServer(ServerSession* session, uint32_t id, Frame first,
    std::vector<uint8_t>& block, Canceller ct) {
    auto data = stripPadding(first.payload, first.flags);
    block.insert(block.end(), data.begin(), data.end());
    uint8_t flags = first.flags;
    while (!(flags & kFlagEndHeaders)) {
        Frame next = co_await readFrame(session->transport.get(), session->peerMaxFrame, ct);
        if (next.type != kContinuation || next.stream != id) {
            throw H2Error("expected continuation", kErrProtocol);
        }
        flags = next.flags;
        block.insert(block.end(), next.payload.begin(), next.payload.end());
        if (block.size() > session->limits.maxHeaderBytes) {
            throw H2Error("header block too large", kErrEnhanceYourCalm);
        }
    }
    co_return;
}

Task<void> serverSessionLoop(std::shared_ptr<ServerSession> session, bool expectMagic) {
    Stream* stream = session->transport.get();
    const Canceller ct = session->canceller;
    uint32_t goAwayCode = kErrNoError;
    try {
        if (expectMagic) {
            char magic[kClientMagicLen];
            try {
                co_await stream->readExact(std::span(magic, kClientMagicLen), ct);
            }
            catch (const SocketClosed&) {
                co_return;
            }
            if (std::memcmp(magic, kClientMagic, kClientMagicLen) != 0) {
                throw H2Error("bad client magic", kErrProtocol);
            }
        }
        // First frame MUST be SETTINGS.
        {
            Frame first = co_await readFrame(stream, session->peerMaxFrame, ct);
            if (first.type != kSettings || (first.flags & kFlagAck)) {
                throw H2Error("first frame is not settings", kErrProtocol);
            }
            if (first.payload.size() % 6 != 0) {
                throw H2Error("bad settings", kErrProtocol);
            }
            for (size_t i = 0; i < first.payload.size(); i += 6) {
                const uint16_t sid = uint16_t { first.payload[i] } << 8 | first.payload[i + 1];
                const uint32_t value = getU32(first.payload.data() + i + 2);
                if (sid == kSettingsEnablePush && value != 0) {
                    throw H2Error("push not supported", kErrProtocol);
                }
                if (sid == kSettingsHeaderTableSize) {
                    session->decoder.setMaxTableBytes(value);
                }
                if (sid == kSettingsInitialWindowSize && value > kMaxWindow) {
                    throw H2Error("bad window", kErrFlowControl);
                }
            }
            auto lock = co_await session->writeMutex.lock(ct);
            co_await writeFrame(stream, kSettings, 0, 0, nullptr, 0, ct);
            co_await writeFrame(stream, kSettings, kFlagAck, 0, nullptr, 0, ct);
        }

        auto worker = Worker::currentWorker();
        if (!worker) {
            worker = Worker::defaultWorker();
        }
        while (true) {
            Frame frame = co_await readFrame(stream, session->peerMaxFrame, ct);
            switch (frame.type) {
            case kSettings: {
                if (frame.stream != 0 || frame.payload.size() % 6 != 0) {
                    throw H2Error("bad settings", kErrProtocol);
                }
                if (!(frame.flags & kFlagAck)) {
                    for (size_t i = 0; i < frame.payload.size(); i += 6) {
                        const uint16_t sid = uint16_t { frame.payload[i] } << 8 | frame.payload[i + 1];
                        const uint32_t value = getU32(frame.payload.data() + i + 2);
                        if (sid == kSettingsEnablePush && value != 0) {
                            throw H2Error("push not supported", kErrProtocol);
                        }
                        if (sid == kSettingsHeaderTableSize) {
                            session->decoder.setMaxTableBytes(value);
                        }
                    }
                    auto lock = co_await session->writeMutex.lock(ct);
                    co_await writeFrame(stream, kSettings, kFlagAck, 0, nullptr, 0, ct);
                }
                break;
            }
            case kHeaders: {
                const uint32_t id = frame.stream;
                if (id == 0 || (id & 1) == 0) {
                    throw H2Error("bad stream id", kErrProtocol);
                }
                bool refused = false;
                {
                    std::lock_guard guard(session->mutex);
                    if (session->goawayReceived || id <= session->lastStreamId
                        || session->flows.count(id) || session->pending.count(id)) {
                        break; // stale/duplicate: ignore.
                    }
                    if (session->openStreams >= session->limits.maxStreams) {
                        refused = true;
                    }
                    else {
                        session->lastStreamId = id;
                        session->flows[id] = { session->peerInitWnd, int64_t { kDefaultWindow }, false };
                        ++session->openStreams;
                    }
                }
                if (refused) {
                    try {
                        co_await session->sendRst(id, kErrRefusedStream, ct);
                    }
                    catch (...) {
                    }
                    break;
                }
                std::vector<uint8_t> block;
                H2Request req;
                bool headOk = true;
                try {
                    co_await readHeaderBlockServer(session.get(), id, std::move(frame), block, ct);
                    req = fromRequestFields(session->decoder.decode(block));
                }
                catch (...) {
                    headOk = false;
                }
                if (!headOk) {
                    try {
                        co_await session->sendRst(id, kErrProtocol, ct);
                    }
                    catch (...) {
                    }
                    std::lock_guard guard(session->mutex);
                    session->flows.erase(id);
                    --session->openStreams;
                    break;
                }
                if (frame.flags & kFlagEndStream) {
                    std::lock_guard guard(session->mutex);
                    session->pending[id] = req;
                    worker->push(runServerStream(session, id, std::move(req)));
                }
                else {
                    std::lock_guard guard(session->mutex);
                    session->pending[id] = std::move(req);
                }
                break;
            }
            case kData: {
                const uint32_t id = frame.stream;
                auto data = stripPadding(frame.payload, frame.flags);
                const auto n = static_cast<int64_t>(data.size());
                bool topUpStream = false, topUpConn = false, dispatch = false;
                H2Request full;
                {
                    std::lock_guard guard(session->mutex);
                    auto fit = session->flows.find(id);
                    auto pit = session->pending.find(id);
                    if (fit == session->flows.end() || pit == session->pending.end()) {
                        break; // unknown: ignore.
                    }
                    session->connRecvWnd -= n;
                    fit->second.recvWnd -= n;
                    topUpStream = fit->second.recvWnd <= 32768;
                    topUpConn = session->connRecvWnd <= 32768;
                    pit->second.body.setBytes(pit->second.body.bytes()
                        + std::string(
                            reinterpret_cast<const char*>(data.data()), data.size()));
                    if (frame.flags & kFlagEndStream) {
                        full = std::move(pit->second);
                        session->pending.erase(pit);
                        dispatch = true;
                    }
                }
                if (topUpStream) {
                    int64_t current = kDefaultWindow;
                    {
                        std::lock_guard guard(session->mutex);
                        if (session->flows.count(id)) {
                            current = session->flows[id].recvWnd;
                        }
                    }
                    auto lock = co_await session->writeMutex.lock(ct);
                    std::vector<uint8_t> p;
                    putU32(p, static_cast<uint32_t>(kDefaultWindow - current));
                    co_await writeFrame(stream, kWindowUpdate, 0, id, p, ct);
                    std::lock_guard guard(session->mutex);
                    if (session->flows.count(id)) {
                        session->flows[id].recvWnd = kDefaultWindow;
                    }
                }
                if (topUpConn) {
                    uint32_t increment = 0;
                    {
                        std::lock_guard guard(session->mutex);
                        increment = static_cast<uint32_t>(kDefaultWindow - session->connRecvWnd);
                    }
                    auto lock = co_await session->writeMutex.lock(ct);
                    std::vector<uint8_t> p;
                    putU32(p, increment);
                    co_await writeFrame(stream, kWindowUpdate, 0, 0, p, ct);
                    session->connRecvWnd = kDefaultWindow;
                }
                if (dispatch) {
                    worker->push(runServerStream(session, id, std::move(full)));
                }
                break;
            }
            case kWindowUpdate: {
                if (frame.payload.size() != 4) {
                    throw H2Error("bad window update", kErrProtocol);
                }
                const uint32_t inc = getU32(frame.payload.data()) & 0x7FFFFFFFu;
                if (inc == 0) {
                    throw H2Error("zero increment", kErrProtocol);
                }
                {
                    std::lock_guard guard(session->mutex);
                    if (frame.stream == 0) {
                        session->connSendWnd += inc;
                    }
                    else if (auto it = session->flows.find(frame.stream);
                        it != session->flows.end()) {
                        it->second.sendWnd += inc;
                    }
                }
                session->pokeWake();
                break;
            }
            case kPing: {
                if (frame.stream != 0 || frame.payload.size() != 8) {
                    throw H2Error("bad ping", kErrProtocol);
                }
                if (!(frame.flags & kFlagAck)) {
                    auto lock = co_await session->writeMutex.lock(ct);
                    co_await writeFrame(stream, kPing, kFlagAck, 0, frame.payload, ct);
                }
                break;
            }
            case kRst: {
                std::lock_guard guard(session->mutex);
                session->flows.erase(frame.stream);
                session->pending.erase(frame.stream);
                if (session->openStreams > 0) {
                    --session->openStreams;
                }
                break;
            }
            case kGoAway:
                session->goawayReceived = true;
                break;
            case kPush:
                throw H2Error("push from client", kErrProtocol);
            case kPriority:
            case kContinuation:
                throw H2Error("unexpected frame", kErrProtocol);
            default:
                break; // unknown types ignored.
            }
        }
    }
    catch (const OperationCanceled&) {
        goAwayCode = kErrNoError;
    }
    catch (...) {
        goAwayCode = kErrInternal;
    }
    try {
        co_await session->sendGoAway(goAwayCode, { });
    }
    catch (...) {
    }
    session->transport->close();
    co_return;
}

} // namespace

// ------------------------------------------------------------ H2Server

Task<void> H2Server::serveH2c(Socket listener, H2Handler handler,
    H2Limits limits, Canceller canceller) {
    while (!canceller.isTriggered()) {
        Socket raw;
        try {
            raw = co_await listener.accept(canceller);
        }
        catch (const OperationCanceled&) {
            break;
        }
        auto session = std::make_shared<ServerSession>();
        session->transport = std::make_unique<SocketStream>(std::move(raw));
        session->limits = limits;
        session->handler = handler;
        session->canceller = canceller;
        auto worker = Worker::currentWorker();
        if (!worker) {
            worker = Worker::defaultWorker();
        }
        try {
            worker->push(serverSessionLoop(std::move(session), true));
        }
        catch (...) {
        }
    }
    listener.close();
    co_return;
}

Task<void> H2Server::serveTls(Socket listener, TlsConfig tls, H2Handler handler,
    H2Limits limits, Canceller canceller) {
    while (!canceller.isTriggered()) {
        Socket raw;
        try {
            raw = co_await listener.accept(canceller);
        }
        catch (const OperationCanceled&) {
            break;
        }
        std::optional<TlsStream> established;
        try {
            established.emplace(co_await TlsStream::accept(std::move(raw), tls, canceller));
        }
        catch (...) {
            continue;
        }
        if (established->negotiatedAlpn() != "h2") {
            continue; // not an H2 client: close.
        }
        auto session = std::make_shared<ServerSession>();
        session->transport = std::make_unique<TlsStream>(std::move(*established));
        session->limits = limits;
        session->handler = handler;
        session->canceller = canceller;
        auto worker = Worker::currentWorker();
        if (!worker) {
            worker = Worker::defaultWorker();
        }
        try {
            worker->push(serverSessionLoop(std::move(session), false));
        }
        catch (...) {
        }
    }
    listener.close();
    co_return;
}

// ------------------------------------------------------------ H2Client

Task<H2Response> H2Client::request(const std::string& method, const std::string& url,
    Headers headers, const std::string& body, Canceller canceller) {
    const Url parsed = Url::parse(url);
    if (parsed.scheme == "http") {
        Socket raw = co_await Socket::connect(parsed.host, parsed.port, canceller);
        H2Connection conn = co_await H2Connection::connect(
            std::make_unique<SocketStream>(std::move(raw)), { }, canceller);
        H2Request req;
        req.method = method;
        req.scheme = "http";
        req.authority = parsed.port == 80 ? parsed.host : parsed.host + ":" + std::to_string(parsed.port);
        req.path = parsed.path;
        req.headers = std::move(headers);
        req.body = body;
        H2Response response = co_await conn.request(std::move(req), canceller);
        conn.close();
        co_return response;
    }
    throw std::logic_error("H2Client https needs a TlsConfig (see the overload).");
}

Task<H2Response> H2Client::get(const std::string& url, Canceller canceller) {
    H2Response response = co_await request("GET", url, { }, { }, std::move(canceller));
    co_return response;
}

Task<H2Response> H2Client::post(const std::string& url, const std::string& body,
    const std::string& contentType, Canceller canceller) {
    Headers headers;
    headers.push_back({ "Content-Type", contentType });
    H2Response response = co_await request("POST", url, std::move(headers), body, std::move(canceller));
    co_return response;
}

Task<H2Response> H2Client::request(const std::string& method, const std::string& url,
    Headers headers, const std::string& body, TlsConfig tls, Canceller canceller) {
    const Url parsed = Url::parse(url);
    if (parsed.scheme == "http") {
        H2Response response = co_await request(method, url, std::move(headers), body, std::move(canceller));
        co_return response;
    }
    if (tls.serverName.empty()) {
        tls.serverName = parsed.host;
    }
    if (std::find(tls.alpn.begin(), tls.alpn.end(), "h2") == tls.alpn.end()) {
        tls.alpn.insert(tls.alpn.begin(), "h2");
    }
    Socket raw = co_await Socket::connect(parsed.host, parsed.port, canceller);
    TlsStream tlsStream = co_await TlsStream::connect(std::move(raw), std::move(tls), canceller);
    if (tlsStream.negotiatedAlpn() != "h2") {
        throw H2Error("server did not negotiate h2", kErrProtocol);
    }
    H2Connection conn = co_await H2Connection::connect(
        std::make_unique<TlsStream>(std::move(tlsStream)), { }, canceller, false);
    H2Request req;
    req.method = method;
    req.scheme = "https";
    req.authority = parsed.port == 443 ? parsed.host : parsed.host + ":" + std::to_string(parsed.port);
    req.path = parsed.path;
    req.headers = std::move(headers);
    req.body = body;
    H2Response response = co_await conn.request(std::move(req), canceller);
    conn.close();
    co_return response;
}

} // namespace taskpp::http
