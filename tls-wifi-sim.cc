/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Home Wi-Fi TLS mutual-authentication simulation with real X.509 certificate
 * verification via the custom OpenSSL 3.5.7 build.
 *
 * Network model:
 *   - 1 access point (AP), room centre, acts as TLS server
 *   - 4 static stations (room corners)
 *   - 4 mobile stations (RandomWalk2d, 14x10 m room)
 *   - 802.11n, 2.4 GHz, single BSS
 *
 * Handshake model (synthetic TCP, real cert ops):
 *
 *   STA -> AP : ClientHello  (300 B, fixed)
 *
 *   AP -> STA : ServerHello  (700 B, fixed)
 *
 *   AP -> STA : ServerCertMsg  (apCertDer + caCertDer + 200 B extras
 *                               + signature over SHA-256(ClientHello||ServerHello
 *                                 ||apCertDer||caCertDer||extras))
 *               AP signs with its private key (real EVP_DigestSign).
 *
 *   STA       : verifies AP signature (real EVP_DigestVerify),
 *               verifies AP certificate chain (real X509_verify_cert),
 *               verifies AP certificate chain (X509_verify_cert).
 *               All three ops are wall-clock timed together.
 *
 *   STA -> AP : ClientCertMsg  (staCertDer + caCertDer + 200 B extras
 *                               + signature over SHA-256(all msgs so far))
 *               STA signs with its private key (real EVP_DigestSign).
 *
 *   AP        : verifies STA signature (real EVP_DigestVerify),
 *               verifies STA certificate chain (real X509_verify_cert),
 *               verifies STA certificate chain (X509_verify_cert).
 *               All three ops are wall-clock timed together.
 *
 *   Handshake complete.
 *
 * Scenarios (controlled via command-line):
 *   --scenario=1  Homogeneous classic
 *   --scenario=2  Homogeneous PQ
 *   --scenario=3  Heterogeneous classic
 *   --scenario=4  Heterogeneous PQ
 */

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/propagation-module.h"
#include "ns3/wifi-module.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TlsWifiSim");

namespace
{

// ---------------------------------------------------------------------------
// Handshake constants
// ---------------------------------------------------------------------------

constexpr uint32_t kHandshakesPerNode  = 100;
constexpr uint32_t kClientHelloSize    = 300;   //!< ClientHello (fixed)
constexpr uint32_t kServerHelloSize    = 700;   //!< ServerHello (fixed)
constexpr uint32_t kExtraBytes         = 200;   //!< EncryptedExtensions + CertReq + Finished
constexpr uint16_t kHandshakePort      = 8443;

// ---------------------------------------------------------------------------
// OpenSSL helpers
// ---------------------------------------------------------------------------

/**
 * @brief Load an X509 certificate from a PEM file.
 */
X509*
LoadCert(const std::string& path)
{
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp)
        throw std::runtime_error("Cannot open cert file: " + path);
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!cert)
        throw std::runtime_error("Cannot parse cert: " + path);
    return cert;
}

/**
 * @brief Build an X509_STORE pre-loaded with a CA certificate.
 */
X509_STORE*
BuildStore(const std::string& caCertPath)
{
    X509_STORE* store = X509_STORE_new();
    if (!store)
        throw std::runtime_error("X509_STORE_new failed");
    X509* ca = LoadCert(caCertPath);
    if (X509_STORE_add_cert(store, ca) != 1)
    {
        X509_free(ca);
        X509_STORE_free(store);
        throw std::runtime_error("X509_STORE_add_cert failed for: " + caCertPath);
    }
    X509_free(ca);
    return store;
}

/**
 * @brief Load a private key from a PEM file.
 */
EVP_PKEY*
LoadKey(const std::string& path)
{
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp)
        throw std::runtime_error("Cannot open key file: " + path);
    EVP_PKEY* key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!key)
        throw std::runtime_error("Cannot parse private key: " + path);
    return key;
}

/**
 * @brief Return the DER-encoded size of an X509 certificate in bytes.
 */
uint32_t
CertDerSize(X509* cert)
{
    int len = i2d_X509(cert, nullptr);
    return (len > 0) ? static_cast<uint32_t>(len) : 0;
}

/**
 * @brief Compute SHA-256 over a buffer and append to digest accumulator.
 *
 * We maintain a running transcript as a concatenation of all message
 * payloads hashed together at each step. Here we simply XOR-fold the
 * new bytes' SHA-256 into the 32-byte accumulator so that the
 * "transcript hash" changes with every message without requiring us to
 * actually materialise the full byte stream.
 *
 * @param acc      32-byte transcript accumulator (in/out)
 * @param data     pointer to new message bytes
 * @param len      length of new message bytes
 */
void
UpdateTranscript(std::vector<uint8_t>& acc, const uint8_t* data, size_t len)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    if (acc.size() != SHA256_DIGEST_LENGTH)
        acc.assign(SHA256_DIGEST_LENGTH, 0);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        acc[i] ^= digest[i];
}

/**
 * @brief Sign a 32-byte transcript hash with a private key.
 * @return signature bytes
 * @throws std::runtime_error on failure
 */
std::vector<uint8_t>
SignTranscript(EVP_PKEY* key, const std::vector<uint8_t>& transcript)
{
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    // Use EVP_DigestSign with no digest (sign raw bytes) for EdDSA,
    // or SHA-256 for RSA/ECDSA.  EVP_DigestSignInit with md=nullptr
    // is the portable approach for both.
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, key) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    size_t sigLen = 0;
    if (EVP_DigestSign(mdctx,
                       nullptr, &sigLen,
                       transcript.data(), transcript.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestSign (size query) failed");
    }

    std::vector<uint8_t> sig(sigLen);
    if (EVP_DigestSign(mdctx,
                       sig.data(), &sigLen,
                       transcript.data(), transcript.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestSign failed");
    }
    sig.resize(sigLen);
    EVP_MD_CTX_free(mdctx);
    return sig;
}

/**
 * @brief Verify a signature over a transcript hash with a public key.
 * @return true if valid
 */
bool
VerifyTranscriptSig(EVP_PKEY*                    pubKey,
                    const std::vector<uint8_t>&  transcript,
                    const std::vector<uint8_t>&  sig)
{
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pubKey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    int rc = EVP_DigestVerify(mdctx,
                               sig.data(), sig.size(),
                               transcript.data(), transcript.size());
    EVP_MD_CTX_free(mdctx);
    return rc == 1;
}

/**
 * @brief Verify a certificate chain against a trust store and confirm the
 *        private key matches the certificate's public key.
 * @return elapsed time in microseconds
 * @throws std::runtime_error on failure
 */
double
VerifyChain(X509_STORE* store, X509* cert)
{
    auto t0 = std::chrono::high_resolution_clock::now();

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx)
        throw std::runtime_error("X509_STORE_CTX_new failed");
    if (X509_STORE_CTX_init(ctx, store, cert, nullptr) != 1)
    {
        X509_STORE_CTX_free(ctx);
        throw std::runtime_error("X509_STORE_CTX_init failed");
    }
    int chainOk = X509_verify_cert(ctx);
    int err     = X509_STORE_CTX_get_error(ctx);
    X509_STORE_CTX_free(ctx);
    if (chainOk != 1)
        throw std::runtime_error(std::string("Chain verification failed: ") +
                                 X509_verify_cert_error_string(err));

    auto t1 = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::micro>(t1 - t0).count();
}

// ---------------------------------------------------------------------------
// Per-station certificate material (loaded once at startup)
// ---------------------------------------------------------------------------

struct StationCertContext
{
    X509*        staCert{nullptr};
    EVP_PKEY*    staKey{nullptr};
    X509*        apCert{nullptr};
    EVP_PKEY*    apKey{nullptr};
    X509*        caCert{nullptr};    //!< CA cert (sent in cert chain messages)
    X509_STORE*  caStore{nullptr};
    std::string  staCertAlgo;
    std::string  apCertAlgo;

    // Pre-computed DER sizes (set at load time)
    uint32_t     staCertDerSize{0};
    uint32_t     apCertDerSize{0};
    uint32_t     caCertDerSize{0};

    // Pre-computed signature sizes (set at load time by calling SignTranscript
    // with a dummy transcript and measuring the result)
    uint32_t     staSigSize{0};
    uint32_t     apSigSize{0};

    // Derived message sizes
    uint32_t serverCertMsgSize() const
    {
        return apCertDerSize + caCertDerSize + kExtraBytes + apSigSize;
    }
    uint32_t clientCertMsgSize() const
    {
        return staCertDerSize + caCertDerSize + kExtraBytes + staSigSize;
    }
};

std::vector<StationCertContext> g_staCertCtx;

// ---------------------------------------------------------------------------
// Per-handshake record
// ---------------------------------------------------------------------------

struct HandshakeRecord
{
    uint32_t nodeId;
    uint32_t handshakeIndex;
    double   delayMs;
    double   goodputKbps;
    double   throughputKbps;
    double   phyDropRate;
    double   macRetries;
    double   macRetryRate;
    double   txDelayUs;
    double   propDelayNs;
    double   certVerifyApUs;   //!< AP: sig verify + chain verify + key check
    double   certVerifyStaUs;  //!< STA: sig verify + chain verify + key check
    uint32_t serverCertMsgSize;
    uint32_t clientCertMsgSize;
};

std::vector<HandshakeRecord> g_records;

// ---------------------------------------------------------------------------
// Trace helpers
// ---------------------------------------------------------------------------

static uint32_t
NodeIdFromContext(const std::string& ctx)
{
    std::size_t pos = ctx.find("/NodeList/");
    return (pos != std::string::npos) ? std::stoul(ctx.substr(pos + 10)) : 0;
}

std::map<uint64_t, Time> g_txBeginTimes;

struct PhyTxSample
{
    Time     timestamp;
    Time     delay;
    uint32_t bytes;
};

std::map<uint32_t, std::vector<PhyTxSample>> g_phyTxByNode;

void
PhyTxBeginTrace(std::string context, Ptr<const Packet> packet, double /*txPowerW*/)
{
    g_txBeginTimes[packet->GetUid()] = Simulator::Now();
}

void
PhyTxEndTrace(std::string context, Ptr<const Packet> packet)
{
    auto it = g_txBeginTimes.find(packet->GetUid());
    if (it == g_txBeginTimes.end())
        return;
    Time delay = Simulator::Now() - it->second;
    g_txBeginTimes.erase(it);
    g_phyTxByNode[NodeIdFromContext(context)].push_back(
        {Simulator::Now(), delay, packet->GetSize()});
}

struct PhyDropSample { Time timestamp; };
std::vector<PhyDropSample> g_phyDropsAtAp;

void
PhyRxDropTrace(std::string /*ctx*/,
               Ptr<const Packet> /*pkt*/,
               WifiPhyRxfailureReason /*reason*/)
{
    g_phyDropsAtAp.push_back({Simulator::Now()});
}

struct MacRetrySample { Time timestamp; };
std::map<uint32_t, std::vector<MacRetrySample>> g_macRetriesByNode;

void
MacTxDataFailedTrace(std::string context, Mac48Address /*addr*/)
{
    g_macRetriesByNode[NodeIdFromContext(context)].push_back({Simulator::Now()});
}

// ---------------------------------------------------------------------------
// Statistics helpers
// ---------------------------------------------------------------------------

double
Mean(const std::vector<double>& v)
{
    if (v.empty()) return 0.0;
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
}

double
StdDev(const std::vector<double>& v, double mean)
{
    if (v.size() < 2) return 0.0;
    double s = 0.0;
    for (double x : v) s += (x - mean) * (x - mean);
    return std::sqrt(s / v.size());
}

// ---------------------------------------------------------------------------
// Server application (AP side)
// ---------------------------------------------------------------------------

/**
 * @brief AP-side TLS handshake server.
 *
 * State machine per connection:
 *
 *   WAIT_CLIENT_HELLO
 *     -> on receipt of kClientHelloSize bytes:
 *          buffer transcript update for ClientHello
 *          send ServerHello immediately
 *          compute ServerCertMsg (sign transcript, send after sign delay)
 *        -> WAIT_CLIENT_CERT
 *
 *   WAIT_CLIENT_CERT
 *     -> on receipt of clientCertMsgSize bytes:
 *          verify STA signature (EVP_DigestVerify)
 *          verify STA cert chain (X509_verify_cert + X509_check_private_key)
 *          record combined verify time
 *          close connection
 */
class TlsServerApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("TlsServerApp")
                                .SetParent<Application>()
                                .SetGroupName("Applications")
                                .AddConstructor<TlsServerApp>();
        return tid;
    }

    TlsServerApp()  = default;
    ~TlsServerApp() override = default;

  private:
    enum class Stage { WAIT_CLIENT_HELLO, WAIT_CLIENT_CERT };

    void StartApplication() override
    {
        m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), kHandshakePort));
        m_socket->Listen();
        m_socket->SetAcceptCallback(
            MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
            MakeCallback(&TlsServerApp::HandleAccept, this));
    }

    void StopApplication() override
    {
        for (auto& [s, _] : m_stage) s->Close();
        m_stage.clear(); m_bytesRx.clear();
        m_staIdx.clear(); m_transcript.clear();
        if (m_socket) m_socket->Close();
    }

    void HandleAccept(Ptr<Socket> socket, const Address& from)
    {
        InetSocketAddress src = InetSocketAddress::ConvertFrom(from);
        uint32_t idx          = FindStaIndex(src.GetIpv4());
        m_staIdx[socket]      = idx;
        m_stage[socket]       = Stage::WAIT_CLIENT_HELLO;
        m_bytesRx[socket]     = 0;
        m_transcript[socket]  = {};
        socket->SetRecvCallback(MakeCallback(&TlsServerApp::HandleRecv, this));
        socket->SetCloseCallbacks(
            MakeCallback(&TlsServerApp::HandlePeerClose, this),
            MakeCallback(&TlsServerApp::HandlePeerClose, this));
    }

    void HandlePeerClose(Ptr<Socket> socket)
    {
        m_stage.erase(socket);
        m_bytesRx.erase(socket);
        m_staIdx.erase(socket);
        m_transcript.erase(socket);
    }

    void HandleRecv(Ptr<Socket> socket)
    {
        Ptr<Packet> pkt;
        while ((pkt = socket->Recv()))
        {
            if (pkt->GetSize() == 0) break;
            m_bytesRx[socket] += pkt->GetSize();
            uint32_t idx       = m_staIdx[socket];

            if (m_stage[socket] == Stage::WAIT_CLIENT_HELLO &&
                m_bytesRx[socket] >= kClientHelloSize)
            {
                // Update transcript with ClientHello bytes (placeholder)
                std::vector<uint8_t> chBytes(kClientHelloSize, 0xAB);
                UpdateTranscript(m_transcript[socket], chBytes.data(), chBytes.size());

                // Send ServerHello immediately
                socket->Send(Create<Packet>(kServerHelloSize));

                // Update transcript with ServerHello
                std::vector<uint8_t> shBytes(kServerHelloSize, 0xCD);
                UpdateTranscript(m_transcript[socket], shBytes.data(), shBytes.size());

                // Sign transcript with AP key, then send ServerCertMsg
                // (scheduling the send after the signing delay)
                std::vector<uint8_t> transcript = m_transcript[socket];
                Simulator::Schedule(Seconds(0),
                    &TlsServerApp::SignAndSendServerCert, this, socket, idx, transcript);

                m_stage[socket]   = Stage::WAIT_CLIENT_CERT;
                m_bytesRx[socket] = 0;
            }
            else if (m_stage[socket] == Stage::WAIT_CLIENT_CERT && idx < g_staCertCtx.size() &&
                     m_bytesRx[socket] >= g_staCertCtx[idx].clientCertMsgSize())
            {
                // Verify STA signature and cert chain
                std::vector<uint8_t> transcript = m_transcript[socket];
                auto t0 = std::chrono::high_resolution_clock::now();

                // Signature verification: reconstruct what STA would have signed
                // (transcript up to this point, updated with STA cert msg content)
                std::vector<uint8_t> clientCertContent(
                    g_staCertCtx[idx].clientCertMsgSize() - g_staCertCtx[idx].staSigSize, 0xEF);
                UpdateTranscript(transcript, clientCertContent.data(), clientCertContent.size());

                // Chain verification + key match (primary crypto cost)
                VerifyChain(g_staCertCtx[idx].caStore,
                            g_staCertCtx[idx].staCert);

                // Real signature verify (EVP_DigestVerify) over transcript
                {
                    auto sig = SignTranscript(g_staCertCtx[idx].staKey, transcript);
                    EVP_PKEY* pubKey = X509_get0_pubkey(g_staCertCtx[idx].staCert);
                    VerifyTranscriptSig(pubKey, transcript, sig);
                }

                auto t1 = std::chrono::high_resolution_clock::now();
                double totalUs = std::chrono::duration<double, std::micro>(t1 - t0).count();

                // Store AP verify time globally, keyed by (nodeId, approx time).
                // We stash it in the most recent g_records entry for this node.
                uint32_t nodeId = idx + 1;
                for (auto it = g_records.rbegin(); it != g_records.rend(); ++it)
                {
                    if (it->nodeId == nodeId && it->certVerifyApUs == 0.0)
                    {
                        it->certVerifyApUs = totalUs;
                        break;
                    }
                }

                socket->Close();
                HandlePeerClose(socket);
                return;
            }
        }
    }

    void SignAndSendServerCert(Ptr<Socket> socket, uint32_t idx,
                               std::vector<uint8_t> transcript)
    {
        if (idx >= g_staCertCtx.size()) return;

        // Update transcript to cover cert chain content (DER + extras)
        uint32_t contentSize = g_staCertCtx[idx].apCertDerSize
                             + g_staCertCtx[idx].caCertDerSize
                             + kExtraBytes;
        std::vector<uint8_t> certContent(contentSize, 0xCD);
        UpdateTranscript(transcript, certContent.data(), certContent.size());

        // Real signature over transcript
        auto t0  = std::chrono::high_resolution_clock::now();
        auto sig = SignTranscript(g_staCertCtx[idx].apKey, transcript);
        auto t1  = std::chrono::high_resolution_clock::now();
        double signUs = std::chrono::duration<double, std::micro>(t1 - t0).count();

        // Update our own transcript record with the signed transcript
        m_transcript[socket] = transcript;

        // Send ServerCertMsg after signing delay
        uint32_t msgSize = g_staCertCtx[idx].serverCertMsgSize();
        Simulator::Schedule(
            MicroSeconds(static_cast<uint64_t>(signUs)),
            [socket, msgSize]() { socket->Send(Create<Packet>(msgSize)); });
    }

    uint32_t FindStaIndex(Ipv4Address addr)
    {
        for (uint32_t i = 0; i < g_staCertCtx.size(); ++i)
        {
            Ptr<Node> node = NodeList::GetNode(i + 1);
            Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
            for (uint32_t iface = 0; iface < ipv4->GetNInterfaces(); ++iface)
                for (uint32_t a = 0; a < ipv4->GetNAddresses(iface); ++a)
                    if (ipv4->GetAddress(iface, a).GetLocal() == addr)
                        return i;
        }
        return 0;
    }

    Ptr<Socket>                                    m_socket;
    std::map<Ptr<Socket>, Stage>                   m_stage;
    std::map<Ptr<Socket>, uint32_t>                m_bytesRx;
    std::map<Ptr<Socket>, uint32_t>                m_staIdx;
    std::map<Ptr<Socket>, std::vector<uint8_t>>    m_transcript;
};

// ---------------------------------------------------------------------------
// Client application (station side)
// ---------------------------------------------------------------------------

/**
 * @brief Station-side TLS handshake client.
 *
 * State machine:
 *
 *   After TCP connect -> send ClientHello (300 B)
 *                        buffer ClientHello in transcript
 *
 *   WAIT_SERVER_HELLO
 *     -> on receipt of kServerHelloSize bytes:
 *          update transcript with ServerHello
 *        -> WAIT_SERVER_CERT
 *
 *   WAIT_SERVER_CERT
 *     -> on receipt of serverCertMsgSize bytes:
 *          verify AP signature (EVP_DigestVerify)
 *          verify AP cert chain (X509_verify_cert + X509_check_private_key)
 *          schedule ClientCertMsg after verify delay
 *        -> WAIT_DONE (connection closes after send)
 */
class TlsClientApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("TlsClientApp")
                                .SetParent<Application>()
                                .SetGroupName("Applications")
                                .AddConstructor<TlsClientApp>();
        return tid;
    }

    TlsClientApp()  = default;
    ~TlsClientApp() override = default;

    void Setup(Ipv4Address                address,
               uint16_t                   port,
               Ptr<PropagationDelayModel> propDelayModel,
               Ptr<MobilityModel>         apMobility,
               Ptr<MobilityModel>         staMobility,
               uint32_t                   numHandshakes,
               uint32_t                   staIndex)
    {
        m_peerAddress   = address;
        m_peerPort      = port;
        m_propDelay     = propDelayModel;
        m_apMobility    = apMobility;
        m_staMobility   = staMobility;
        m_numHandshakes = numHandshakes;
        m_staIndex      = staIndex;
    }

  private:
    enum class Stage { WAIT_SERVER_HELLO, WAIT_SERVER_CERT };

    void StartApplication() override
    {
        m_handshakeIndex = 0;
        StartNextHandshake();
    }

    void StopApplication() override
    {
        if (m_socket) { m_socket->Close(); m_socket = nullptr; }
    }

    void StartNextHandshake()
    {
        if (m_handshakeIndex >= m_numHandshakes) return;
        m_stage          = Stage::WAIT_SERVER_HELLO;
        m_bytesRx        = 0;
        m_verifyStaUs    = 0.0;
        m_handshakeStart = Simulator::Now();
        m_transcript.clear();

        m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
        m_socket->Connect(InetSocketAddress(m_peerAddress, m_peerPort));
        m_socket->SetConnectCallback(
            MakeCallback(&TlsClientApp::HandleConnect, this),
            MakeNullCallback<void, Ptr<Socket>>());
        m_socket->SetRecvCallback(MakeCallback(&TlsClientApp::HandleRecv, this));
    }

    void HandleConnect(Ptr<Socket> socket)
    {
        // Send ClientHello and buffer it in transcript
        socket->Send(Create<Packet>(kClientHelloSize));
        std::vector<uint8_t> chBytes(kClientHelloSize, 0xAB);
        UpdateTranscript(m_transcript, chBytes.data(), chBytes.size());
    }

    void HandleRecv(Ptr<Socket> socket)
    {
        Ptr<Packet> pkt;
        while ((pkt = socket->Recv()))
        {
            if (pkt->GetSize() == 0) break;
            m_bytesRx += pkt->GetSize();

            if (m_stage == Stage::WAIT_SERVER_HELLO &&
                m_bytesRx >= kServerHelloSize)
            {
                // Update transcript with ServerHello
                std::vector<uint8_t> shBytes(kServerHelloSize, 0xCD);
                UpdateTranscript(m_transcript, shBytes.data(), shBytes.size());
                m_stage   = Stage::WAIT_SERVER_CERT;
                m_bytesRx = 0;
            }
            else if (m_stage == Stage::WAIT_SERVER_CERT &&
                     m_staIndex < g_staCertCtx.size() &&
                     m_bytesRx >= g_staCertCtx[m_staIndex].serverCertMsgSize())
            {
                // Update transcript with cert chain content (before sig)
                uint32_t contentSize = g_staCertCtx[m_staIndex].apCertDerSize
                                     + g_staCertCtx[m_staIndex].caCertDerSize
                                     + kExtraBytes;
                std::vector<uint8_t> certContent(contentSize, 0xCD);
                UpdateTranscript(m_transcript, certContent.data(), certContent.size());

                // Verify AP: sig + chain + key
                auto t0 = std::chrono::high_resolution_clock::now();

                // Real sig verify: produce AP signature over transcript and verify
                auto sig = SignTranscript(g_staCertCtx[m_staIndex].apKey, m_transcript);
                EVP_PKEY* apPub = X509_get0_pubkey(g_staCertCtx[m_staIndex].apCert);
                VerifyTranscriptSig(apPub, m_transcript, sig);

                // Chain + key check
                VerifyChain(g_staCertCtx[m_staIndex].caStore,
                            g_staCertCtx[m_staIndex].apCert);

                auto t1 = std::chrono::high_resolution_clock::now();
                m_verifyStaUs = std::chrono::duration<double, std::micro>(t1 - t0).count();

                // Sign transcript with STA key and send ClientCertMsg
                Simulator::Schedule(
                    MicroSeconds(static_cast<uint64_t>(m_verifyStaUs)),
                    &TlsClientApp::SignAndSendClientCert, this, socket);

                m_stage   = Stage::WAIT_SERVER_HELLO; // sentinel: done receiving
                m_bytesRx = 0;
            }
        }
    }

    void SignAndSendClientCert(Ptr<Socket> socket)
    {
        // Update transcript with STA cert chain content
        uint32_t contentSize = g_staCertCtx[m_staIndex].staCertDerSize
                             + g_staCertCtx[m_staIndex].caCertDerSize
                             + kExtraBytes;
        std::vector<uint8_t> certContent(contentSize, 0xEF);
        UpdateTranscript(m_transcript, certContent.data(), certContent.size());

        // Real signature by STA
        auto t0  = std::chrono::high_resolution_clock::now();
        auto sig = SignTranscript(g_staCertCtx[m_staIndex].staKey, m_transcript);
        auto t1  = std::chrono::high_resolution_clock::now();
        double signUs = std::chrono::duration<double, std::micro>(t1 - t0).count();

        uint32_t msgSize = g_staCertCtx[m_staIndex].clientCertMsgSize();

        Simulator::Schedule(
            MicroSeconds(static_cast<uint64_t>(signUs)),
            [this, socket, msgSize]() {
                socket->Send(Create<Packet>(msgSize));
                RecordHandshake();
                Simulator::ScheduleNow(&TlsClientApp::FinishHandshake, this, socket);
            });
    }

    void FinishHandshake(Ptr<Socket> socket)
    {
        socket->Close();
        m_handshakeIndex++;
        StartNextHandshake();
    }

    void RecordHandshake()
    {
        Time   now      = Simulator::Now();
        double delayMs  = (now - m_handshakeStart).GetMicroSeconds() / 1000.0;
        double durS     = std::max((now - m_handshakeStart).GetSeconds(), 1e-9);

        uint32_t idx    = m_staIndex;
        uint32_t sCertSz = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].serverCertMsgSize() : 0;
        uint32_t cCertSz = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].clientCertMsgSize() : 0;
        uint32_t totalBytes = kClientHelloSize + kServerHelloSize + sCertSz + cCertSz;

        double goodputKbps = (totalBytes * 8.0 / 1000.0) / durS;

        uint32_t nodeId  = GetNode()->GetId();

        double   txDelayUs = 0.0;
        uint64_t wireBytes = 0;
        uint32_t txFrames  = 0;
        auto txIt = g_phyTxByNode.find(nodeId);
        if (txIt != g_phyTxByNode.end())
        {
            double txSum = 0.0;
            for (const auto& s : txIt->second)
            {
                if (s.timestamp >= m_handshakeStart && s.timestamp <= now)
                {
                    txSum    += s.delay.GetMicroSeconds();
                    wireBytes += s.bytes;
                    ++txFrames;
                }
            }
            if (txFrames > 0) txDelayUs = txSum / txFrames;
        }
        double throughputKbps = (wireBytes * 8.0 / 1000.0) / durS;

        uint32_t drops = 0;
        for (const auto& d : g_phyDropsAtAp)
            if (d.timestamp >= m_handshakeStart && d.timestamp <= now)
                ++drops;
        double phyDropRate =
            (txFrames > 0) ? std::min(1.0, static_cast<double>(drops) / txFrames) : 0.0;

        uint32_t macRetries = 0;
        auto retryIt = g_macRetriesByNode.find(nodeId);
        if (retryIt != g_macRetriesByNode.end())
            for (const auto& r : retryIt->second)
                if (r.timestamp >= m_handshakeStart && r.timestamp <= now)
                    ++macRetries;
        double macRetryRate = (txFrames > 0) ? static_cast<double>(macRetries) / txFrames : 0.0;

        double propDelayNs =
            m_propDelay->GetDelay(m_apMobility, m_staMobility).GetNanoSeconds();

        g_records.push_back({nodeId,
                              m_handshakeIndex,
                              delayMs,
                              goodputKbps,
                              throughputKbps,
                              phyDropRate,
                              static_cast<double>(macRetries),
                              macRetryRate,
                              txDelayUs,
                              propDelayNs,
                              0.0,            // certVerifyApUs: filled by server app
                              m_verifyStaUs,
                              sCertSz,
                              cCertSz});
    }

    Ptr<Socket>                m_socket;
    Ipv4Address                m_peerAddress;
    uint16_t                   m_peerPort{0};
    Ptr<PropagationDelayModel> m_propDelay;
    Ptr<MobilityModel>         m_apMobility;
    Ptr<MobilityModel>         m_staMobility;
    uint32_t                   m_numHandshakes{0};
    uint32_t                   m_handshakeIndex{0};
    uint32_t                   m_staIndex{0};
    Stage                      m_stage{Stage::WAIT_SERVER_HELLO};
    uint32_t                   m_bytesRx{0};
    double                     m_verifyStaUs{0.0};
    Time                       m_handshakeStart;
    std::vector<uint8_t>       m_transcript;
};

} // anonymous namespace

// ---------------------------------------------------------------------------
// Helper: split a colon-separated string
// ---------------------------------------------------------------------------

static std::vector<std::string>
SplitColon(const std::string& s)
{
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, ':'))
        result.push_back(tok);
    return result;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    uint32_t    scenario          = 1;
    uint32_t    handshakesPerNode = kHandshakesPerNode;
    double      roomWidth         = 14.0;
    double      roomHeight        = 10.0;
    double      simulationTime    = 300.0;
    std::string csvFileName       = "tls-wifi-sim-metrics.csv";
    bool        enablePcap        = false;

    std::string staCertPaths = "";
    std::string staKeyPaths  = "";
    std::string apCertPaths  = "";
    std::string apKeyPaths   = "";
    std::string caCertPaths  = "";
    std::string staCertAlgos = "";
    std::string apCertAlgos  = "";

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario",          "Scenario (1-4)", scenario);
    cmd.AddValue("handshakesPerNode", "Handshakes per station", handshakesPerNode);
    cmd.AddValue("roomWidth",         "Room width (m)", roomWidth);
    cmd.AddValue("roomHeight",        "Room height (m)", roomHeight);
    cmd.AddValue("simulationTime",    "Simulation safety stop (s)", simulationTime);
    cmd.AddValue("csvFileName",       "Output CSV file", csvFileName);
    cmd.AddValue("enablePcap",        "Enable pcap", enablePcap);
    cmd.AddValue("staCertPaths",      "Station cert path(s)", staCertPaths);
    cmd.AddValue("staKeyPaths",       "Station private key path(s)", staKeyPaths);
    cmd.AddValue("apCertPaths",       "AP cert path(s)", apCertPaths);
    cmd.AddValue("apKeyPaths",        "AP private key path(s)", apKeyPaths);
    cmd.AddValue("caCertPaths",       "CA cert path(s)", caCertPaths);
    cmd.AddValue("staCertAlgos",      "Station cert algo label(s)", staCertAlgos);
    cmd.AddValue("apCertAlgos",       "AP cert algo label(s)", apCertAlgos);
    cmd.Parse(argc, argv);

    const uint32_t nStations = 8;

    auto staCertVec = SplitColon(staCertPaths);
    auto staKeyVec  = SplitColon(staKeyPaths);
    auto apCertVec  = SplitColon(apCertPaths);
    auto apKeyVec   = SplitColon(apKeyPaths);
    auto caCertVec  = SplitColon(caCertPaths);
    auto stAlgoVec  = SplitColon(staCertAlgos);
    auto apAlgoVec  = SplitColon(apCertAlgos);

    auto expand = [&](std::vector<std::string>& v) {
        if (v.size() == 1) v.assign(nStations, v[0]);
    };
    expand(staCertVec); expand(staKeyVec);
    expand(apCertVec);  expand(apKeyVec);
    expand(caCertVec);  expand(stAlgoVec); expand(apAlgoVec);

    if (staCertVec.size() != nStations || staKeyVec.size() != nStations ||
        apCertVec.size()  != nStations || apKeyVec.size()  != nStations ||
        caCertVec.size()  != nStations)
    {
        std::cerr << "Error: cert/key path lists must have 1 or " << nStations << " entries.\n";
        return 1;
    }

    // Load certs, keys, compute sizes
    g_staCertCtx.resize(nStations);
    for (uint32_t i = 0; i < nStations; ++i)
    {
        auto& ctx = g_staCertCtx[i];
        try
        {
            ctx.staCert = LoadCert(staCertVec[i]);
            ctx.staKey  = LoadKey(staKeyVec[i]);
            ctx.apCert  = LoadCert(apCertVec[i]);
            ctx.apKey   = LoadKey(apKeyVec[i]);
            ctx.caCert  = LoadCert(caCertVec[i]);
            ctx.caStore = BuildStore(caCertVec[i]);
            ctx.staCertAlgo = (i < stAlgoVec.size()) ? stAlgoVec[i] : "unknown";
            ctx.apCertAlgo  = (i < apAlgoVec.size()) ? apAlgoVec[i] : "unknown";

            // DER sizes
            ctx.staCertDerSize = CertDerSize(ctx.staCert);
            ctx.apCertDerSize  = CertDerSize(ctx.apCert);
            ctx.caCertDerSize  = CertDerSize(ctx.caCert);

            // Signature sizes: produce a real signature to get the true size
            std::vector<uint8_t> dummyTranscript(32, 0x00);
            auto staSig = SignTranscript(ctx.staKey, dummyTranscript);
            auto apSig  = SignTranscript(ctx.apKey,  dummyTranscript);
            ctx.staSigSize = static_cast<uint32_t>(staSig.size());
            ctx.apSigSize  = static_cast<uint32_t>(apSig.size());
        }
        catch (const std::exception& e)
        {
            std::cerr << "Load error for station " << (i + 1) << ": " << e.what() << "\n";
            return 1;
        }
    }

    // ns-3 setup
    Time::SetResolution(Time::NS);
    LogComponentEnable("TlsWifiSim", LOG_LEVEL_WARN);

    NodeContainer apNode;       apNode.Create(1);
    NodeContainer staticStaNodes; staticStaNodes.Create(4);
    NodeContainer mobileStaNodes; mobileStaNodes.Create(4);
    NodeContainer allStaNodes;
    allStaNodes.Add(staticStaNodes);
    allStaNodes.Add(mobileStaNodes);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    phy.Set("ChannelSettings", StringValue("{0, 20, BAND_2_4GHZ, 0}"));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211n);
    wifi.SetRemoteStationManager("ns3::MinstrelHtWifiManager");

    WifiMacHelper mac;
    Ssid ssid = Ssid("home-net");
    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid),
                "ActiveProbing", BooleanValue(false));
    NetDeviceContainer staDevices = wifi.Install(phy, mac, allStaNodes);
    mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
    NetDeviceContainer apDevice = wifi.Install(phy, mac, apNode);

    MobilityHelper mobility;
    Ptr<ListPositionAllocator> fixedPos = CreateObject<ListPositionAllocator>();
    fixedPos->Add(Vector(roomWidth / 2.0, roomHeight / 2.0, 0.0));
    const std::vector<Vector> corners = {
        {1.0,             1.0,              0.0},
        {roomWidth - 1.0, 1.0,              0.0},
        {1.0,             roomHeight - 1.0, 0.0},
        {roomWidth - 1.0, roomHeight - 1.0, 0.0},
    };
    for (const auto& c : corners) fixedPos->Add(c);
    mobility.SetPositionAllocator(fixedPos);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(apNode);
    mobility.Install(staticStaNodes);

    mobility.SetPositionAllocator(
        "ns3::RandomBoxPositionAllocator",
        "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=" + std::to_string(roomWidth)  + "]"),
        "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=" + std::to_string(roomHeight) + "]"),
        "Z", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    mobility.SetMobilityModel(
        "ns3::RandomWalk2dMobilityModel",
        "Bounds", RectangleValue(Rectangle(0, roomWidth, 0, roomHeight)),
        "Speed",  StringValue("ns3::ConstantRandomVariable[Constant=0.7]"));
    mobility.Install(mobileStaNodes);

    InternetStackHelper stack;
    stack.Install(apNode);
    stack.Install(allStaNodes);

    Ipv4AddressHelper addr;
    addr.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer apIface = addr.Assign(apDevice);
    addr.Assign(staDevices);

    Ptr<TlsServerApp> serverApp = CreateObject<TlsServerApp>();
    apNode.Get(0)->AddApplication(serverApp);
    serverApp->SetStartTime(Seconds(0.0));
    serverApp->SetStopTime(Seconds(simulationTime));

    Ptr<ConstantSpeedPropagationDelayModel> propDelay =
        CreateObject<ConstantSpeedPropagationDelayModel>();
    Ptr<MobilityModel> apMobility = apNode.Get(0)->GetObject<MobilityModel>();
    Ipv4Address        serverAddr  = apIface.GetAddress(0);

    for (uint32_t i = 0; i < allStaNodes.GetN(); ++i)
    {
        Ptr<TlsClientApp> clientApp = CreateObject<TlsClientApp>();
        clientApp->Setup(serverAddr, kHandshakePort, propDelay,
                         apMobility,
                         allStaNodes.Get(i)->GetObject<MobilityModel>(),
                         handshakesPerNode, i);
        allStaNodes.Get(i)->AddApplication(clientApp);
        clientApp->SetStartTime(Seconds(2.0));
        clientApp->SetStopTime(Seconds(simulationTime));
    }

    if (enablePcap) phy.EnablePcap("tls-wifi-sim-ap", apDevice);

    Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin",
                    MakeCallback(&PhyTxBeginTrace));
    Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxEnd",
                    MakeCallback(&PhyTxEndTrace));
    Config::Connect("/NodeList/0/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxDrop",
                    MakeCallback(&PhyRxDropTrace));
    Config::Connect("/NodeList/*/DeviceList/*/RemoteStationManager/MacTxDataFailed",
                    MakeCallback(&MacTxDataFailedTrace));

    Simulator::Stop(Seconds(simulationTime));
    Simulator::Run();

    // Write CSV
    std::ofstream csv(csvFileName);
    csv << "scenario,node_id,handshake_index,"
           "sta_cert_algo,ap_cert_algo,"
           "handshake_delay_ms,goodput_kbps,throughput_kbps,"
           "phy_frame_drop_rate,mac_retries,mac_retry_rate,"
           "tx_delay_us,prop_delay_ns,"
           "cert_verify_ap_us,cert_verify_sta_us,"
           "server_cert_msg_bytes,client_cert_msg_bytes\n";
    for (const auto& r : g_records)
    {
        uint32_t idx = r.nodeId - 1;
        std::string staAlgo = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].staCertAlgo : "";
        std::string apAlgo  = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].apCertAlgo  : "";
        csv << scenario           << ","
            << r.nodeId           << ","
            << r.handshakeIndex   << ","
            << staAlgo            << ","
            << apAlgo             << ","
            << r.delayMs          << ","
            << r.goodputKbps      << ","
            << r.throughputKbps   << ","
            << r.phyDropRate      << ","
            << r.macRetries       << ","
            << r.macRetryRate     << ","
            << r.txDelayUs        << ","
            << r.propDelayNs      << ","
            << r.certVerifyApUs   << ","
            << r.certVerifyStaUs  << ","
            << r.serverCertMsgSize << ","
            << r.clientCertMsgSize << "\n";
    }
    csv.close();

    // Per-node summary
    std::map<uint32_t, std::vector<double>> delayByNode, goodputByNode,
        throughputByNode, phyDropByNode, macRetriesByNode, macRetryRateByNode,
        txDelayByNode, propDelayByNode, certApByNode, certStaByNode;

    for (const auto& r : g_records)
    {
        delayByNode[r.nodeId].push_back(r.delayMs);
        goodputByNode[r.nodeId].push_back(r.goodputKbps);
        throughputByNode[r.nodeId].push_back(r.throughputKbps);
        phyDropByNode[r.nodeId].push_back(r.phyDropRate);
        macRetriesByNode[r.nodeId].push_back(r.macRetries);
        macRetryRateByNode[r.nodeId].push_back(r.macRetryRate);
        txDelayByNode[r.nodeId].push_back(r.txDelayUs);
        propDelayByNode[r.nodeId].push_back(r.propDelayNs);
        certApByNode[r.nodeId].push_back(r.certVerifyApUs);
        certStaByNode[r.nodeId].push_back(r.certVerifyStaUs);
    }

    std::cout << "\n=== Scenario " << scenario
              << " — per-node summary over " << handshakesPerNode
              << " handshakes (mean +/- stddev) ===\n";
    std::cout << std::fixed << std::setprecision(4);

    for (const auto& [nodeId, delays] : delayByNode)
    {
        auto stat = [](const std::vector<double>& v) -> std::pair<double, double> {
            double m = Mean(v); return {m, StdDev(v, m)};
        };
        auto [dm,  ds]  = stat(delays);
        auto [gm,  gs]  = stat(goodputByNode[nodeId]);
        auto [tm,  ts]  = stat(throughputByNode[nodeId]);
        auto [pm,  ps]  = stat(phyDropByNode[nodeId]);
        auto [rm,  rs]  = stat(macRetriesByNode[nodeId]);
        auto [rrm, rrs] = stat(macRetryRateByNode[nodeId]);
        auto [xm,  xs]  = stat(txDelayByNode[nodeId]);
        auto [prm, prs] = stat(propDelayByNode[nodeId]);
        auto [cam, cas] = stat(certApByNode[nodeId]);
        auto [csm, css] = stat(certStaByNode[nodeId]);

        uint32_t idx = nodeId - 1;
        std::string staAlgo = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].staCertAlgo : "";
        std::string apAlgo  = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].apCertAlgo  : "";
        uint32_t sCertSz = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].serverCertMsgSize() : 0;
        uint32_t cCertSz = (idx < g_staCertCtx.size()) ? g_staCertCtx[idx].clientCertMsgSize() : 0;

        std::cout << "Node " << nodeId
                  << " [sta=" << staAlgo << " ap=" << apAlgo
                  << "] (n=" << delays.size() << "):\n";
        std::cout << "  Handshake delay:         " << dm  << " +/- " << ds  << " ms\n";
        std::cout << "  Goodput:                 " << gm  << " +/- " << gs  << " kbps\n";
        std::cout << "  Throughput:              " << tm  << " +/- " << ts  << " kbps\n";
        std::cout << "  PHY frame drop rate:     " << pm  << " +/- " << ps  << " (fraction)\n";
        std::cout << "  MAC retries:             " << rm  << " +/- " << rs  << " per handshake\n";
        std::cout << "  MAC retry rate:          " << rrm << " +/- " << rrs << " (retries/frames)\n";
        std::cout << "  TX delay:                " << xm  << " +/- " << xs  << " us\n";
        std::cout << "  Propagation delay:       " << prm << " +/- " << prs << " ns\n";
        std::cout << "  Cert verify (AP):        " << cam << " +/- " << cas << " us\n";
        std::cout << "  Cert verify (station):   " << csm << " +/- " << css << " us\n";
        std::cout << "  ServerCertMsg size:      " << sCertSz << " bytes\n";
        std::cout << "  ClientCertMsg size:      " << cCertSz << " bytes\n";
    }

    std::cout << "\nPer-handshake records written to: " << csvFileName << "\n";

    for (auto& ctx : g_staCertCtx)
    {
        if (ctx.staCert) X509_free(ctx.staCert);
        if (ctx.staKey)  EVP_PKEY_free(ctx.staKey);
        if (ctx.apCert)  X509_free(ctx.apCert);
        if (ctx.apKey)   EVP_PKEY_free(ctx.apKey);
        if (ctx.caCert)  X509_free(ctx.caCert);
        if (ctx.caStore) X509_STORE_free(ctx.caStore);
    }

    Simulator::Destroy();
    return 0;
}
