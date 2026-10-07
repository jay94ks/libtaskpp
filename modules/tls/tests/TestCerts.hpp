#pragma once
// Shared TLS test certificates: a P-256 CA plus a leaf for localhost/127.0.0.1.
// Included by TlsTests.cpp and H2Tests.cpp (no separate TU: everything inline).
#include "TestHarness.hpp"

#include <taskpp/tls/Tls.hpp>
#include <taskpp/core/Core.hpp>

#include <string>

using namespace taskpp;
using namespace taskpp::tls;

namespace testcerts {

namespace cx = certpp::x509;
namespace cc = certpp::crypto;

inline constexpr const char* kLoopback = "127.0.0.1";

inline certpp::ERetCode checkCert(certpp::ERetCode rc) {
    CHECK(rc == certpp::ERET_OK);
    return rc;
}

inline cc::SKeyPair generateKey(cc::EAsymmetrics algo, cc::SKeySize bits) {
    auto impl = cc::IAsymmetric::builtIn(algo);
    CHECK(!!impl);
    cc::SKeyPair pair;
    checkCert(impl->generateKeyPair(bits, pair));
    return pair;
}

inline certpp::CDistinguishedName dn(const char* cn) {
    certpp::CDistinguishedName out;
    CHECK(certpp::CDistinguishedName::tryParse(out, certpp::CString(cn)));
    return out;
}

inline certpp::SDateTime daysFromNow(int days) {
    auto now = certpp::SDateTime::now(true);
    return now.add(certpp::STimeSpan(static_cast<int64_t>(days) * 86400 * 1000));
}

inline cx::CCert makeCa(const cc::SKeyPair& pair) {
    cx::CCertBuilder builder;
    builder.issuer = dn("CN=Test CA");
    builder.subject = dn("CN=Test CA");
    const uint8_t serial[] = { 1 };
    builder.serialNumber = certpp::COctet(serial, sizeof(serial));
    builder.notBefore = daysFromNow(-1);
    builder.notAfter = daysFromNow(3650);
    builder.subjectKey = pair.publicKey;
    builder.issuerKeyPair = pair;

    cx::CBasicConstraintsExtensionBuilder bc;
    bc.setIsCa(true);
    bc.setPathLenConstraint(1);
    builder.extensions.add(bc.build());

    cx::CKeyUsagesExtensionBuilder ku;
    ku.setBits(cx::EKUSE_KEY_CERT_SIGN | cx::EKUSE_CRL_SIGN | cx::EKUSE_DIGITAL_SIGNATURE);
    builder.extensions.add(ku.build());

    cx::CCert cert;
    checkCert(builder.build(cert));
    return cert;
}

inline cx::CCert makeLeaf(const cc::SKeyPair& leafPair, const cx::CCert& ca,
    const cc::SKeyPair& caPair, bool expired = false,
    const char* ekuOid = cx::CEkuExtension::OID_SERVER_AUTH) {
    cx::CCertBuilder builder;
    builder.issuer = ca.subject();
    builder.subject = dn("CN=localhost");
    const uint8_t serial[] = { 2 };
    builder.serialNumber = certpp::COctet(serial, sizeof(serial));
    builder.notBefore = daysFromNow(-1);
    builder.notAfter = expired ? daysFromNow(-2) : daysFromNow(90);
    builder.subjectKey = leafPair.publicKey;
    builder.issuerKeyPair = caPair;

    cx::CBasicConstraintsExtensionBuilder bc;
    bc.setIsCa(false);
    builder.extensions.add(bc.build());

    cx::CKeyUsagesExtensionBuilder ku;
    ku.setBits(cx::EKUSE_DIGITAL_SIGNATURE);
    builder.extensions.add(ku.build());

    cx::CEkuExtensionBuilder eku;
    eku.addPurpose(certpp::CString(ekuOid));
    builder.extensions.add(eku.build());

    cx::CSanExtensionBuilder san;
    san.addName(cx::CGeneralName(cx::EGNAME_DNS, certpp::CString("localhost")));
    const uint8_t loopback[] = { 127, 0, 0, 1 };
    san.addName(cx::CGeneralName(cx::EGNAME_IP_ADDRESS,
        certpp::COctet(loopback, sizeof(loopback))));
    builder.extensions.add(san.build());

    cx::CCert cert;
    checkCert(builder.build(cert));
    // Server proves possession of the leaf key via CertificateVerify.
    auto priv = leafPair.privateKey;
    checkCert(cert.privateKey(priv));
    return cert;
}

struct Fixture {
    cc::SKeyPair caPair = generateKey(cc::EASYM_P256, 256);
    cc::SKeyPair leafPair = generateKey(cc::EASYM_P256, 256);
    cx::CCert ca = makeCa(caPair);
    cx::CCert leaf = makeLeaf(leafPair, ca, caPair);
    std::vector<uint8_t> ticketKey;

    TlsConfig serverConfig() {
        TlsConfig config;
        config.verifyPeer = false;
        config.certificateChain = { leaf };
        return config;
    }

    TlsConfig serverConfigWithTickets() {
        TlsConfig config = serverConfig();
        if (ticketKey.empty()) {
            ticketKey.assign(32, 0);
            certpp::SByteSpan span(ticketKey.data(), ticketKey.size());
            certpp::crypto::CRng::fill(span);
        }
        config.ticketKey = ticketKey;
        return config;
    }

    TlsConfig clientConfig(const std::string& name = "localhost") {
        TlsConfig config;
        config.trustAnchors = { ca };
        config.serverName = name;
        return config;
    }
};

inline Task<std::string> echoOnce(TlsStream* server) {
    std::string in(5, '\0');
    co_await server->readExact(std::span(in.data(), in.size()));
    co_await server->write(std::span(in.data(), in.size()));
    co_return in;
}

} // namespace testcerts
