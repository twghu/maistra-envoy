#include "source/extensions/transport_sockets/tls/ssl_handshaker.h"

#include "envoy/stats/scope.h"

#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/http/headers.h"
#include "source/extensions/transport_sockets/tls/utility.h"

using Envoy::Network::PostIoAction;

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

void SslExtendedSocketInfoImpl::setCertificateValidationStatus(
    Envoy::Ssl::ClientValidationStatus validated) {
  certificate_validation_status_ = validated;
}

Envoy::Ssl::ClientValidationStatus SslExtendedSocketInfoImpl::certificateValidationStatus() const {
  return certificate_validation_status_;
}

SslHandshakerImpl::SslHandshakerImpl(bssl::UniquePtr<SSL> ssl, int ssl_extended_socket_info_index,
                                     Ssl::HandshakeCallbacks* handshake_callbacks)
    : ssl_(std::move(ssl)), handshake_callbacks_(handshake_callbacks),
      state_(Ssl::SocketState::PreHandshake) {
  SSL_set_ex_data(ssl_.get(), ssl_extended_socket_info_index, &(this->extended_socket_info_));
}

bool SslHandshakerImpl::peerCertificateValidated() const {
  return extended_socket_info_.certificateValidationStatus() ==
         Envoy::Ssl::ClientValidationStatus::Validated;
}

absl::Span<const std::string> SslHandshakerImpl::uriSanLocalCertificate() const {
  if (!cached_uri_san_local_certificate_.empty()) {
    return cached_uri_san_local_certificate_;
  }

  // The cert object is not owned.
  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_uri_san_local_certificate_.empty());
    return cached_uri_san_local_certificate_;
  }
  cached_uri_san_local_certificate_ = Utility::getSubjectAltNames(*cert, GEN_URI);
  return cached_uri_san_local_certificate_;
}

absl::Span<const std::string> SslHandshakerImpl::dnsSansLocalCertificate() const {
  if (!cached_dns_san_local_certificate_.empty()) {
    return cached_dns_san_local_certificate_;
  }

  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_dns_san_local_certificate_.empty());
    return cached_dns_san_local_certificate_;
  }
  cached_dns_san_local_certificate_ = Utility::getSubjectAltNames(*cert, GEN_DNS);
  return cached_dns_san_local_certificate_;
}

const std::string& SslHandshakerImpl::sha256PeerCertificateDigest() const {
  if (!cached_sha_256_peer_certificate_digest_.empty()) {
    return cached_sha_256_peer_certificate_digest_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_sha_256_peer_certificate_digest_.empty());
    return cached_sha_256_peer_certificate_digest_;
  }

  std::vector<uint8_t> computed_hash(SHA256_DIGEST_LENGTH);
  unsigned int n;
  X509_digest(cert.get(), EVP_sha256(), computed_hash.data(), &n);
  RELEASE_ASSERT(n == computed_hash.size(), "");
  cached_sha_256_peer_certificate_digest_ = Hex::encode(computed_hash);
  return cached_sha_256_peer_certificate_digest_;
}

const std::string& SslHandshakerImpl::sha1PeerCertificateDigest() const {
  if (!cached_sha_1_peer_certificate_digest_.empty()) {
    return cached_sha_1_peer_certificate_digest_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_sha_1_peer_certificate_digest_.empty());
    return cached_sha_1_peer_certificate_digest_;
  }

  std::vector<uint8_t> computed_hash(SHA_DIGEST_LENGTH);
  unsigned int n;
  X509_digest(cert.get(), EVP_sha1(), computed_hash.data(), &n);
  RELEASE_ASSERT(n == computed_hash.size(), "");
  cached_sha_1_peer_certificate_digest_ = Hex::encode(computed_hash);
  return cached_sha_1_peer_certificate_digest_;
}

const std::string& SslHandshakerImpl::urlEncodedPemEncodedPeerCertificate() const {
  if (!cached_url_encoded_pem_encoded_peer_certificate_.empty()) {
    return cached_url_encoded_pem_encoded_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_url_encoded_pem_encoded_peer_certificate_.empty());
    return cached_url_encoded_pem_encoded_peer_certificate_;
  }

  bssl::UniquePtr<BIO> buf(BIO_new(BIO_s_mem()));
  RELEASE_ASSERT(buf != nullptr, "");
  RELEASE_ASSERT(PEM_write_bio_X509(buf.get(), cert.get()) == 1, "");
  const uint8_t* output;
  size_t length;
  RELEASE_ASSERT(BIO_mem_contents(buf.get(), &output, &length) == 1, "");
  absl::string_view pem(reinterpret_cast<const char*>(output), length);
  cached_url_encoded_pem_encoded_peer_certificate_ = absl::StrReplaceAll(
      pem, {{"\n", "%0A"}, {" ", "%20"}, {"+", "%2B"}, {"/", "%2F"}, {"=", "%3D"}});
  return cached_url_encoded_pem_encoded_peer_certificate_;
}

const std::string& SslHandshakerImpl::urlEncodedPemEncodedPeerCertificateChain() const {
  if (!cached_url_encoded_pem_encoded_peer_cert_chain_.empty()) {
    return cached_url_encoded_pem_encoded_peer_cert_chain_;
  }

  STACK_OF(X509)* cert_chain = SSL_get_peer_full_cert_chain(ssl());
  if (cert_chain == nullptr) {
    ASSERT(cached_url_encoded_pem_encoded_peer_cert_chain_.empty());
    return cached_url_encoded_pem_encoded_peer_cert_chain_;
  }

  for (int i = 0; i < sk_X509_num(cert_chain); i++) {
    X509* cert = sk_X509_value(cert_chain, i);

    bssl::UniquePtr<BIO> buf(BIO_new(BIO_s_mem()));
    RELEASE_ASSERT(buf != nullptr, "");
    RELEASE_ASSERT(PEM_write_bio_X509(buf.get(), cert) == 1, "");
    const uint8_t* output;
    size_t length;
    RELEASE_ASSERT(BIO_mem_contents(buf.get(), &output, &length) == 1, "");

    absl::string_view pem(reinterpret_cast<const char*>(output), length);
    cached_url_encoded_pem_encoded_peer_cert_chain_ = absl::StrCat(
        cached_url_encoded_pem_encoded_peer_cert_chain_,
        absl::StrReplaceAll(
            pem, {{"\n", "%0A"}, {" ", "%20"}, {"+", "%2B"}, {"/", "%2F"}, {"=", "%3D"}}));
  }
  return cached_url_encoded_pem_encoded_peer_cert_chain_;
}

absl::Span<const std::string> SslHandshakerImpl::uriSanPeerCertificate() const {
  if (!cached_uri_san_peer_certificate_.empty()) {
    return cached_uri_san_peer_certificate_;
  }

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_uri_san_peer_certificate_.empty());
    return cached_uri_san_peer_certificate_;
  }
  cached_uri_san_peer_certificate_ = Utility::getSubjectAltNames(*cert, GEN_URI);
  return cached_uri_san_peer_certificate_;
}

absl::Span<const std::string> SslHandshakerImpl::dnsSansPeerCertificate() const {
  if (!cached_dns_san_peer_certificate_.empty()) {
    return cached_dns_san_peer_certificate_;
  }

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_dns_san_peer_certificate_.empty());
    return cached_dns_san_peer_certificate_;
  }
  cached_dns_san_peer_certificate_ = Utility::getSubjectAltNames(*cert, GEN_DNS);
  return cached_dns_san_peer_certificate_;
}

uint16_t SslHandshakerImpl::ciphersuiteId() const {
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  if (cipher == nullptr) {
    return 0xffff;
  }

  // From the OpenSSL docs:
  //    SSL_CIPHER_get_id returns |cipher|'s id. It may be cast to a |uint16_t| to
  //    get the cipher suite value.
  return static_cast<uint16_t>(SSL_CIPHER_get_id(cipher));
}

std::string SslHandshakerImpl::ciphersuiteString() const {
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  if (cipher == nullptr) {
    return {};
  }

  return SSL_CIPHER_get_name(cipher);
}

const std::string& SslHandshakerImpl::tlsVersion() const {
  if (!cached_tls_version_.empty()) {
    return cached_tls_version_;
  }
  cached_tls_version_ = SSL_get_version(ssl());
  return cached_tls_version_;
}

Network::PostIoAction SslHandshakerImpl::doHandshake() {
  ASSERT(state_ != Ssl::SocketState::HandshakeComplete && state_ != Ssl::SocketState::ShutdownSent);
  int rc = SSL_do_handshake(ssl());
  if (rc == 1) {
    state_ = Ssl::SocketState::HandshakeComplete;
    handshake_callbacks_->onSuccess(ssl());

    // It's possible that we closed during the handshake callback.
    return handshake_callbacks_->connection().state() == Network::Connection::State::Open
               ? PostIoAction::KeepOpen
               : PostIoAction::Close;
  } else {
    int err = SSL_get_error(ssl(), rc);
    ENVOY_CONN_LOG(trace, "ssl error occurred while read: {}", handshake_callbacks_->connection(),
                   Utility::getErrorDescription(err));
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return PostIoAction::KeepOpen;
    // SSL_ERROR_WANT_PRIVATE_KEY_OPERATION is undefined in OpenSSL
    // case SSL_ERROR_WANT_PRIVATE_KEY_OPERATION:
    //  state_ = Ssl::SocketState::HandshakeInProgress;
    //  return PostIoAction::KeepOpen;
    default:
      handshake_callbacks_->onFailure();
      return PostIoAction::Close;
    }
  }
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
