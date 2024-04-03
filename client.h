#pragma once

#include <iostream>
#include <string>
#include <thread>

#include <glog/logging.h>

#include <folly/fibers/Baton.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <fizz/protocol/CertificateVerifier.h>


class client_certificate_verifier : public fizz::CertificateVerifier {
 public:
  ~client_certificate_verifier() override = default;

  std::shared_ptr<const folly::AsyncTransportCertificate> verify(
      const std::vector<std::shared_ptr<const fizz::PeerCert>>& certs)
      const override {
    return certs.front();
  }

  [[nodiscard]] std::vector<fizz::Extension> getCertificateRequestExtensions()
      const override {
    return std::vector<fizz::Extension>();
  }
};




class client:public quic::QuicSocket::ConnectionSetupCallback,
                   public quic::QuicSocket::ConnectionCallback,
                   public quic::QuicSocket::ReadCallback {
public:
    
  client(std::string host, uint16_t port);
  void start();

  void onConnectionSetupError(quic::QuicError code) noexcept override;
  void onNewBidirectionalStream(quic::StreamId id) noexcept override;
  void onNewUnidirectionalStream(quic::StreamId id) noexcept override;
  void onStopSending(quic::StreamId id, quic::ApplicationErrorCode error) noexcept override;
  void onConnectionEnd() noexcept override;
  void onConnectionError(quic::QuicError code) noexcept override;
  void onTransportReady() noexcept override;
  void readAvailable(quic::StreamId id) noexcept override;
  void readError(quic::StreamId id, quic::QuicError error) noexcept override;

  void send_message(quic::StreamId id, quic::BufQueue& data);
  
private:
  std::string host_;
  uint16_t port_;
  std::shared_ptr<quic::QuicClientTransport> quic_client_;
  folly::fibers::Baton start_done_;
  std::map<quic::StreamId, quic::BufQueue> pending_output_;
};