#pragma once

#include <fizz/crypto/Utils.h>
#include <folly/init/Init.h>
#include <folly/portability/GFlags.h>
#include <folly/Synchronized.h>
#include <glog/logging.h>
#include <quic/server/QuicServer.h>
#include <quic/QuicException.h>
#include <quic/codec/Types.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>


class server_handle:public quic::QuicSocket::ConnectionSetupCallback,
                    public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback
{
public:
    using StreamData = std::pair<quic::BufQueue, bool>;

    server_handle(folly::EventBase* evb);
    ~server_handle() override;

    void onConnectionSetupError(quic::QuicError code) noexcept override;
    void onNewBidirectionalStream(quic::StreamId id) noexcept override;
    void onNewUnidirectionalStream(quic::StreamId id) noexcept override;

    void onStopSending(quic::StreamId id, quic::ApplicationErrorCode error) noexcept override;
    void onConnectionEnd() noexcept override;
    void onConnectionError(quic::QuicError code) noexcept override;

    void readAvailable(quic::StreamId id) noexcept override;
    void readError(quic::StreamId id, quic::QuicError error) noexcept override;

    void set_quicsock(std::shared_ptr<quic::QuicSocket> sock);
    void echo(quic::StreamId id, StreamData& data);

    folly::EventBase* get_eventbase() {
        return event_base_;
    }

private:

    folly::EventBase* event_base_;
    std::shared_ptr<quic::QuicSocket> sock_;
    using PerStreamData = std::map<quic::StreamId, StreamData>;
    PerStreamData input_;
};


class transport_factory:public quic::QuicServerTransportFactory {
public:

    transport_factory();
    ~transport_factory() override;

    virtual quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<quic::FollyAsyncUDPSocketAlias> socket,
      const folly::SocketAddress& addr,
      quic::QuicVersion quicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept override;

private:
    folly::Synchronized<std::vector<std::unique_ptr<server_handle>>> echoHandlers_;
};


class server {
public:

    server(std::string host, uint16_t port, std::string cert, std::string key);
    ~server();
    server(const server& rhs) = delete;
    server(server&& rhs) = delete;

    void run();
    std::shared_ptr<fizz::server::FizzServerContext> create_server_ctx();
    
private:

    std::string host_;
    uint16_t port_;
    std::string cert_;
    std::string key_;
    folly::EventBase eventbase_;
    std::shared_ptr<quic::QuicServer> quic_server_;
};