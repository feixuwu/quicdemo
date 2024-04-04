#include "server.h"
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/protocol/CertUtils.h>
#include <fizz/server/AeadTicketCipher.h>
#include <fizz/server/CertManager.h>
#include <fizz/server/TicketCodec.h>
#include <folly/FileUtil.h>
#include <folly/Random.h>


server_handle::server_handle(folly::EventBase* evb):event_base_(evb) {

}

server_handle::~server_handle() {

}

void server_handle::readAvailable(quic::StreamId id) noexcept {
    LOG(INFO)<<"readAvailable stream:"<<id<<std::endl;
    auto res = sock_->read(id, 0);
    if(res.hasError() ) {
        LOG(ERROR) << "read stream:"<<id<<" Got error=" << toString(res.error());
        sock_->setReadCallback(id, nullptr);
        return;
    }

    if (input_.find(id) == input_.end()) {
      input_.emplace(id, std::make_pair(quic::BufQueue(), false));
    }

    quic::Buf data = std::move(res.value().first);
    bool eof = res.value().second;
    auto dataLen = (data ? data->computeChainDataLength() : 0);
    LOG(INFO) << "Got len=" << dataLen << " eof=" << uint32_t(eof)
              << " total=" << input_[id].first.chainLength() + dataLen
              << " data="
              << ((data) ? data->clone()->moveToFbString().toStdString()
                         : std::string());
    input_[id].first.append(std::move(data));
    input_[id].second = eof;
    if (eof) {
      echo(id, input_[id]);
      LOG(INFO) << "uninstalling read callback";
      sock_->setReadCallback(id, nullptr);
    }
}

void server_handle::readError(quic::StreamId id, quic::QuicError error) noexcept {
    LOG(INFO)<<"readError stream:"<<id<<" error:"<<error<<std::endl;
}

void server_handle::onConnectionSetupError(quic::QuicError code) noexcept {
    LOG(ERROR)<<"onConnectionSetupError:"<<code;
}

void server_handle::onNewBidirectionalStream(quic::StreamId id) noexcept {
    LOG(INFO)<<"new bidrection stream:"<<id<<std::endl;
    sock_->setReadCallback(id, this);
}

void server_handle::onNewUnidirectionalStream(quic::StreamId id) noexcept {
    LOG(INFO)<<"new Unidrection stream:"<<id<<std::endl;
}

void server_handle::onStopSending(quic::StreamId id, quic::ApplicationErrorCode error) noexcept {
    LOG(INFO)<<"onStopSending:"<<id<<std::endl;
}

void server_handle::onConnectionEnd() noexcept {
    LOG(INFO)<<"onConnectionEnd"<<std::endl;
}

void server_handle::onConnectionError(quic::QuicError code) noexcept {
    LOG(INFO)<<"onConnectionError:"<<code<<std::endl;
}

void server_handle::set_quicsock(std::shared_ptr<quic::QuicSocket> sock) {
    sock_ = sock;
}

void server_handle::echo(quic::StreamId id, StreamData& data) {
    if (!data.second) {
      // only echo when eof is present
      return;
    }
    auto echoed_data = folly::IOBuf::copyBuffer("echo ");
    echoed_data->prependChain(data.first.move());
    auto res = sock_->writeChain(id, std::move(echoed_data), true, nullptr);
    if (res.hasError()) {
      LOG(ERROR) << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
      input_.erase(id);
    }
}


transport_factory::transport_factory() {

}

transport_factory::~transport_factory() {
    echoHandlers_.withWLock([](auto& echoHandlers) {
      while (!echoHandlers.empty()) {
        auto& handler = echoHandlers.back();
        handler->get_eventbase()->runImmediatelyOrRunInEventBaseThreadAndWait(
            [&] {
              // The evb should be performing a sequential consistency atomic
              // operation already, so we can bank on that to make sure the
              // writes propagate to all threads.
              echoHandlers.pop_back();
            });
      }
    });
}

quic::QuicServerTransport::Ptr transport_factory::make(
      folly::EventBase* evb,
      std::unique_ptr<quic::FollyAsyncUDPSocketAlias> socket,
      const folly::SocketAddress& addr,
      quic::QuicVersion quicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept 
{
    auto echoHandler = std::make_unique<server_handle>(evb);
    auto transport = quic::QuicServerTransport::make(evb, std::move(socket), echoHandler.get(), echoHandler.get(), ctx);
    echoHandler->set_quicsock(transport);
    echoHandlers_.withWLock([&](auto& echoHandlers) {
      echoHandlers.push_back(std::move(echoHandler));
    });
    return transport;
}


server::server(std::string host, uint16_t port, std::string cert, std::string key):host_(host), port_(port),
    cert_(cert),
    key_(key),
    quic_server_(quic::QuicServer::createQuicServer()) {
    quic_server_->setQuicServerTransportFactory(std::make_unique<transport_factory>());

    auto serverCtx = create_server_ctx();
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    quic_server_->setFizzContext(serverCtx);
}

server::~server() {
    quic_server_->shutdown();
}

std::shared_ptr<fizz::server::FizzServerContext> server::create_server_ctx() {
    std::string cert_data;
    folly::readFile(cert_.c_str(), cert_data);

    std::string key_data;
    folly::readFile(key_.c_str(), key_data);

    auto cert = fizz::CertUtils::makeSelfCert(cert_data, key_data, "feixuwu");
    auto cert_manager = std::make_shared<fizz::server::CertManager>();
    cert_manager->addCert(std::move(cert), true);
    
    auto server_ctx = std::make_shared<fizz::server::FizzServerContext>();
    server_ctx->setCertManager(cert_manager);

    fizz::server::ClockSkewTolerance tolerance;
    tolerance.before = std::chrono::minutes(-5);
    tolerance.after = std::chrono::minutes(5);

    std::shared_ptr<fizz::server::ReplayCache> replay_cache = std::make_shared<fizz::server::AllowAllReplayReplayCache>();

    server_ctx->setEarlyDataSettings(true, tolerance, std::move(replay_cache));

    return server_ctx;
}

void server::run() {
    folly::SocketAddress addr1(host_.c_str(), port_);
    addr1.setFromHostPort(host_, port_);
    quic_server_->start(addr1, 0);
    LOG(INFO) << "Echo server started at: " << addr1.describe();
    eventbase_.loopForever();
}