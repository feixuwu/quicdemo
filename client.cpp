#include "client.h"


client::client(std::string host, uint16_t port):host_(host), port_(port) {

}

std::unique_ptr<fizz::CertificateVerifier>
create_client_certificate_verifier() {
  return std::make_unique<client_certificate_verifier>();
}

void client::start() {
    folly::ScopedEventBaseThread network_thread("EchoClientThread");
    auto evb = network_thread.getEventBase();
    auto qEvb = std::make_shared<quic::FollyQuicEventBase>(evb);

    folly::SocketAddress addr(host_.c_str(), port_);
    evb->runInEventBaseThreadAndWait([&] {
      auto sock = std::make_unique<quic::FollyQuicAsyncUDPSocket>(qEvb);
      auto fizzClientContext =
          quic::FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(create_client_certificate_verifier())
              .build();
      quic_client_ = std::make_shared<quic::QuicClientTransport>(
          qEvb, std::move(sock), std::move(fizzClientContext));
      quic_client_->setHostname("echo.com");
      quic_client_->addNewPeerAddress(addr);
    
      LOG(INFO) << "EchoClient connecting to " << addr.describe();
      quic_client_->start(this, this);
    });

    start_done_.wait();
    

    std::string message;
    bool closed = false;
    auto client = quic_client_;

    auto send_message_in_stream = [&]() {
      if (message == "/close") {
        quic_client_->close(folly::none);
        closed = true;
        return;
      }

      // create new stream for each message
      auto streamId = client->createBidirectionalStream().value();
      client->setReadCallback(streamId, this);
      pending_output_[streamId].append(folly::IOBuf::copyBuffer(message));
      send_message(streamId, pending_output_[streamId]);
    };


    // loop until Ctrl+D
    while (!closed && std::getline(std::cin, message)) {
      if (message.empty()) {
        continue;
      }
      evb->runInEventBaseThreadAndWait([=] {
        send_message_in_stream();
      });
    }
    LOG(INFO) << "EchoClient stopping client";
}

void client::send_message(quic::StreamId id, quic::BufQueue& data) {
    auto message = data.move();
    auto res = quic_client_->writeChain(id, message->clone(), true);
    if (res.hasError()) {
      LOG(ERROR) << "EchoClient writeChain error=" << uint32_t(res.error());
    } else {
      auto str = message->moveToFbString().toStdString();
      LOG(INFO) << "EchoClient wrote \"" << str << "\""
                << ", len=" << str.size() << " on stream=" << id;
      // sent whole message
      pending_output_.erase(id);
    }
}

void client::onConnectionSetupError(quic::QuicError code) noexcept {

}

void client::onNewBidirectionalStream(quic::StreamId id) noexcept {

}

void client::onNewUnidirectionalStream(quic::StreamId id) noexcept {

}

void client::onStopSending(quic::StreamId id, quic::ApplicationErrorCode error) noexcept {
  LOG(INFO) << "Client onStopSending" << " on stream=" << id<<" err:"<<error;
}

void client::onConnectionEnd() noexcept {

}

void client::readAvailable(quic::StreamId id) noexcept {
    LOG(INFO) << "Client readAvailable" << " on stream=" << id;

    auto res = quic_client_->read(id, 0);
    if(res.hasError() ) {
        LOG(ERROR) << "read stream:"<<id<<" Got error=" << toString(res.error());
        quic_client_->setReadCallback(id, nullptr);
        return;
    }

    quic::Buf data = std::move(res.value().first);
    bool eof = res.value().second;

    LOG(INFO)<<"client read:"<<data->clone()->moveToFbString().toStdString();
}

void client::readError(quic::StreamId id, quic::QuicError error) noexcept {
    LOG(INFO) << "Client readError" << " on stream=" << id << "error:"<<error;
}

void client::onConnectionError(quic::QuicError code) noexcept {
    LOG(ERROR) << "EchoClient error: "
               << code;
    start_done_.post();
}

void client::onTransportReady() noexcept {
    start_done_.post();
}