#include <iostream>
#include "server.h"
#include "client.h"


DEFINE_string(host, "::1", "Echo server hostname/IP");
DEFINE_int32(port, 6666, "Echo server port");
DEFINE_string(
    mode,
    "server",
    "Mode to run in: 'client', 'server', transport-server");
DEFINE_string(
    token,
    "",
    "Client new token string to attach to connection initiation");

DEFINE_string(
    cert,
    "/home/feixuwu/tool/cert.pem",
    "cert file");


DEFINE_string(
    key,
    "/home/feixuwu/tool/key.pem",
    "key file");



int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, false);
    folly::Init init(&argc, &argv);
    fizz::CryptoUtils::init();

    if(FLAGS_mode == "server") {
        server s(FLAGS_host, FLAGS_port, FLAGS_cert, FLAGS_key);
        s.run();
    } else if(FLAGS_mode == "client"){
        client c(FLAGS_host, FLAGS_port);
        c.start();
        
    } else {
        LOG(ERROR)<<"invalid model";
        return -1;
    }

    return 0;
}