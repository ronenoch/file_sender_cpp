#include <iostream>
#include <stdio.h>
#include <boost/asio.hpp>

#include "config.h"
#include "FileSender\FileSender\requests_operations.h"

#define VERSION (3)
#define CLIENT_NAME_SIZE (255)

using boost::asio::ip::tcp;

int main(int argc, char **argv)
{
    //bool should_reconnect = false;

    std::shared_ptr<Config> config = std::make_shared<Config>();

    boost::asio::io_context io_context;
    std::shared_ptr<tcp::socket> s = std::make_shared<tcp::socket>(io_context);
    //tcp::socket s(io_context);
    tcp::resolver resolver(io_context);
    std::string port_str = std::to_string(config->port);
    boost::system::error_code ec;
    boost::asio::ip::address::from_string(config->ip, ec);
    if (ec) {
        std::cerr << "bad ip: " << ec.message() << std::endl;
        exit(-1);
    }
    boost::asio::connect(*s, resolver.resolve(config->ip, port_str));

    std::shared_ptr<AESWrapper> aes;
    int result = 0;

    if (config->private_rsa_key.empty() && !(0 == config->client_id.length())) {
        std::cout << "no private key in the existing me.info file! big error! " << std::endl;
        exit(-1);
    }
    /* by now, if the private rsa key is empty, the client did not connect before */
    bool should_reconnect = !config->private_rsa_key.empty();
    /*if (this->config.get()->private_rsa_key.empty()) {
        std::cout << "rsa key is empty" << std::endl;
        return -1;
    };*/

    if (should_reconnect) {
        /* re-register! */
        should_reconnect = true;
        RERegistrationRequest re_register_request(s, config);
        result = re_register_request.send_request_and_handle_response();
        aes = re_register_request.aes_wrapper;
    }
    if (!should_reconnect || 0 != result) {
        RegistrationRequest register_request(s, config);
        result = register_request.send_request_and_handle_response();
        aes = register_request.aes_wrapper;

    }

    if (0 != result) {
        std::cout << "error in registration. try to change the name and register again." << std::endl;
        exit(-1);
    }
    SendFileRequest send_request(s, config, aes);

    //send_request.aes_wrapper = aes;
    send_request.send_request_and_handle_response();

    return 0;
}
