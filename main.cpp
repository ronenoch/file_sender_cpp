#include <iostream>
#include <stdio.h>
#include <boost/asio.hpp>

#include "config.h"

#define VERSION (3)
#define CLIENT_NAME_SIZE (255)

using boost::asio::ip::tcp;

// if msvc -
// #pragma pack(push, 1)
// ...
// #pragma pack(pop)

struct __attribute__((packed)) request_header {
    uint8_t id[16];
    uint8_t version;
    uint16_t request_code;
    uint32_t payload_size;
    uint8_t payload[0];
};

struct __attribute__((packed)) response_header {
    uint8_t version;
    uint16_t response_code;
    uint32_t payload_size;
    uint8_t payload[0];
};

struct __attribute__((packed)) request_register {
    struct request_header header;
    uint8_t client_name[CLIENT_NAME_SIZE];
};


int main(int argc, char **argv)
{
    std::cout << "Hello World" << std::endl;

    char port[] = "1337";
    char address[] = "127.0.0.1";
    char client_name[] = "Ron Enoch";

    boost::asio::io_context io_context;
    tcp::socket s(io_context);
    tcp::resolver resolver(io_context);
    boost::asio::connect(s, resolver.resolve(address, port));


    Config config = Config();

    /* TODO - check if id was found and re register */
    // struct request_header register_header = {
    struct request_register registration_request = {
        .header = {
            .version = VERSION,
            .request_code = 1100,
            .payload_size = CLIENT_NAME_SIZE,
        },

    };
    struct response_header response_header_recv = {0};

    strncpy((char *)registration_request.client_name, client_name, CLIENT_NAME_SIZE);


    boost::asio::write(s, boost::asio::buffer(&registration_request, 280));
    char data_recv[400] = {0};
    boost::asio::read(s, boost::asio::buffer(&response_header_recv, sizeof(response_header)));

    std::cout << "response was: code " << response_header_recv.response_code << \
        " version " << response_header_recv.version << " size " << response_header_recv.payload_size << std::endl;

    if (0 != response_header_recv.payload_size) {
        /* TODO check if payload size is 16 */
        boost::asio::read(s, boost::asio::buffer(&config.client_id, response_header_recv.payload_size));

        config.save_user_name_and_id();
    }

}
