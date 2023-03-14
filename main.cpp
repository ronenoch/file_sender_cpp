#include <iostream>
#include <stdio.h>
#include <boost/asio.hpp>

#include "config.h"
#include "FileSender\FileSender\requests_operations.h"

#define VERSION (3)
#define CLIENT_NAME_SIZE (255)

//#define _CRT_SECURE_NO_WARNINGS

using boost::asio::ip::tcp;

// if msvc -
// #pragma pack(push, 1)
//
//
//struct request_header {
//    uint8_t id[16];
//    uint8_t version;
//    uint16_t request_code;
//    uint32_t payload_size;
//    //uint8_t payload[0];
//};
//
//struct response_header {
//    uint8_t version;
//    uint16_t response_code;
//    uint32_t payload_size;
//    //uint8_t payload[0];
//};
//
//struct request_register {
//    struct request_header header;
//    uint8_t client_name[CLIENT_NAME_SIZE];
//};
//
//#pragma pack(pop)

int main(int argc, char **argv)
{
    std::cout << "Hello World" << std::endl;

    //char port[] = "1337";
    char address[] = "127.0.0.1";
    char client_name[] = "Ron Enoch";
    bool should_reconnect = false;

    std::shared_ptr<Config> config = std::make_shared<Config>();

    boost::asio::io_context io_context;
    std::shared_ptr<tcp::socket> s = std::make_shared<tcp::socket>(io_context);
    //tcp::socket s(io_context);
    tcp::resolver resolver(io_context);
    std::string port_str = std::to_string(config->port);
    boost::asio::connect(*s, resolver.resolve(config->ip, port_str));



    /* TODO - check if id was found and re register */
    // struct request_header register_header = {
    // struct request_register registration_request = {
    //     .header = {
    //         .version = VERSION,
    //         .request_code = 1100,
    //         .payload_size = CLIENT_NAME_SIZE,
    //     },
    //     .client_name = { 0 },

    // };
    // struct response_header response_header_recv = {0};

    //memset(registration_request.client_name, 0, CLIENT_NAME_SIZE);
    ////strncpy_s((char *)registration_request.client_name, sizeof(registration_request.client_name), config.client_name, CLIENT_NAME_SIZE);
    //strncpy((char *)registration_request.client_name, config->client_name, CLIENT_NAME_SIZE);

    //if (config->client_id[0] != 0) {
    std::shared_ptr<AESWrapper> aes;
    int result = 0;
    bool client_name_is_known = config->client_name[0] != 0;

    if (client_name_is_known) {
        /* re-register! */
        should_reconnect = true;
        //registration_request.header.request_code = 1102;
        RERegistrationRequest re_register_request(s, config);
        result = re_register_request.send_request_and_handle_response();
        aes = re_register_request.aes_wrapper;
    }
    if (!client_name_is_known || 0 != result) {
        RegistrationRequest register_request(s, config);
        register_request.send_request_and_handle_response();
        aes = register_request.aes_wrapper;

    }

    SendFileRequest send_request(s, config, aes);

    //send_request.aes_wrapper = aes;
    send_request.send_request_and_handle_response();



    return 0;



    //boost::asio::write(s, boost::asio::buffer(&registration_request, sizeof(registration_request)));
    //char data_recv[400] = {0};
    //boost::asio::read(s, boost::asio::buffer(&response_header_recv, sizeof(response_header)));

    //std::cout << "response was: code " << response_header_recv.response_code << \
    //    " version " << response_header_recv.version << " size " << response_header_recv.payload_size << std::endl;

    //if (2101 == response_header_recv.response_code) {
    //    std::cout << "registration failed" << std::endl;
    //} else if (2100 == response_header_recv.response_code && 0 != response_header_recv.payload_size) {
    //    /* TODO check if payload size is 16 */
    //    boost::asio::read(s, boost::asio::buffer(&config->client_id, response_header_recv.payload_size));

    //    config->save_user_name_and_id();
    //} else if (2105 == response_header_recv.response_code && 0 != response_header_recv.payload_size) {
    //    /* get aes key from client */
    //}

}
