#pragma once

//#include <stdio.h>
#include <stdint.h>
#include <memory>
#include <boost/asio.hpp>
#include <boost/crc.hpp>

#include "../../config.h"
#include "../../AESWrapper.h"
#include "../../RSAWrapper.h"


#define CLIENT_NAME_SIZE (255)
#define FILE_NAME_SIZE (255)

#pragma pack(push, 1)
struct request_header {
    uint8_t id[16];
    uint8_t version;
    uint16_t request_code;
    uint32_t payload_size;
    //uint8_t payload[0];
};

struct response_header {
    uint8_t version;
    uint16_t response_code;
    uint32_t payload_size;
    //uint8_t payload[0];
};

struct response_2103 {
    uint8_t id[16];
    uint32_t content_size;
    uint8_t file_name[255];
    uint32_t checksum;
};

struct request_register {
    struct request_header header;
    uint8_t client_name[CLIENT_NAME_SIZE];
};

struct request_public_key {
    struct request_header header;
    uint8_t client_name[CLIENT_NAME_SIZE];
    uint8_t pub_key[RSAPublicWrapper::KEYSIZE];
};

struct request_crc {
    struct request_header header;
    uint8_t file_name[FILE_NAME_SIZE];
};

struct request_send_file {
    struct request_header header;
    uint32_t content_size;
    uint8_t file_name[CLIENT_NAME_SIZE];
};

#pragma pack(pop)


using boost::asio::ip::tcp;

class GeneralRequest {
public:
    struct request_header request_header;
    struct response_header response_header;
    int request_payload_size;
    uint8_t * request_payload;
    uint8_t * response_payload;
    /*std::unique_ptr<uint8_t*> request_payload;
    std::unique_ptr<uint8_t*> response_payload;*/
    //boost::asio::buffer request_payload;
    //boost::asio::buffer response_payload;
    std::shared_ptr<Config> config;
    /* add expected response payload size */
    std::shared_ptr<tcp::socket> s;
    //std::shared_ptr<RSAPublicWrapper> rsa_public_wrapper;
    std::shared_ptr<RSAPrivateWrapper> rsa_private_wrapper;
    std::shared_ptr<AESWrapper> aes_wrapper;

    GeneralRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config);
    virtual ~GeneralRequest() = default;

    virtual int send_request_and_handle_response();

protected:
    virtual int handle_response_data() = 0;

};

class BasicRequest : public GeneralRequest{
public:
    struct request_register basic_request_header;


    BasicRequest(std::shared_ptr<tcp::socket> const &s, std::shared_ptr<Config> const& config);
    virtual ~BasicRequest() = default;

};

class RegistrationRequest : public BasicRequest {
public:
    RegistrationRequest(std::shared_ptr<tcp::socket> const &s, std::shared_ptr<Config> const& config);
    virtual ~RegistrationRequest() = default;

protected:
    virtual int handle_response_data();

};

class RERegistrationRequest : public BasicRequest {
public:
    RERegistrationRequest(std::shared_ptr<tcp::socket> const &s, std::shared_ptr<Config> const& config);
    virtual ~RERegistrationRequest() = default;

protected:
    virtual int handle_response_data();

};

class PublicKeyRequest : public GeneralRequest {
public:
    struct request_public_key request;
    PublicKeyRequest(std::shared_ptr<tcp::socket> const &s, std::shared_ptr<Config> const& config);
    virtual ~PublicKeyRequest() = default;

    friend RERegistrationRequest;
protected:
    virtual int handle_response_data();

};

class CRCRequest : public GeneralRequest {
public:
    struct request_crc request;
    CRCRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config, uint32_t code);
    virtual ~CRCRequest() = default;

protected:
    virtual int handle_response_data();

};


class SendFileRequest : public GeneralRequest {
    int file_size;
    std::string ciphertext;
    boost::crc_32_type crc;

public:
    struct request_send_file request;
    SendFileRequest(
        std::shared_ptr<tcp::socket> const& s,
        std::shared_ptr<Config> const& config,
        std::shared_ptr<AESWrapper> const& aes);
    virtual ~SendFileRequest() = default;
    virtual int send_request_and_handle_response();

protected:
    virtual int handle_response_data();

};
