#pragma once

//#include <stdio.h>
#include <stdint.h>
#include <memory>
#include <boost/asio.hpp>
#include <boost/crc.hpp>

#include "config.h"
#include "AESWrapper.h"
#include "RSAWrapper.h"


enum requests_codes {
    REQ_REGISTRATION_CODE = 1100,
    REQ_SEND_PUB_KEY_CODE = 1101,
    REQ_RE_REGISTRATION_CODE = 1102,
    REQ_SEND_FILE_CODE = 1103,
    REQ_CRC_VALID_CODE = 1104,
    REQ_CRC_INVALID_CODE = 1105,
    REQ_CRC_INVALID_MAX_CODE = 1106,
};

enum reponses_codes {
    RES_REGISTRATION_SUCCESS_CODE = 2100,
    RES_REGISTRATION_FAIL_CODE = 2101,
    RES_SEND_KEYS_CODE = 2102,
    RES_GOT_FILE_CODE = 2103,
    RES_ACK_CODE = 2104,
    RES_RE_REGISTRATION_SUCCESS_CODE = 2105,
    RES_RE_REGISTRATION_REJECT_CODE = 2106,
    RES_OTHER_ERROR_CODE = 2107,
};

#pragma pack(push, 1)
struct request_header {
    uint8_t id[16];
    uint8_t version;
    uint16_t request_code;
    uint32_t payload_size;
};

struct response_header {
    uint8_t version;
    uint16_t response_code;
    uint32_t payload_size;
};

struct response_2103 {
    uint8_t id[16];
    uint32_t content_size;
    uint8_t file_name[FILE_NAME_SIZE];
    uint32_t checksum;
};

struct basic_request_with_name {
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

/* NOT USING COPYCTORS AT THE PROJECT, also I'm good with the default. I want to make the code the simplest */

class GeneralRequest {
    /**
     * this class represent the flow of a request.
     * every request must implement the handle_response_data to handle the specific response.
     * the general request expects that the derrived classes will put the payload to send in request_payload.
    */
public:
    std::shared_ptr<RSAPrivateWrapper> rsa_private_wrapper;
    std::shared_ptr<AESWrapper> aes_wrapper;

    GeneralRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config);
    virtual ~GeneralRequest() = default;

    virtual int send_request_and_handle_response();

protected:
    struct request_header request_header;
    struct response_header response_header;

    /* pointer to the buffer to send */
    uint8_t * request_payload;

    std::shared_ptr<Config> config;
    std::shared_ptr<tcp::socket> s;

    virtual int handle_response_data() = 0;

};

class BasicRequest : public GeneralRequest {
    /* request that contains only client_name */
public:
    struct basic_request_with_name basic_request_header;


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
    /* public key exchange request */
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
    /* sends the file in chuncks */

    std::string ciphertext;
    boost::crc_32_type crc;

public:
    struct request_send_file request;
    SendFileRequest(
        std::shared_ptr<tcp::socket> const& s,
        std::shared_ptr<Config> const& config,
        std::shared_ptr<AESWrapper> const& aes);
    virtual ~SendFileRequest() = default;
    /* overrriding this function to send chunks instead of one buffer. */
    virtual int send_request_and_handle_response();

protected:
    virtual int handle_response_data();

};
