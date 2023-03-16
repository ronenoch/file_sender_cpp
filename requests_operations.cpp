#include <iostream>
#include <fstream>

#include "requests_operations.h"
#include "RSAWrapper.h"

static void hexify(const unsigned char* buffer, unsigned int length)
{
    std::ios::fmtflags f(std::cout.flags());
    std::cout << std::hex;
    for (size_t i = 0; i < length; i++)
        std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
    std::cout << std::endl;
    std::cout.flags(f);
}

GeneralRequest::GeneralRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config)
{
	this->s = s;
	this->config = config;
    this->request_header.version = 3;


    memcpy((char*)this->request_header.id, config->client_id.c_str(), 16);

    std::cout << "rsa key length " << this->config->private_rsa_key.length() << std::endl;
    /* if there is an existing rsa key, use it. otherwise, generate a new one. */
    if (0 != this->config->private_rsa_key.length())
    {
        this->rsa_private_wrapper = std::make_shared<RSAPrivateWrapper>(this->config->private_rsa_key);
    }
    else {
        this->rsa_private_wrapper = std::make_shared<RSAPrivateWrapper>();
    }
}

int GeneralRequest::send_request_and_handle_response()
{
    std::cout << "request code is " << ((struct request_header*)(this->request_payload))->request_code << std::endl;
    //boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, this->request_header.payload_size + sizeof(this->request_header)));
    boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, ((struct request_header*)(this->request_payload))->payload_size + sizeof(this->request_header)));
    if (1105 != this->request_header.request_code) {

        boost::asio::read(*this->s, boost::asio::buffer(&this->response_header, sizeof(this->response_header)));

        std::cout << "response was: code " << this->response_header.response_code << \
            " version " << this->response_header.version << " size " << this->response_header.payload_size << std::endl;
    }
    return this->handle_response_data();
}

BasicRequest::BasicRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config)
    : GeneralRequest(s, config)
{
    this->request_header.payload_size = CLIENT_NAME_SIZE;

    this->basic_request_header.header = this->request_header;
    memset(this->basic_request_header.client_name, 0, CLIENT_NAME_SIZE);
    //strncpy_s((char *)registration_request.client_name, sizeof(registration_request.client_name), config.client_name, CLIENT_NAME_SIZE);

    std::cout << "client name " << config->client_name << std::endl;
    strncpy((char*)this->basic_request_header.client_name, config->client_name, CLIENT_NAME_SIZE);

}

RegistrationRequest::RegistrationRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config)
    : BasicRequest(s, config)
{
    this->basic_request_header.header.request_code = REQ_REGISTRATION_CODE;
    this->request_payload = (uint8_t *)&this->basic_request_header;

}

int RegistrationRequest::handle_response_data()
{
    int result = 0;

    if (RES_REGISTRATION_FAIL_CODE == this->response_header.response_code) {
        std::cout << "registration failed" << std::endl;
        return -1;
    }
    else if (RES_REGISTRATION_SUCCESS_CODE == this->response_header.response_code && 0 != this->response_header.payload_size) {
        /* TODO check if payload size is 16 ? */
        config->client_id.resize(16);
        boost::asio::read(*this->s, boost::asio::buffer(config->client_id, this->response_header.payload_size));
        config->save_user_name_and_id();
        std::string priv_key = this->rsa_private_wrapper.get()->getPrivateKey();
        this->config->save_priv_key(priv_key);

        /* now the client should send the public key to the server. */
        PublicKeyRequest public_key_request(this->s, this->config);
        result = public_key_request.send_request_and_handle_response();
        this->aes_wrapper = public_key_request.aes_wrapper;
        return result;
    }
    return -1;
}

RERegistrationRequest::RERegistrationRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config)
    : BasicRequest(s, config)
{
    this->basic_request_header.header.request_code = REQ_RE_REGISTRATION_CODE;
    this->request_payload = (uint8_t *)&this->basic_request_header;
}

int RERegistrationRequest::handle_response_data()
{
    int result = 0;
    uint32_t dummy_id[16];

    if (RES_REGISTRATION_FAIL_CODE == this->response_header.response_code) {
        std::cout << "reregistration failed" << std::endl;
        return -1;
    }

    else if (RES_RE_REGISTRATION_SUCCESS_CODE == this->response_header.response_code && 0 != this->response_header.payload_size) {

        PublicKeyRequest public_key_request(this->s, this->config);
        public_key_request.response_header = this->response_header;
        result =  public_key_request.handle_response_data();
        this->aes_wrapper = public_key_request.aes_wrapper;

        return result;
    }
    /* re-registration failed. need to register again. */
    else if (RES_RE_REGISTRATION_REJECT_CODE == this->response_header.response_code &&
            16 == this->response_header.payload_size) {
        boost::asio::read(*this->s, boost::asio::buffer(dummy_id, this->response_header.payload_size));
        return -1;
    }

    return -1;
}

PublicKeyRequest::PublicKeyRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config)
    : GeneralRequest(s, config)
{
    this->request_header.request_code = REQ_SEND_PUB_KEY_CODE;
    this->request_header.payload_size = sizeof(this->request) - sizeof(this->request.header);
    this->request.header = this->request_header;

    strncpy((char*)this->request.client_name, config->client_name, CLIENT_NAME_SIZE);
    std::string pub_key = this->rsa_private_wrapper.get()->getPublicKey();

    memcpy(this->request.pub_key, pub_key.c_str(), RSAPublicWrapper::KEYSIZE);

    this->request_payload = (uint8_t*)&this->request;
}

int PublicKeyRequest::handle_response_data()
{
    if (this->response_header.payload_size <= 16) {
        std::cout << "2102 response's payload size is too small." << std::endl;
        return -1;
    }

    uint8_t dummy_id[16];
    std::vector<uint8_t> enc_aes_key(this->response_header.payload_size - 16);

    if ((RES_SEND_KEYS_CODE == this->response_header.response_code ||
            RES_RE_REGISTRATION_SUCCESS_CODE == this->response_header.response_code)
            && 0 != this->response_header.payload_size) {
        boost::asio::read(*this->s, boost::asio::buffer(dummy_id, 16));
        boost::asio::read(*this->s, boost::asio::buffer(enc_aes_key));


        std::string str_key(enc_aes_key.begin(), enc_aes_key.end());
        std::string decrypted = this->rsa_private_wrapper.get()->decrypt(str_key);
        this->aes_wrapper = std::make_shared<AESWrapper>(
                reinterpret_cast<const unsigned char*>(decrypted.c_str()),
                decrypted.size());

        //hexify(this->aes_wrapper.get()->getKey(), 16);
        return 0;
    }

    return -1;
}

SendFileRequest::SendFileRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config, std::shared_ptr<AESWrapper> const& aes)
    : GeneralRequest(s, config)
{
    this->request_header.request_code = REQ_SEND_FILE_CODE;
    this->request_header.payload_size = sizeof(this->request) - sizeof(this->request.header);
    this->aes_wrapper = aes;

    std::ifstream file_ptr(config->file_name, std::ios::in | std::ios::binary | std::ios::ate);
    if (file_ptr.is_open())
    {
        /* get file size */
        size_t size = file_ptr.tellg();
        std::string buffer(size, ' ');
        std::cout << "file's size " << size << std::endl;

        /* read file */
        file_ptr.seekg(0);
        file_ptr.read(buffer.data(), size);
        file_ptr.close();

        /* calculate crc */
        this->crc.process_bytes(buffer.data(), buffer.length());
        std::cout << "checksum is " << this->crc.checksum() << std::endl;


        this->ciphertext = this->aes_wrapper.get()->encrypt(buffer.c_str(), buffer.length());

        /* build the header's fields */
        this->request_header.payload_size += this->ciphertext.length();
        this->request.content_size = this->ciphertext.length();
        this->request.header = this->request_header;
    }
    else {
        std::cout << "file not found" << std::endl;
        exit(-1);
    }

    /* TODO change the const */
    strncpy((char*)this->request.file_name, config->file_name, FILE_NAME_SIZE);

    this->request_payload = (uint8_t*)&this->request;
}

int SendFileRequest::send_request_and_handle_response()
{
    const int max_block_size = 1024;
    const int max_retries = 4;
    int written_bytes_number = max_block_size;
    int ret = 0;
    int chunk_size = 0;

    for (int retry_num = 0; retry_num < max_retries; retry_num++) {
        written_bytes_number = max_block_size;
        chunk_size = 0;

        std::cout << "request code is " << ((struct request_header*)(this->request_payload))->request_code << std::endl;
        boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, sizeof(this->request)));
        if (this->request.content_size < max_block_size) {
            written_bytes_number = this->request.content_size;
        }
        chunk_size = written_bytes_number;
        while (chunk_size > 0) {
            boost::asio::write(*this->s, boost::asio::buffer(&(this->ciphertext.c_str()[written_bytes_number - chunk_size]), chunk_size));
            if (this->request.content_size - written_bytes_number > max_block_size) {
                chunk_size = max_block_size;
            }
            else {
                chunk_size = this->request.content_size - written_bytes_number;
            }
            written_bytes_number += chunk_size;
        }

        boost::asio::read(*this->s, boost::asio::buffer(&this->response_header, sizeof(this->response_header)));

        std::cout << "response was: code " << this->response_header.response_code << \
            " version " << this->response_header.version << " size " << this->response_header.payload_size << std::endl;

        ret = this->handle_response_data();
        if (0 == ret) {
            CRCRequest valid_crc_request(s, config, REQ_CRC_VALID_CODE);
            valid_crc_request.send_request_and_handle_response();
            break;
        }
        else if (retry_num == max_retries - 1) {
            CRCRequest max_invalid_crc_request(s, config, REQ_CRC_INVALID_MAX_CODE);
            max_invalid_crc_request.send_request_and_handle_response();
        }
        else {
            CRCRequest max_invalid_crc_request(s, config, REQ_CRC_INVALID_CODE);
            max_invalid_crc_request.send_request_and_handle_response();
        }
    }
    if (0 == ret) {
        std::cout << "the file received successfuly." << std::endl;
    } else {
        std::cout << "the file failed to be delivered more than the maximum fail-times." << std::endl;
    }
    return ret;
}

int SendFileRequest::handle_response_data()
{
     struct response_2103 response_data = { 0 };

    if ((RES_GOT_FILE_CODE == this->response_header.response_code)
        && sizeof(response_2103) == this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        boost::asio::read(*this->s, boost::asio::buffer(&response_data, sizeof(response_data)));

        std::cout << "response crc " << response_data.checksum << std::endl;

        return !(response_data.checksum == this->crc.checksum());
    }

    return -1;
}

CRCRequest::CRCRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config, uint32_t code)
    : GeneralRequest(s, config)
{
    this->request_header.request_code = code;
    this->request_header.payload_size = sizeof(this->request) - sizeof(this->request.header);
    this->request.header = this->request_header;

    strncpy((char*)this->request.file_name, config->file_name, FILE_NAME_SIZE);
    this->request_payload = (uint8_t*)&this->request;

}

int CRCRequest::handle_response_data()
{
    uint8_t dummy_id[16];
    if ((RES_ACK_CODE == this->response_header.response_code)
        && 16 == this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        boost::asio::read(*this->s, boost::asio::buffer(dummy_id, 16));
        return 0;
    }

    return -1;
}
