#include <iostream>
#include <fstream>

#include "requests_operations.h"
#include "../../RSAWrapper.h"

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


    memcpy((char*)this->request_header.id, config->client_id, 16);

    std::cout << "rsa key length " << this->config->private_rsa_key.length() << std::endl;
    /*std::cout << "rsa key " << this->config->private_rsa_key << std::endl;*/
    if (0 != this->config->private_rsa_key.length())
    {
        /*std::string real_private_key = Base64Wrapper::decode(this->config->private_rsa_key);
        this->rsa_private_wrapper = std::make_shared<RSAPrivateWrapper>(real_private_key);*/
        this->rsa_private_wrapper = std::make_shared<RSAPrivateWrapper>(this->config->private_rsa_key);
    }
    else {
        this->rsa_private_wrapper = std::make_shared<RSAPrivateWrapper>();

    }
    /*this->rsa_public_wrapper = std::shared_ptr<RSAP
        std::make_shared<RSAPublicWrapper>(
        this->rsa_private_wrapper.get()->getPublicKey());*/


}

int GeneralRequest::send_request_and_handle_response()
{
    //boost::asio::write(*this->s, boost::asio::buffer(&this->request_header, sizeof(this->request_header)));
    //boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, this->request_header.payload_size));
    std::cout << "request code is " << ((struct request_header*)(this->request_payload))->request_code << std::endl;
    //boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, this->request_header.payload_size + sizeof(this->request_header)));
    boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, ((struct request_header*)(this->request_payload))->request_code + sizeof(this->request_header)));
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


    //this->request_payload_size =
}

RegistrationRequest::RegistrationRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config)
    : BasicRequest(s, config)
{
    this->basic_request_header.header.request_code = 1100;
    this->request_payload = (uint8_t *)&this->basic_request_header;

}

int RegistrationRequest::handle_response_data()
{
    int result = 0;

    if (2101 == this->response_header.response_code) {
        std::cout << "registration failed" << std::endl;
        return -1;
    }
    else if (2100 == this->response_header.response_code && 0 != this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        boost::asio::read(*this->s, boost::asio::buffer(&config->client_id, this->response_header.payload_size));
        config->save_user_name_and_id();
        std::string priv_key = this->rsa_private_wrapper.get()->getPrivateKey();
        this->config->save_priv_key(priv_key);

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
    this->basic_request_header.header.request_code = 1102;
    this->request_payload = (uint8_t*)&this->basic_request_header;


}
int RERegistrationRequest::handle_response_data()
{
    int result = 0;
    uint32_t dummy_id[16];

    if (2101 == this->response_header.response_code) {
        std::cout << "reregistration failed" << std::endl;
        return -1;
    }
    else if (2100 == this->response_header.response_code && 0 != this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        boost::asio::read(*this->s, boost::asio::buffer(&config->client_id, this->response_header.payload_size));
        config->save_user_name_and_id();
        std::string priv_key = this->rsa_private_wrapper.get()->getPrivateKey();
        this->config->save_priv_key(priv_key);
        PublicKeyRequest public_key_request(this->s, this->config);
        std::cout << "in here" << std::endl;
        result = public_key_request.send_request_and_handle_response();
        this->aes_wrapper = public_key_request.aes_wrapper;
        return result;
    }
    else if (2105 == this->response_header.response_code && 0 != this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        PublicKeyRequest public_key_request(this->s, this->config);
        public_key_request.response_header = this->response_header;
        result =  public_key_request.handle_response_data();
        this->aes_wrapper = public_key_request.aes_wrapper;

        return result;
    }
    else if (2106 == this->response_header.response_code && 16 == this->response_header.payload_size) {
        boost::asio::read(*this->s, boost::asio::buffer(dummy_id, this->response_header.payload_size));
        return -1;
    }

    return -1;
}

PublicKeyRequest::PublicKeyRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config)
    : GeneralRequest(s, config)
{
    this->request_header.request_code = 1101;
    this->request_header.payload_size = sizeof(this->request) - sizeof(this->request.header);
    this->request.header = this->request_header;

    strncpy((char*)this->request.client_name, config->client_name, CLIENT_NAME_SIZE);
    std::string pub_key = this->rsa_private_wrapper.get()->getPublicKey();
    //std::string base64key = Base64Wrapper::encode(pub_key);
    //memcpy(this->request.pub_key_base64, base64key.c_str(), RSAPublicWrapper::KEYSIZE);
    memcpy(this->request.pub_key, pub_key.c_str(), RSAPublicWrapper::KEYSIZE);

    this->request_payload = (uint8_t*)&this->request;
}

int PublicKeyRequest::handle_response_data()
{
    uint8_t dummy_id[16];
    std::vector<uint8_t> enc_aes_key(this->response_header.payload_size - 16);
    //std::string enc_aes_key();
    if ((2102 == this->response_header.response_code || 2105 == this->response_header.response_code)
                && 0 != this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        boost::asio::read(*this->s, boost::asio::buffer(dummy_id, 16));
        //boost::asio::read(*this->s, boost::asio::buffer(enc_aes_key, this->response_header.payload_size - 16));
        boost::asio::read(*this->s, boost::asio::buffer(enc_aes_key));
        //config->save_user_name_and_id();
        std::string str_key(enc_aes_key.begin(), enc_aes_key.end());
        std::string decrypted = this->rsa_private_wrapper.get()->decrypt(str_key);
        this->aes_wrapper = std::make_shared<AESWrapper>(
                reinterpret_cast<const unsigned char*>(decrypted.c_str()),
                decrypted.size());

        hexify(this->aes_wrapper.get()->getKey(), 16);
        return 0;
    }

    return -1;
}

SendFileRequest::SendFileRequest(std::shared_ptr<tcp::socket> const& s, std::shared_ptr<Config> const& config, std::shared_ptr<AESWrapper> const& aes)
    : GeneralRequest(s, config)
{
    this->request_header.request_code = 1103;
    this->request_header.payload_size = sizeof(this->request) - sizeof(this->request.header);
    this->aes_wrapper = aes;

    //char * buf_to_send = NULL;

    std::ifstream file_ptr(config->file_name, std::ios::in | std::ios::binary | std::ios::ate);
    if (file_ptr.is_open())
    {
        //size = file_ptr.tellg();

        size_t size = file_ptr.tellg();
        std::string buffer(size, ' ');
        file_ptr.seekg(0);
        //file_ptr.read(&buffer[0], size);
        file_ptr.read(buffer.data(), size);
        file_ptr.close();
        std::cout << "size " << size << std::endl;
        //std::cout << "payload " << buffer.c_str() << std::endl;

        this->crc.process_bytes(buffer.data(), buffer.length());
        std::cout << "checksum is " << this->crc.checksum() << std::endl;
        //std::cout << "crc32 is " << crc32((uint8_t *)buffer.data(), buffer.length()) << std::endl;

        this->file_size = size;

        std::cout << "file was found" << std::endl;

        //std::string ciphertext = this->aes_wrapper.get()->encrypt(buffer.c_str(), buffer.length());
        this->ciphertext = this->aes_wrapper.get()->encrypt(buffer.c_str(), buffer.length());
        std::cout << "Cipher:" << std::endl;
        //hexify(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length());	// print binary data nicely
        this->request_header.payload_size += this->ciphertext.length();
        this->request.content_size = this->ciphertext.length();
        this->request.header = this->request_header;
    }
    else {
        std::cout << "file not found" << std::endl;
        exit(-1);
    }
    //else cout << "Unable to open file";


    /* TODO change the const */
    strncpy((char*)this->request.file_name, config->file_name, FILE_NAME_SIZE);

    //buf_to_send = new char[this->request_header.payload_size];
    //memcpy(buf_to_send, &this->request, sizeof(this->request));
    // memcpy(buf_to_send, this->request + sizeof(this->request), this->request_header.payload_size - sizeof(this->request));
    //memcpy((char *)(buf_to_send + sizeof(this->request)), ciphertext.c_str(), ciphertext.length());

    this->request_payload = (uint8_t*)&this->request;
    //this->request_payload = (uint8_t*)buf_to_send;
}

int SendFileRequest::send_request_and_handle_response()
{
    const int max_block_size = 1024;
    const int max_retries = 4;
    int i = max_block_size;
    int ret = 0;
    for (int retry_num = 0; retry_num < max_retries; retry_num++) {

        std::cout << "request code is " << ((struct request_header*)(this->request_payload))->request_code << std::endl;
        boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, sizeof(this->request)));
        if (this->request.content_size < max_block_size) {
            i = this->request.content_size;
        }
        int chunk_size = i;
        while (chunk_size > 0) {
            boost::asio::write(*this->s, boost::asio::buffer(&(this->ciphertext.c_str()[i - chunk_size]), chunk_size));
            if (this->request.content_size - i > max_block_size) {
                chunk_size = max_block_size;
            }
            else {
                chunk_size = this->request.content_size - i;
            }
            i += chunk_size;
        }

        boost::asio::read(*this->s, boost::asio::buffer(&this->response_header, sizeof(this->response_header)));

        std::cout << "response was: code " << this->response_header.response_code << \
            " version " << this->response_header.version << " size " << this->response_header.payload_size << std::endl;

        ret = this->handle_response_data();
        if (0 == ret) {
            CRCRequest valid_crc_request(s, config, 1104);
            valid_crc_request.send_request_and_handle_response();
            break;
        }
        else if (retry_num == max_retries - 1) {
            CRCRequest max_invalid_crc_request(s, config, 1106);
            max_invalid_crc_request.send_request_and_handle_response();
        }
        else {
            CRCRequest max_invalid_crc_request(s, config, 1105);
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
    // std::vector<uint8_t> enc_aes_key(this->response_header.payload_size - 16);

    //std::string enc_aes_key();
    // crc.checksum()
    if ((2103 == this->response_header.response_code)
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
    if ((2104 == this->response_header.response_code)
        && 16 != this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        boost::asio::read(*this->s, boost::asio::buffer(dummy_id, 16));
       
        return 0;
    }

    return -1;
}
