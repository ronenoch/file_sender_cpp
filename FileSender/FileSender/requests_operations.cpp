#include <iostream>

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
    //this->rsa_private_wrapper = NULL;
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
    //char data_recv[400] = { 0 };
    boost::asio::read(*this->s, boost::asio::buffer(&this->response_header, sizeof(this->response_header)));

    std::cout << "response was: code " << this->response_header.response_code << \
        " version " << this->response_header.version << " size " << this->response_header.payload_size << std::endl;
    return this->handle_response_data();
    //if (2101 == this->response_header.response_code) {
    //    std::cout << "registration failed" << std::endl;
    //}
    //else if (2100 == this->response_header.response_code && 0 != this->response_header.payload_size) {
    //    /* TODO check if payload size is 16 */
    //    boost::asio::read(s, boost::asio::buffer(&config->client_id, this->response_header.payload_size));

    //    config->save_user_name_and_id();
    //}
    //else if (2105 == this->response_header.response_code && 0 != this->response_header.payload_size) {
    //    /* get aes key from client */
    //}
    //return 0;

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
        return public_key_request.send_request_and_handle_response();
        //return 0;
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
        return public_key_request.send_request_and_handle_response();
    }
    else if (2105 == this->response_header.response_code && 0 != this->response_header.payload_size) {
        /* TODO check if payload size is 16 */
        /*boost::asio::read(s, boost::asio::buffer(&config->client_id, this->response_header.payload_size));
        config->save_user_name_and_id();*/
        
        /*char pubkeybuff[RSAPublicWrapper::KEYSIZE];
        this->rsa_private_wrapper->getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);
        boost::asio::write(*this->s, boost::asio::buffer(this->request_payload, this->request_header.payload_size + sizeof(this->request_header)));*/
        PublicKeyRequest public_key_request(this->s, this->config);
        public_key_request.response_header = this->response_header;
        return public_key_request.handle_response_data();

        return 0;
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
