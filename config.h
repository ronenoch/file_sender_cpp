#ifndef __CONFIG_H
#define __CONFIG_H

class Config
{
// private:
public:

    char client_name[255];
    char client_id[16];
    uint8_t private_rsa_key[128]; // not sure about the length
    // uint8_t private_rsa_key_base64[128];
    uint16_t port;
    char ip[16];
    char file_name[255];


// public:
    Config();

private:
    void parse_transfer_info();
    void parse_user_info();
    // char * get_client_name();
    // char * get_client_id();
    // uint8_t * get_private_rsa_key();
    // uint16_t get_port();
    // char * get_ip();
    // char * get_file_name();


};

#endif /* __CONFIG_H */