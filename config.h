#ifndef __CONFIG_H
#define __CONFIG_H

#include "Base64Wrapper.h"

#define CLIENT_NAME_SIZE (255)
#define FILE_NAME_SIZE (255)

class Config
{
public: /* using the members like using a struct in c, so it is public! */

    char client_name[CLIENT_NAME_SIZE];
    //char client_id[16];
    std::string client_id;
    std::string private_rsa_key;
    uint16_t port;
    char ip[16];
    char file_name[FILE_NAME_SIZE];

    void save_user_name_and_id();
    void save_priv_key(std::string &key);

// public:
    Config();

private:
    void parse_transfer_info();
    void parse_user_info();

};

#endif /* __CONFIG_H */
