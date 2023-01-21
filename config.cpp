#include <iostream>
#include <fstream>
#include <stdio.h>

#include "config.h"

Config::Config()
{
    Config::parse_transfer_info();
    Config::parse_user_info();
}

void Config::parse_transfer_info()
{
    std::string text;
    int ret;

    std::ifstream transfer_file("transfer.info");
    // std::snprintf( buf.get(), size, format.c_str(), args ... );
    
    std::getline (transfer_file, text);
    if (!transfer_file) {
        if (transfer_file.eof()) {
            std::cout << "eof" << std::endl;
        } else {
            std::cout << "read_error" << std::endl;
        }
    } else {
        // this->
        // std::snprintf( this->, size, format.c_str(), args ... );
        std::cout << text.c_str() << std::endl;
        // char tmp[5];
        ret = sscanf_s(text.c_str(), "%15[^:]:%h", this->ip, &(this->port), 22);
        // ret = sscanf_s(text.c_str(), "%[^:]%*c%s", this->ip, tmp, 30);
        std::cout << this->ip << std::endl;
        std::cout << " port " << this->port << std::endl;
        // std::cout << tmp << std::endl;
    }


    transfer_file.close();
}

void Config::parse_user_info()
{
    // string text;
    // int ret;

    // ifstream transfer_file("transfer.info");
    // // std::snprintf( buf.get(), size, format.c_str(), args ... );
    
    // getline (transfer_file, text);
    // if (!transfer_file) {
    //     if (transfer_file.eof()) {
    //         std::cout << "eof" << std::endl;
    //     } else {
    //         std::cout << "read_error" << std::endl;
    //     }
    // }
    // // this->
    // // std::snprintf( this->, size, format.c_str(), args ... );
    // ret = sscanfs(text.get(), "%s:%d", this->ip, &this->port);
    // std::cout << this->ip << this->port << std::endl;


    // transfer_file.close();
}