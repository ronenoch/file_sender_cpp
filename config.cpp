#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>
#include <stdexcept>
#include <string.h>

#include "config.h"

Config::Config()
{
    Config::parse_transfer_info();
    Config::parse_user_info();
}

void Config::parse_transfer_info()
{
    /* TODO - goto cleanup instead of return */
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
        return;
    } else {
        std::string ip = text.substr(0, text.find(":"));
        std::string port_str = text.substr(text.find(":") + 1, text.length());

        if (0 == text.find(":")) {
            std::cout << "Error : not a valid format" << std::endl;
            // TODO throw exception
        } else {

            // TODO check ip length
            memcpy(this->ip, ip.c_str(), ip.length());
        }

        int port = std::stoi(port_str);

        if (port <= static_cast<int>(UINT16_MAX) && port >=0) {
            this->port = static_cast<uint16_t>(port);
        } else {
            std::cout << "Error : not a valid port" << std::endl;
            this->port = 1234;
        }

        std::cout << this->ip << std::endl;
        std::cout << " port " << this->port << std::endl;
        // std::cout << " port " << port << std::endl;
        // std::cout << tmp << std::endl;
    }
    std::getline (transfer_file, text);
    if (!transfer_file) {
        // std::cout << "read failed" << std::endl;
        if (transfer_file.eof()) {
            std::cout << "eof" << std::endl;
        } else {
            std::cout << "read_error" << std::endl;
        }
        return;
    } else {
        /* parse the client name */
        if (text.length() >= 255) {
            throw std::invalid_argument("name is too long. must be less than 255");
        }

        strncpy(this->client_name, text.c_str(), text.length());

        std::cout << "name " << this->client_name << std::endl;

    }

    std::getline (transfer_file, text);
    if (!transfer_file) {
        // std::cout << "read failed" << std::endl;
        if (transfer_file.eof()) {
            std::cout << "eof" << std::endl;
        } else {
            std::cout << "read_error" << std::endl;
        }
    } else {
        /* parse the file name */
        if (text.length() >= 255) {
            throw std::invalid_argument("file name is too long. must be less than 255");
        }

        strncpy(this->file_name, text.c_str(), text.length());

        std::cout << "name " << this->file_name << std::endl;

    }

    transfer_file.close();
}

void Config::parse_user_info()
{
    std::string text;
    int ret;

    std::ifstream me_file("me.info");
    // std::snprintf( buf.get(), size, format.c_str(), args ... );

    if (me_file.fail()) {
        std::ofstream me_file("me.info");
        /* client name should be safe at this point */
        // me_file.write(this->client_name, strnlen(this->client_name));
        me_file << this->client_name << std::endl;
        return;
    }
    std::getline (me_file, text);
    if (!me_file) {
        if (me_file.eof()) {
            std::cout << "eof" << std::endl;
        } else {
            std::cout << "read_error" << std::endl;
        }
        return;
    } else {
        /* parse the client name */
        if (text.length() >= 255) {
            throw std::invalid_argument("name is too long. must be less than 255");
        }

        strncpy(this->client_name, text.c_str(), text.length());

        std::cout << "name " << this->client_name << std::endl;

    }
    std::getline (me_file, text);
    if (!me_file) {
        if (me_file.eof()) {
            std::cout << "eof" << std::endl;
        } else {
            std::cout << "read_error" << std::endl;
        }
        return;
    } else {
        // /* parse the client name */
        // if (text.length() >= 255) {
        //     throw std::invalid_argument("name is too long. must be less than 255");
        // }
        std::stringstream ss;
        ss << std::hex << text;


        strncpy(this->client_id, ss.str().c_str(), ss.str().length());
        /* TOOD check that length is 16 */
        std::cout << "id " << this->client_id << std::endl;

    }

    std::getline (me_file, text);
    if (!me_file) {
        // std::cout << "read failed" << std::endl;
        if (me_file.eof()) {
            std::cout << "eof" << std::endl;
        } else {
            std::cout << "read_error" << std::endl;
        }
    } else {
        /* parse the file name */
        if (text.length() >= 255) {
            throw std::invalid_argument("file name is too long. must be less than 255");
        }

        strncpy(this->file_name, text.c_str(), text.length());

        std::cout << "name " << this->file_name << std::endl;

    }

    me_file.close();
}

void Config::save_user_name_and_id()
{
    std::ofstream me_file("me.info");
    static const char hex_digits[] = "0123456789ABCDEF";
    /* client name should be safe at this point */
    // me_file.write(this->client_name, strnlen(this->client_name));
    me_file << this->client_name << std::endl;

    /* TODO make this a static function */
    std::string output;
    output.reserve(sizeof(this->client_id) * 2);
    for (unsigned char c : this->client_id)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 0xf]);
    }


    me_file << output << std::endl;

    return;
}
