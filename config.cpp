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
	memset(this->client_name, 0, sizeof(this->client_name));
	memset(this->file_name, 0, sizeof(this->file_name));
	memset(this->ip, 0, sizeof(this->ip));
	//memset(this->private_rsa_key, 0, sizeof(this->private_rsa_key));
	Config::parse_transfer_info();
	Config::parse_user_info();
}

void Config::parse_transfer_info()
{
	/* TODO - goto cleanup instead of return */
	std::string text;
	int ret;

	std::ifstream transfer_file("transfer.info");

	std::getline(transfer_file, text);
	if (!transfer_file) {
		if (transfer_file.eof()) {
			std::cout << "eof" << std::endl;
		}
		else {
			std::cout << "read_error" << std::endl;
		}
		return;
	}
	else {
		std::string ip = text.substr(0, text.find(":"));
		std::string port_str = text.substr(text.find(":") + 1, text.length());

		if (0 == text.find(":")) {
			std::cout << "Error : not a valid format" << std::endl;
			// TODO throw exception ?
		}
		else {

			if (ip.length() >= 16) {
				std::cout << "ip string length is too big" << std::endl;
				exit(-1);
			}
			memcpy(this->ip, ip.c_str(), ip.length());
			this->ip[ip.length()] = 0;
		}

		int port = std::stoi(port_str);

		if (port <= static_cast<int>(UINT16_MAX) && port >= 0) {
			this->port = static_cast<uint16_t>(port);
		}
		else {
			std::cout << "Error : not a valid port" << std::endl;
			this->port = 1234;
		}

		std::cout << this->ip << std::endl;
		std::cout << " port " << this->port << std::endl;
	}
	std::getline(transfer_file, text);
	if (!transfer_file) {
		if (transfer_file.eof()) {
			std::cout << "eof" << std::endl;
		}
		else {
			std::cout << "read_error" << std::endl;
		}
		return;
	}
	else {
		/* parse the client name */
		if (text.length() >= 255) {
			throw std::invalid_argument("name is too long. must be less than 255");
		}

		strncpy(this->client_name, text.c_str(), text.length());
		this->client_name[text.length()] = 0;

		std::cout << "name " << this->client_name << std::endl;

	}

	std::getline(transfer_file, text);
	if (!transfer_file) {
		// std::cout << "read failed" << std::endl;
		if (transfer_file.eof()) {
			std::cout << "eof" << std::endl;
		}
		else {
			std::cout << "read_error" << std::endl;
		}
	}
	else {
		/* parse the file name */
		if (text.length() >= 255) {
			throw std::invalid_argument("file name is too long. must be less than 255");
		}

		strncpy(this->file_name, text.c_str(), text.length());
		this->file_name[text.length()] = 0;

		std::cout << "name " << this->file_name << std::endl;

	}

	transfer_file.close();
}

void Config::parse_user_info()
{
	std::string text;
	int ret;

	std::ifstream me_file("me.info");

	if (me_file.fail()) {
		std::ofstream me_file("me.info");
		/* client name should be safe at this point */
		me_file << this->client_name << std::endl;
		return;
	}
	std::getline(me_file, text);
	if (!me_file) {
		if (me_file.eof()) {
			std::cout << "eof" << std::endl;
		}
		else {
			std::cout << "read_error" << std::endl;
		}
		return;
	}
	else {
		/* parse the client name */
		if (text.length() >= 255) {
			throw std::invalid_argument("name is too long. must be less than 255");
		}

		strncpy(this->client_name, text.c_str(), text.length());
		this->client_name[text.length()] = 0;

		std::cout << "name " << this->client_name << std::endl;

	}
	std::getline(me_file, text);
	if (!me_file) {
		if (me_file.eof()) {
			std::cout << "eof" << std::endl;
		}
		else {
			std::cout << "read_error" << std::endl;
		}
		return;
	}
	else {
		/* parse id from hex text to binary */
		std::stringstream ss;
		std::string s = "";
		this->client_id.resize(16);
		int n;
		for (int i = 0; i < 16; i++) {
			s = text[i * 2];
			std::string s2 = "";
			s2 += text.c_str()[i * 2 + 1];
			s.append(s2);
			std::cout << s << std::endl;
			std::istringstream(s) >> std::hex >> n;
			this->client_id[i] = n;
			//std::istringstream(((uint16_t*)text.c_str())[i]) >> std::hex >> this->client_id[i];
		}
		std::cout << std::endl;

		std::cout << "id " << this->client_id << std::endl;

	}
	
	/* read all of the last lines because base64 add newlines. */
	std::getline(me_file, text);
	while (me_file) {
		if (this->private_rsa_key.length() >= 1000) {
			throw std::invalid_argument("rsa key is too long. must be less than 128");
		}
		this->private_rsa_key = this->private_rsa_key + text;
		std::getline(me_file, text);

	}
	if (me_file.eof()) {
		std::cout << "eof" << std::endl;
	}
	else {
		std::cout << "read_error" << std::endl;
	}
	std::cout << "rsa key base 64 " << this->private_rsa_key << std::endl;
	this->private_rsa_key = Base64Wrapper::decode(this->private_rsa_key);
	//std::cout << "rsa key " << this->private_rsa_key << std::endl;

	me_file.close();
}

void Config::save_user_name_and_id()
{
	std::ofstream me_file("me.info");
	static const char hex_digits[] = "0123456789ABCDEF";
	/* client name should be safe at this point */
	me_file << this->client_name << std::endl;

	/* TODO make this a static function */
	std::string output;
	output.reserve(sizeof(this->client_id.data()) * 2);
	for (unsigned char c : this->client_id)
	{
		output.push_back(hex_digits[c >> 4]);
		output.push_back(hex_digits[c & 0xf]);
	}


	me_file << output << std::endl;

	return;
}

void Config::save_priv_key(std::string &key)
{
	std::fstream me_file("me.info", std::ios_base::app);

	std::string base64key = Base64Wrapper::encode(key);
	this->private_rsa_key = key;
	me_file << base64key << std::endl;

	return;
}
