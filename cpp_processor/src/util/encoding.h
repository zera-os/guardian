#pragma once

#include <string>
#include <vector>
#include <cstdint>

// base58
std::string base58_encode(const std::vector<uint8_t>& data);
std::string base58_encode(const std::string& data_str);
std::vector<uint8_t> base58_decode(const std::string& encoded);
std::vector<uint8_t> base58_decode(const std::vector<uint8_t>& encoded_vec);
std::string base58_encode_public_key(const std::string& public_key);
std::string base58_encode_public_key(const std::vector<uint8_t>& public_key);
std::vector<uint8_t> base58_decode_public_key(const std::string& public_key);
std::vector<uint8_t> base58_decode_public_key(const std::vector<uint8_t>& public_key);

// base64
bool base64_decode(const std::string &input, std::vector<uint8_t> &output);
uint64_t read_le_u64(const std::vector<unsigned char> &v);

// hex
std::string to_hex(const std::vector<unsigned char> &data);
std::vector<uint8_t> hex_to_bytes(const std::string &data);