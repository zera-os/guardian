#include "encoding.h"

std::string to_hex(const std::vector<unsigned char> &data)
{
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char b : data)
    {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

std::vector<uint8_t> hex_to_bytes(const std::string &data)
{
    std::vector<uint8_t> bytes;
    for(int i = 0; i < data.size(); i += 2)
    {
        bytes.push_back(std::stoi(data.substr(i, 2), nullptr, 16));
    }
    return bytes;
}
