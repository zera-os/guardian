#include "encoding.h"
#include <cctype>


bool base64_decode(const std::string &input, std::vector<uint8_t> &output) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    auto is_base64 = [](unsigned char c) {
        return (std::isalnum(c) || (c == '+') || (c == '/'));
    };

    int in_len = input.size();
    int i = 0;
    int in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];

    while (in_len-- && (input[in_] != '=') && is_base64(input[in_])) {
        char_array_4[i++] = input[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                output.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j <4; j++)
            char_array_4[j] = 0;

        for (int j = 0; j <4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int j = 0; j < i - 1; j++) output.push_back(char_array_3[j]);
    }

    return true;
}

uint64_t read_le_u64(const std::vector<unsigned char> &v)
{
    if (v.size() != 8)
        return 0;
    uint64_t x = 0;
    for (size_t i = 0; i < 8; ++i)
    {
        x |= static_cast<uint64_t>(v[i]) << (8 * i);
    }
    return x;
}