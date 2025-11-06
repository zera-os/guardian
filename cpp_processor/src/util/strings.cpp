#include "string_utils.h"

#include <string>

static bool is_zero_width(unsigned char c1, unsigned char c2)
{
    // UTF-8 sequences for U+200B, U+200C, U+200D: E2 80 8B/C/D
    return c1 == 0xE2 && c2 == 0x80;
}

std::string sanitize_string(const std::string &input)
{
    std::string tmp;
    tmp.reserve(input.size());

    for (size_t i = 0; i < input.size(); )
    {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c == 0x00)
        {
            // drop NUL bytes
            ++i;
            continue;
        }
        if (c == 0xC2 && i + 1 < input.size() && static_cast<unsigned char>(input[i + 1]) == 0xA0)
        {
            // NBSP -> space
            tmp.push_back(' ');
            i += 2;
            continue;
        }
        if (c == 0xEF && i + 2 < input.size())
        {
            // U+FEFF BOM: EF BB BF -> drop
            unsigned char c2 = static_cast<unsigned char>(input[i + 1]);
            unsigned char c3 = static_cast<unsigned char>(input[i + 2]);
            if (c2 == 0xBB && c3 == 0xBF)
            {
                i += 3;
                continue;
            }
        }
        if (i + 2 < input.size() && is_zero_width(c, static_cast<unsigned char>(input[i + 1])))
        {
            unsigned char c3 = static_cast<unsigned char>(input[i + 2]);
            if (c3 == 0x8B || c3 == 0x8C || c3 == 0x8D)
            {
                // Drop zero-width characters
                i += 3;
                continue;
            }
        }

        if (c == '\t' || c == '\n' || c == '\r')
        {
            tmp.push_back(' ');
            ++i;
            continue;
        }
        tmp.push_back(static_cast<char>(c));
        ++i;
    }

    // collapse whitespace and trim
    std::string out;
    out.reserve(tmp.size());
    bool in_space = false;
    for (char ch : tmp)
    {
        if (ch == ' ') {
            if (!in_space) {
                out.push_back(' ');
                in_space = true;
            }
        } else {
            out.push_back(ch);
            in_space = false;
        }
    }
    // trim leading/trailing spaces
    size_t start = 0;
    while (start < out.size() && out[start] == ' ') start++;
    size_t end = out.size();
    while (end > start && out[end - 1] == ' ') end--;
    return out.substr(start, end - start);
}


