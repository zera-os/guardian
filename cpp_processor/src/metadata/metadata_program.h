#pragma once

#include <string>

struct MetadataProgram{
    std::string name;
    std::string symbol;
    std::string uri;
    std::string update_authority;
    std::string decimals;
};

struct PythPrice{
    double price;           // Current price in USD
    uint64_t conf;          // Confidence interval
    int32_t expo;           // Price exponent (price = price_raw * 10^expo)
    int64_t publish_time;   // Unix timestamp of price update
    std::string status;     // "trading" or other status
};

namespace metadata{
    int metadata_program(const std::string &mint_base58, MetadataProgram &metadata_program);
    int get_pyth_price(const std::string &pyth_price_account, PythPrice &pyth_price);
    int get_usd_price_from_jupiter(const std::string &mint_id, double &usd_price);
}
