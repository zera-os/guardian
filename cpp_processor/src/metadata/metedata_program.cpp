// g++ meta.cpp -lcurl -o meta
#include "metadata_program.h"

#include <curl/curl.h>
#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <cstdint>
#include <cstring>
#include <optional>
#include <cassert>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <map>
#include "encoding.h"
#include "string_utils.h"
#include "hashing.h"

using json = nlohmann::json;

namespace
{
    static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
    {
        std::string *out = reinterpret_cast<std::string *>(userdata);
        out->append(reinterpret_cast<char *>(ptr), size * nmemb);
        return size * nmemb;
    }

    // read little-endian u32
    uint32_t read_u32_le(const std::vector<uint8_t> &v, size_t &off)
    {
        if (off + 4 > v.size())
            throw std::runtime_error("truncated");
        uint32_t x = (uint32_t)v[off] | ((uint32_t)v[off + 1] << 8) | ((uint32_t)v[off + 2] << 16) | ((uint32_t)v[off + 3] << 24);
        off += 4;
        return x;
    }

    // read fixed 32 bytes
    std::array<uint8_t, 32> read_pubkey(const std::vector<uint8_t> &v, size_t &off)
    {
        if (off + 32 > v.size())
            throw std::runtime_error("truncated");
        std::array<uint8_t, 32> out{};
        std::memcpy(out.data(), v.data() + off, 32);
        off += 32;
        return out;
    }

    // read Borsh string
    std::string read_borsh_string(const std::vector<uint8_t> &v, size_t &off)
    {
        uint32_t len = read_u32_le(v, off);
        if (off + len > v.size())
            throw std::runtime_error("truncated");
        std::string s(reinterpret_cast<const char *>(v.data() + off), len);
        off += len;
        return s;
    }

    json rpc_post(const std::string &rpc_url, const json &req)
    {
        CURL *curl = curl_easy_init();
        if (!curl)
            throw std::runtime_error("curl init failed");
        std::string out;
        auto body = req.dump();

        curl_easy_setopt(curl, CURLOPT_URL, rpc_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);

        auto res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK)
            throw std::runtime_error("curl error");

        return json::parse(out);
    }

    // Derive Metaplex metadata PDA: SHA256("metadata" + program_id + mint + bump + program_id + "ProgramDerivedAddress")
    std::pair<std::string, uint8_t> find_metadata_pda(const std::string &mint_base58, const std::string &metadata_program_id_base58)
    {
        std::vector<uint8_t> mint = base58_decode(mint_base58);
        std::vector<uint8_t> metadata_program_id = base58_decode(metadata_program_id_base58);
        
        if (mint.size() != 32 || metadata_program_id.size() != 32)
        {
            throw std::runtime_error("Invalid mint or program ID size");
        }

        const char* metadata_seed = "metadata";
        const char* pda_marker = "ProgramDerivedAddress";
        
        // Try bumps from 255 down to 0 to find valid off-curve PDA
        for (int bump = 255; bump >= 0; --bump)
        {
            std::vector<uint8_t> buffer;
            buffer.insert(buffer.end(), metadata_seed, metadata_seed + strlen(metadata_seed));
            buffer.insert(buffer.end(), metadata_program_id.begin(), metadata_program_id.end());
            buffer.insert(buffer.end(), mint.begin(), mint.end());
            buffer.push_back(static_cast<uint8_t>(bump));
            buffer.insert(buffer.end(), metadata_program_id.begin(), metadata_program_id.end());
            buffer.insert(buffer.end(), pda_marker, pda_marker + strlen(pda_marker));
            
            std::vector<uint8_t> hash = Hashing::sha2_256_hash(buffer);
            
            if (hash.size() == 32)
            {
                return {base58_encode(hash), static_cast<uint8_t>(bump)};
            }
        }
        
        throw std::runtime_error("Could not derive metadata PDA");
    }
}

int metadata::metadata_program(const std::string &mint_base58, MetadataProgram &metadata_program)
{
    // 1) Inputs
    std::string rpc = std::getenv("RPC_URL");                 // or your node/Helius
    
    std::string TOKEN_METADATA_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";

    // 2) Try Helius DAS API first (most efficient for Helius)
    std::string data_b64;
    
    
    json das_req = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "getAsset"},
        {"params", {mint_base58}}
    };
    
    json das_resp = rpc_post(rpc, das_req);
    
    // Check if DAS API returned valid data
    if (!das_resp.contains("error") && das_resp.contains("result") && das_resp["result"].contains("content"))
    {
        
        // Extract metadata from DAS response
        auto content = das_resp["result"]["content"];
        auto metadata_obj = content["metadata"];
        
        metadata_program.name = sanitize_string(metadata_obj.value("name", ""));
        metadata_program.symbol = sanitize_string(metadata_obj.value("symbol", ""));
        
        if (content.contains("json_uri"))
        {
            metadata_program.uri = sanitize_string(content["json_uri"].get<std::string>());
        }
        
        // Get update authority if available
        if (das_resp["result"].contains("authorities"))
        {
            auto authorities = das_resp["result"]["authorities"];
            if (authorities.is_array() && !authorities.empty())
            {
                metadata_program.update_authority = authorities[0].value("address", "");
            }
        }
        
        // Get decimals from mint info
        json mint_req = {
            {"jsonrpc", "2.0"},
            {"id", 2},
            {"method", "getAccountInfo"},
            {"params", {mint_base58, {{"encoding", "jsonParsed"}}}}
        };
        json mint_resp = rpc_post(rpc, mint_req);
        int decimals = mint_resp["result"]["value"]["data"]["parsed"]["info"]["decimals"].get<int>();
        metadata_program.decimals = std::string("1") + std::string(decimals, '0');
        
        
        return 0;
    }
    
    // Fallback: DAS API didn't work, try PDA derivation
    std::cout << "DAS API didn't work, trying PDA derivation...\n";
    
    try
    {
        // Try most common bump values (usually 254-255)
        std::vector<uint8_t> mint = base58_decode(mint_base58);
        std::vector<uint8_t> metadata_program_id = base58_decode(TOKEN_METADATA_PROGRAM_ID);
        const char* metadata_seed = "metadata";
        const char* pda_marker = "ProgramDerivedAddress";
        
        // Try most common bumps first
        std::vector<int> bumps_to_try = {255, 254, 253, 252, 251, 250};
        
        for (int bump : bumps_to_try)
        {
            std::vector<uint8_t> buffer;
            buffer.insert(buffer.end(), metadata_seed, metadata_seed + strlen(metadata_seed));
            buffer.insert(buffer.end(), metadata_program_id.begin(), metadata_program_id.end());
            buffer.insert(buffer.end(), mint.begin(), mint.end());
            buffer.push_back(static_cast<uint8_t>(bump));
            buffer.insert(buffer.end(), metadata_program_id.begin(), metadata_program_id.end());
            buffer.insert(buffer.end(), pda_marker, pda_marker + strlen(pda_marker));
            
            std::vector<uint8_t> hash = Hashing::sha2_256_hash(buffer);
            std::string metadata_pda = base58_encode(hash);
            
            std::cout << "Trying bump " << bump << "...\n";
            
            json pda_req = {
                {"jsonrpc", "2.0"},
                {"id", 3},
                {"method", "getAccountInfo"},
                {"params", {metadata_pda, {{"encoding", "base64"}}}}
            };
            
            json pda_resp = rpc_post(rpc, pda_req);
            
            if (!pda_resp["result"].is_null() && !pda_resp["result"]["value"].is_null())
            {
                std::cout << "✓ Found metadata at bump " << bump << "!\n";
                data_b64 = pda_resp["result"]["value"]["data"][0].get<std::string>();
                // Continue with normal parsing below
                goto parse_metadata;
            }
        }
        
        std::cerr << "No metadata account found for mint: " << mint_base58 << "\n";
        std::cerr << "Tried DAS API and PDA derivation.\n";
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to query metadata: " << e.what() << "\n";
        return 1;
    }

parse_metadata:
    std::vector<uint8_t> raw;
    base64_decode(data_b64, raw);

    // 4) parse Borsh (just the early fields)
    size_t off = 0;
    uint8_t key = raw.at(off++); // Metadata key enum
    auto update_auth = read_pubkey(raw, off);
    auto mint_pk = read_pubkey(raw, off);
    std::string name = sanitize_string(read_borsh_string(raw, off));
    std::string symbol = sanitize_string(read_borsh_string(raw, off));
    std::string uri = sanitize_string(read_borsh_string(raw, off));

    // 5) decimals via getAccountInfo on the Mint (spl-token program)
    json mint_req = {
        {"jsonrpc", "2.0"},
        {"id", 2},
        {"method", "getAccountInfo"},
        {"params", {mint_base58, {{"encoding", "jsonParsed"}}}}};
    json mint_resp = rpc_post(rpc, mint_req);
    int decimals = mint_resp["result"]["value"]["data"]["parsed"]["info"]["decimals"].get<int>();


    std::vector<uint8_t> update_auth_vec(update_auth.begin(), update_auth.end());
    std::cout << "name:   " << name << "\n";
    std::cout << "symbol: " << symbol << "\n";
    std::cout << "uri:    " << uri << "\n";
    std::cout << "updateAuthority: " << base58_encode(update_auth_vec) + "[pubkey bytes]" << "\n";
    std::cout << "mint:   " << mint_base58 << "\n";
    std::cout << "decimals: " << decimals << "\n";

    metadata_program.name = name;
    metadata_program.symbol = symbol;
    metadata_program.uri = uri;
    metadata_program.update_authority = base58_encode(update_auth_vec);

    
    // Store the scale factor 10^decimals as a string (e.g., 6 -> "1000000")
    metadata_program.decimals = std::string("1") + std::string(decimals, '0');

    std::cout << "name size:   " << metadata_program.name.size() << "\n";
    std::cout << "symbol size: " << metadata_program.symbol.size() << "\n";
    std::cout << "uri size:    " << metadata_program.uri.size() << "\n";
    std::cout << "update_authority size: " << metadata_program.update_authority.size() << "\n";
    std::cout << "decimals size: " << metadata_program.decimals.size() << "\n";

    return 0;
}

int metadata::get_usd_price_from_jupiter(const std::string &mint_id, double &usd_price)
{

    // TODO:
    // Pricing will have to be updated in future to grab pricing from a community implemented rate oracle, 
    // or internal price verification system between guardians
    // For now, we will use a hardcoded price for some common tokens price does not need to be exact, it just needs to be a reasonable price
    if (mint_id == SOL_MINT_ID) // SOL
    {
        usd_price = 100.0;
        return 0;
    }
    else if (mint_id == "So11111111111111111111111111111111111111112") // SOL
    {
        usd_price = 100.0;
        return 0;
    }
    else if (mint_id == "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v") // USDC
    {
        usd_price = 1.0;
        return 0;
    }
    else if (mint_id == "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB") // USDT
    {
        usd_price = 1.0;
        return 0;
    }
    else{
        usd_price = 0.0;
        return 1;
    }
    // Jupiter Lite API v2 - search by mint address
    std::string jupiter_url = "https://lite-api.jup.ag/tokens/v2/search?query=" + mint_id;
    
    std::cout << "Querying Jupiter API for mint: " << mint_id << "\n";
    
    // Make HTTP GET request
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        std::cerr << "Failed to initialize CURL\n";
        usd_price = 0.0;
        return 1;
    }
    
    std::string response;
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Accept: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, jupiter_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK)
    {
        std::cerr << "CURL request failed: " << curl_easy_strerror(res) << "\n";
        usd_price = 0.0;
        return 1;
    }
    
    // Parse JSON response
    try
    {
        json j = json::parse(response);
        
        
        if (!j.is_array() || j.empty())
        {
            std::cerr << "No tokens found for mint: " << mint_id << "\n";
            usd_price = 0.0;
            return 1;
        }
        
        // Get the first result (should be exact match)
        auto token_data = j[0];
        
        // Verify it's the correct mint
        if (!token_data.contains("id") || token_data["id"].get<std::string>() != mint_id)
        {
            std::cerr << "Returned token ID doesn't match requested mint\n";
            usd_price = 0.0;
            return 1;
        }
        
        // Extract price
        if (!token_data.contains("usdPrice") || token_data["usdPrice"].is_null())
        {
            std::cerr << "usdPrice field not found or null\n";
            usd_price = 0.0;
            return 1;
        }
        
        usd_price = token_data["usdPrice"].get<double>();
        
        std::string symbol = token_data.value("symbol", "UNKNOWN");
        std::string name = token_data.value("name", "UNKNOWN");
        
        std::cout << "Jupiter Price (" << symbol << " - " << name << "): $" 
                  << std::fixed << std::setprecision(8) << usd_price << "\n";
        
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to parse Jupiter response: " << e.what() << "\n";
        std::cerr << "Response: " << response.substr(0, 500) << "...\n";
        usd_price = 0.0;
        return 1;
    }
}