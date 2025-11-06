#pragma once

#include <cstdint>
#include <sodium.h>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "../blake3/blake3.h"
#include <iostream>
#include "encoding.h"
#include "const.h"
#include <cstring>

enum class Blake3HashLength
{
    Bits_256 = 32,   // 256 bits = 32 bytes
    Bits_512 = 64,   // 512 bits = 64 bytes
    Bits_1024 = 128, // 1024 bits = 128 bytes
    Bits_2048 = 256, // 2048 bits = 256 bytes
    Bits_4096 = 512, // 4096 bits = 512 bytes
    Bits_9001 = 1126 // 9001 bits ≈ 1126 bytes
};

enum class SHAKEHashLength
{
    Bits_1024 = 128, // 1024 bits = 128 bytes
    Bits_2048 = 256, // 2048 bits = 256 bytes
    Bits_4096 = 512  // 4096 bits = 512 bytes
};

namespace Hashing
{
    static std::vector<uint8_t> blake3_hash(const std::vector<uint8_t> &input, Blake3HashLength length = Blake3HashLength::Bits_256)
    {
        size_t output_length_bytes = static_cast<size_t>(length);
        std::vector<uint8_t> hash(output_length_bytes);
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, input.data(), input.size());
        blake3_hasher_finalize(&hasher, hash.data(), hash.size());

        // Handle special case for 9001 bits
        if (length == Blake3HashLength::Bits_9001)
        {
            // Truncate the hash to 9001 bits (1125 bytes + 1 bit)
            hash.resize(1126);  // 1126 bytes = 9008 bits
            hash[1125] &= 0x80; // Truncate the last byte to keep only the most significant bit (7 bits cleared)
        }

        return hash;
    }

    static std::vector<uint8_t> shake_hash(const std::vector<uint8_t> &input, SHAKEHashLength length)
    {
        size_t output_length_bytes = static_cast<size_t>(length);
        std::vector<uint8_t> hash(output_length_bytes);

        // Select SHAKE-256 or SHAKE-128 based on required security
        const EVP_MD *md = EVP_shake256(); // Use EVP_shake128() for lower security
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

        if (mdctx == nullptr)
        {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }

        if (1 != EVP_DigestInit_ex(mdctx, md, nullptr))
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to initialize EVP_Digest");
        }

        if (1 != EVP_DigestUpdate(mdctx, input.data(), input.size()))
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to update EVP_Digest");
        }

        if (1 != EVP_DigestFinalXOF(mdctx, hash.data(), output_length_bytes))
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to finalize EVP_Digest");
        }

        EVP_MD_CTX_free(mdctx);
        return hash;
    }
    static std::vector<uint8_t> sha2_256_hash(const std::vector<uint8_t> &input)
    {
        // Buffer for the hash result
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        // Create a context for the hashing operation
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr)
        {
            std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
            return {};
        }

        // Initialize the context with the SHA-3-256 algorithm
        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
        {
            std::cerr << "Failed to initialize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Hash the data
        if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1)
        {
            std::cerr << "Failed to update digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Finalize the hash and retrieve the result
        if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
        {
            std::cerr << "Failed to finalize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Cleanup
        EVP_MD_CTX_free(mdctx);

        // Convert the hash to a vector<uint8_t> and return it
        return std::vector<uint8_t>(hash, hash + hash_len);
    }

    static std::vector<uint8_t> sha256_hash(const std::vector<uint8_t> &input)
    {
        // Buffer for the hash result
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        // Create a context for the hashing operation
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr)
        {
            std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
            return {};
        }

        // Initialize the context with the SHA-3-256 algorithm
        if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), nullptr) != 1)
        {
            std::cerr << "Failed to initialize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Hash the data
        if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1)
        {
            std::cerr << "Failed to update digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Finalize the hash and retrieve the result
        if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
        {
            std::cerr << "Failed to finalize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Cleanup
        EVP_MD_CTX_free(mdctx);

        // Convert the hash to a vector<uint8_t> and return it
        return std::vector<uint8_t>(hash, hash + hash_len);
    }

    static std::vector<uint8_t> sha256_hash(const std::string &input_str)
    {
        std::vector<uint8_t> input(input_str.begin(), input_str.end());
        return sha256_hash(input);
    }

    static std::vector<uint8_t> sha512_hash(const std::vector<uint8_t> &input)
    {
        // Buffer for the hash result
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        // Create a context for the hashing operation
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr)
        {
            std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
            return {};
        }

        // Initialize the context with the SHA-3-512 algorithm
        if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), nullptr) != 1)
        {
            std::cerr << "Failed to initialize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Hash the data
        if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1)
        {
            std::cerr << "Failed to update digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Finalize the hash and retrieve the result
        if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
        {
            std::cerr << "Failed to finalize digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        // Cleanup
        EVP_MD_CTX_free(mdctx);

        // Convert the hash to a vector<uint8_t> and return it
        return std::vector<uint8_t>(hash, hash + hash_len);
    }
    static bool compare_hash(const std::vector<uint8_t> &hash_1, const std::vector<uint8_t> &hash_2)
    {
        if (hash_1.size() != hash_2.size())
        {
            return false;
        }

        int hash_size = static_cast<int>(hash_1.size());

        for (int x = 0; x < hash_size; x++)
        {
            if (hash_1.at(x) != hash_2.at(x))
            {
                return false;
            }
        }
        return true;
    }

    static std::vector<uint8_t> hash_strings(std::vector<std::string> &strings)
    {
        std::string hash_string = "";
        for(int i = 0; i < strings.size(); i++)
        {
            hash_string += strings[i];
        }

        return sha256_hash(hash_string);
    }

    static std::vector<uint8_t> hash_bytes(std::vector<std::vector<uint8_t>> &bytes)
    {
        std::vector<uint8_t> hash_bytes = {};
        for(int i = 0; i < bytes.size(); i++)
        {
            hash_bytes.insert(hash_bytes.end(), bytes[i].begin(), bytes[i].end());
        }

        return sha256_hash(hash_bytes);
    }

    static void append_u64_be(std::vector<uint8_t>& out, uint64_t v) { out.push_back((v>>56)&0xFF); out.push_back((v>>48)&0xFF); out.push_back((v>>40)&0xFF); out.push_back((v>>32)&0xFF); out.push_back((v>>24)&0xFF); out.push_back((v>>16)&0xFF); out.push_back((v>>8)&0xFF); out.push_back(v & 0xFF); }
    static void append_u64_le(std::vector<uint8_t>& out, uint64_t v) { for (int i=0;i<8;++i) out.push_back((v>>(8*i))&0xFF); }
    static void append_u16_le(std::vector<uint8_t>& out, uint16_t v) { out.push_back(v & 0xFF); out.push_back((v>>8)&0xFF); }
    static void append_u32_be(std::vector<uint8_t>& out, uint32_t v) { out.push_back((v>>24)&0xFF); out.push_back((v>>16)&0xFF); out.push_back((v>>8)&0xFF); out.push_back(v & 0xFF); }
    static std::vector<uint8_t> to_le_bytes(uint64_t v) { return std::vector<uint8_t>((const uint8_t*)&v, ((const uint8_t*)&v) + 8); }
    static std::vector<uint8_t> to_le_bytes_16(uint16_t v) { return std::vector<uint8_t>((const uint8_t*)&v, ((const uint8_t*)&v) + 2); }
    static std::vector<uint8_t> to_le_bytes_8(uint8_t v) { return std::vector<uint8_t>((const uint8_t*)&v, ((const uint8_t*)&v) + 1); }


    static std::vector<uint8_t> build_update_guardian_keys_hash(const std::vector<std::string> &guardian_keys_vector, const uint8_t threshold, const std::string& txn_hash, const uint64_t timestamp)
    {
        constexpr const char* kDomain = SOLANA_BRIDGE_GOV;
        const uint8_t version = 1;

        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 0;

        std::vector<uint8_t> tx_id = hex_to_bytes(txn_hash);
        std::vector<uint8_t> program_id = base58_decode(ZERA_BRIDGE_CORE_PROGRAM_ID);


        if (tx_id.size() != 32) 
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }

        std::vector<uint8_t> payload;
        payload.push_back(threshold);
        payload.push_back(static_cast<uint8_t>(guardian_keys_vector.size()));

        for(int i = 0; i < guardian_keys_vector.size(); i++)
        {
            std::vector<uint8_t> decoded = base58_decode(guardian_keys_vector[i]);
            if (decoded.empty()) {
                std::cout << "ERROR: Failed to decode guardian key - invalid base58 character found" << std::endl;
                return {};
            }
            payload.insert(payload.end(), decoded.begin(), decoded.end());
        }
        std::cout << "Total payload size: " << payload.size() << " bytes" << std::endl;

        uint8_t action = 0; // gov action update guardian keys

        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain));  
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), program_id.begin(), program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());

    
        return sha2_256_hash(preimage); // exactly what the program expects as message
    }

    static std::vector<uint8_t> build_upgrade_token_bridge_hash(const std::string& buffer_address, const std::string& spill_address, const std::string& txn_hash, const uint64_t timestamp, const bool token_bridge)
    {
        constexpr const char* kDomain = SOLANA_BRIDGE_GOV;
        const uint8_t version = 1;

        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 0;

        std::vector<uint8_t> tx_id = hex_to_bytes(txn_hash);
        std::vector<uint8_t> program_id = base58_decode(ZERA_BRIDGE_CORE_PROGRAM_ID);


        if (tx_id.size() != 32) 
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }

        std::vector<uint8_t> buffer_address_bytes = base58_decode(buffer_address);
        std::vector<uint8_t> spill_address_bytes = base58_decode(spill_address);
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), buffer_address_bytes.begin(), buffer_address_bytes.end());
        payload.insert(payload.end(), spill_address_bytes.begin(), spill_address_bytes.end());

        uint8_t action = 5; // gov action upgrade core bridge
        
        if(token_bridge)
        {
            action = 1; // gov action upgrade token bridge
        }


        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain));  
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), program_id.begin(), program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());

        return sha2_256_hash(preimage); // exactly what the program expects as message
    }
    
    static std::vector<uint8_t> build_wrapped_pause_hash(
        uint8_t pause_level,
        uint64_t pause_duration,
        const std::string& tx_id_hex,
        const uint64_t timestamp
    ) {
        constexpr const char* kDomain = SOLANA_BRIDGE_GOV;
        const uint8_t version = 1;

        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 0;

        std::vector<uint8_t> tx_id = hex_to_bytes(tx_id_hex);
        std::vector<uint8_t> program_id = base58_decode(ZERA_BRIDGE_CORE_PROGRAM_ID);


        if (tx_id.size() != 32) 
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }

        std::vector<uint8_t> payload;
        payload.push_back(pause_level);

        uint8_t action = 2; // gov action pause bridge
        
        if(pause_level == 0)
        {
            action = 4;
        }
        if(pause_level == 1)
        {
            action = 2;
        }
        if(pause_level == 2)
        {
            action = 3;
        }

        if(pause_level > 0)
        {
            append_u64_be(payload, pause_duration);
        }


        //print all in order
        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain));  
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), program_id.begin(), program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());
    
        return sha2_256_hash(preimage); // exactly what the program expects as message
    }

    static std::vector<uint8_t> build_wrapped_zera_to_solana_mint_hash(
        uint64_t amt,
        const std::string& recipient_b58,
        const std::string& contract_id,
        const std::string& tx_id_hex,
        const uint64_t timestamp,
        const uint64_t usd_amount
    ) {
        constexpr const char* kDomain = SOLANA_BRIDGE_TOKEN;
        const uint8_t version = 1;
        const uint8_t action = 3; // mint wrapped SOL

        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 0;

        std::vector<uint8_t> tx_id = hex_to_bytes(tx_id_hex);
        std::vector<uint8_t> program_id = base58_decode(ZERA_BRIDGE_TOKEN_V1_PROGRAM_ID);
        std::vector<uint8_t> recipient = base58_decode(recipient_b58);

        std::vector<uint8_t> contract_id_bytes(contract_id.begin(), contract_id.end());


        if (recipient.size() != 32) 
        {
            std::cout << "Recipient not 32 bytes" << std::endl;
            return {};
        }
        if (tx_id.size() != 32) 
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }

        // Payload = amount (u64 BE) + recipient (32) + contract_id (u16 len + bytes) + decimals (u8) + name (u8 len + bytes) + symbol (u8 len + bytes) + uri (u16 len + bytes)
        std::vector<uint8_t> payload;
        payload.reserve(8 + 32 + 2 + contract_id_bytes.size());
        
        append_u64_be(payload, amt);
        payload.insert(payload.end(), recipient.begin(), recipient.end());
        // contract_id with u16 BE length prefix
        uint16_t contract_id_len = static_cast<uint16_t>(contract_id_bytes.size());
        payload.push_back((contract_id_len >> 8) & 0xFF);
        payload.push_back(contract_id_len & 0xFF);
        payload.insert(payload.end(), contract_id_bytes.begin(), contract_id_bytes.end());
        append_u64_be(payload, usd_amount);

        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain)); 
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), program_id.begin(), program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());
    
        return sha2_256_hash(preimage); // exactly what the program expects as message
    }

    static std::vector<uint8_t> build_wrapped_zera_to_solana_hash(
        uint64_t amt,
        const std::string& recipient_b58,
        const std::string& contract_id,
        const std::string& name,
        const std::string& symbol,
        const uint8_t decimals,
        const std::string& uri,
        const std::string& tx_id_hex,
        const uint64_t timestamp,
        const uint64_t usd_amount
    ) {
        constexpr const char* kDomain = SOLANA_BRIDGE_TOKEN;
        const uint8_t version = 1;
        const uint8_t action = 2; // create wrapped SOL

        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 0;

        std::vector<uint8_t> tx_id = hex_to_bytes(tx_id_hex);
        std::vector<uint8_t> program_id = base58_decode(ZERA_BRIDGE_TOKEN_V1_PROGRAM_ID);
        std::vector<uint8_t> recipient = base58_decode(recipient_b58);

        std::vector<uint8_t> contract_id_bytes(contract_id.begin(), contract_id.end());
        std::vector<uint8_t> name_bytes(name.begin(), name.end());
        std::vector<uint8_t> symbol_bytes(symbol.begin(), symbol.end());
        std::vector<uint8_t> uri_bytes(uri.begin(), uri.end());


        if (recipient.size() != 32) 
        {
            std::cout << "Recipient not 32 bytes" << std::endl;
            return {};
        }
        if (tx_id.size() != 32) 
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }

        //print all in orde

        // Payload = amount (u64 BE) + recipient (32) + contract_id (u16 len + bytes) + decimals (u8) + name (u8 len + bytes) + symbol (u8 len + bytes) + uri (u16 len + bytes)
        std::vector<uint8_t> payload;
        payload.reserve(8 + 32 + 2 + contract_id_bytes.size() + 1 + 1 + name_bytes.size() + 1 + symbol_bytes.size() + 2 + uri_bytes.size());
        
        append_u64_be(payload, amt);
        payload.insert(payload.end(), recipient.begin(), recipient.end());
        // contract_id with u16 BE length prefix
        uint16_t contract_id_len = static_cast<uint16_t>(contract_id_bytes.size());
        payload.push_back((contract_id_len >> 8) & 0xFF);
        payload.push_back(contract_id_len & 0xFF);
        payload.insert(payload.end(), contract_id_bytes.begin(), contract_id_bytes.end());
        // decimals (u8)
        payload.push_back(decimals);
        // name with u8 length prefix
        payload.push_back(static_cast<uint8_t>(name_bytes.size()));
        payload.insert(payload.end(), name_bytes.begin(), name_bytes.end());
        // symbol with u8 length prefix
        payload.push_back(static_cast<uint8_t>(symbol_bytes.size()));
        payload.insert(payload.end(), symbol_bytes.begin(), symbol_bytes.end());
        // uri with u16 BE length prefix
        uint16_t uri_len = static_cast<uint16_t>(uri_bytes.size());
        payload.push_back((uri_len >> 8) & 0xFF);
        payload.push_back(uri_len & 0xFF);
        payload.insert(payload.end(), uri_bytes.begin(), uri_bytes.end());
        append_u64_be(payload, usd_amount);

        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain)); 
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), program_id.begin(), program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());
    
        return sha2_256_hash(preimage); // exactly what the program expects as message
    }

    static std::vector<uint8_t> build_release_hash(
        uint64_t amt,
        const std::string& recipient_b58,
        const std::string& tx_id_hex,
        const uint64_t timestamp,
        const uint64_t usd_amount
    ) {
        const uint8_t version = 1;

        constexpr const char* kDomain = SOLANA_BRIDGE_TOKEN;
        const uint8_t action = 0; // release SOL

        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 0;

        std::vector<uint8_t> tx_id = hex_to_bytes(tx_id_hex);
        std::vector<uint8_t> program_id = base58_decode(ZERA_BRIDGE_TOKEN_V1_PROGRAM_ID);
        std::vector<uint8_t> recipient = base58_decode(recipient_b58);

        if (recipient.size() != 32)
        {
            std::cout << "Recipient not 32 bytes" << std::endl;
            return {};
        }
        if (tx_id.size() != 32)
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }
        if (program_id.size() != 32)
        {
            std::cout << "Program id not 32 bytes" << std::endl;
            return {};
        }

        // Payload = amount (u64 BE) + recipient (32)
        std::vector<uint8_t> payload;
        payload.reserve(8 + 32);
        append_u64_be(payload, amt);
        payload.insert(payload.end(), recipient.begin(), recipient.end());
        append_u64_be(payload, usd_amount);


        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain));  
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), program_id.begin(), program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());

        return sha2_256_hash(preimage);
    }

    static std::vector<uint8_t> build_release_spl_hash(
        uint64_t amt,
        const std::string& recipient_b58,
        const std::string& tx_id_hex,
        const std::string& mint_b58,
        const uint64_t timestamp,
        const uint64_t usd_amount
    ) {
        const uint8_t version = 1;
        constexpr const char* kDomain = SOLANA_BRIDGE_TOKEN;
        const uint8_t action = 1; // release SPL

        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 0; 

        std::vector<uint8_t> tx_id = hex_to_bytes(tx_id_hex);
        std::vector<uint8_t> program_id = base58_decode(ZERA_BRIDGE_TOKEN_V1_PROGRAM_ID);
        std::vector<uint8_t> recipient = base58_decode(recipient_b58);
        std::vector<uint8_t> mint = base58_decode(mint_b58);

        if (mint.size() != 32)
        {
            std::cout << "Mint not 32 bytes" << std::endl;
            return {};
        }
        if (recipient.size() != 32)
        {
            std::cout << "Recipient not 32 bytes" << std::endl;
            return {};
        }
        if (tx_id.size() != 32)
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }
        if (program_id.size() != 32)
        {
            std::cout << "Program id not 32 bytes" << std::endl;
            return {};
        }


        // Payload = amount (u64 BE) + recipient (32) + mint (32)
        std::vector<uint8_t> payload;
        payload.reserve(8 + 32 + 32);
        append_u64_be(payload, amt);
        payload.insert(payload.end(), recipient.begin(), recipient.end());
        payload.insert(payload.end(), mint.begin(), mint.end());
        append_u64_be(payload, usd_amount);


        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain)); 
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), program_id.begin(), program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());

        return sha2_256_hash(preimage);
    }

    static std::vector<uint8_t> build_upgrade_token_bridge_hash(
        const std::string& buffer_address_b58,
        const std::string& spill_address_b58,
        const std::string& tx_id_hex,
        const uint64_t timestamp
    ) {
        const uint8_t version = 1;
        constexpr const char* kDomain = SOLANA_BRIDGE_GOV;
        const uint8_t action = 1; // ACTION_UPGRADE_TOKEN_BRIDGE
    
        const uint64_t ts_be = timestamp;
        const uint64_t expiry_be = 0;
        const uint32_t event_index_be = 1;  // Always 1 for upgrade token bridge actions

        std::vector<uint8_t> tx_id = hex_to_bytes(tx_id_hex);
        std::vector<uint8_t> target_program_id = base58_decode(ZERA_BRIDGE_CORE_PROGRAM_ID);  // Core program ID
        std::vector<uint8_t> buffer_address = base58_decode(buffer_address_b58);
        std::vector<uint8_t> spill_address = base58_decode(spill_address_b58);
    
        // Validate sizes
        if (buffer_address.size() != 32)
        {
            std::cout << "Buffer address not 32 bytes" << std::endl;
            return {};
        }
        if (spill_address.size() != 32)
        {
            std::cout << "Spill address not 32 bytes" << std::endl;
            return {};
        }
        if (tx_id.size() != 32)
        {
            std::cout << "Txn id not 32 bytes" << std::endl;
            return {};
        }
        if (target_program_id.size() != 32)
        {
            std::cout << "Target program id not 32 bytes" << std::endl;
            return {};
        }
    
        // Payload = buffer_address (32) + spill_address (32)
        std::vector<uint8_t> payload;
        payload.reserve(64);
        payload.insert(payload.end(), buffer_address.begin(), buffer_address.end());
        payload.insert(payload.end(), spill_address.begin(), spill_address.end());
    

        // Build preimage
        std::vector<uint8_t> preimage;
        preimage.reserve(1 + strlen(kDomain) + 1 + 8 + 8 + 32 + 4 + 32 + payload.size()); 
        preimage.push_back(version);
        preimage.insert(preimage.end(), kDomain, kDomain + strlen(kDomain)); 
        preimage.push_back(action);
        append_u64_be(preimage, ts_be);
        append_u64_be(preimage, expiry_be);
        preimage.insert(preimage.end(), tx_id.begin(), tx_id.end());
        append_u32_be(preimage, event_index_be);
        preimage.insert(preimage.end(), target_program_id.begin(), target_program_id.end());
        preimage.insert(preimage.end(), payload.begin(), payload.end());
    
    
        return sha2_256_hash(preimage);
    }
};