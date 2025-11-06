// Standard library headers
#include <vector>
#include <stdexcept>
#include <iostream>
#include <regex>
#include <sstream>

// Third-party library headers
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>

// Project-specific headers
#include "signatures.h"
#include "validator.pb.h"

// #include "db_wallets.h"
#include "wallets.h"
#include "wallet.pb.h"
#include "encoding.h"

namespace
{

    KeyType extract_public_key(std::vector<uint8_t> &public_key, std::vector<uint8_t> &public_key_extract)
    {

        std::string pub_key_str(public_key.begin(), public_key.end());

        KeyType key_type = signatures::get_key_type(pub_key_str);

        if (pub_key_str.length() < 4 || key_type == KeyType::ERROR_TYPE)
        {
            return KeyType::ERROR_TYPE;
        }

        int key_size = 0;

        if (key_type == KeyType::ED25519)
        {
            key_size = 32;
        }
        else if (key_type == KeyType::ED448)
        {
            key_size = 57;
        }
        else
        {
            return KeyType::ERROR_TYPE;
        }

        std::string pub_key_extract_str = pub_key_str.substr(pub_key_str.size() - key_size);

        public_key_extract.assign(pub_key_extract_str.begin(), pub_key_extract_str.end());

        return key_type;
    }

    // ##################################################
    //                 BASE FUNCTIONS
    // ##################################################
    //  Function to sign a message using either Ed25519 with Sodium or Ed448 with OpenSSL
    std::string sign_message(const std::vector<unsigned char> &message, KeyPair key_pair)
    {

        std::vector<uint8_t> pub_key_extract;
        KeyType key_type = extract_public_key(key_pair.public_key, pub_key_extract);
        std::vector<uint8_t> private_key = key_pair.private_key;
        std::vector<uint8_t> signature; // Create a vector to hold the signature

        if (key_type == KeyType::ED25519) // If the key type is Ed25519
        {
            // Use the sodium crypto_sign_detached function to sign the message
            signature = std::vector<uint8_t>(crypto_sign_BYTES); // Allocate space for the signature
            if (crypto_sign_detached(signature.data(), nullptr, message.data(), message.size(), private_key.data()) != 0)
            {
                // If the signature generation fails, throw an error
                std::string sig_str(signature.begin(), signature.end());
                return sig_str;
            }
            std::string sig_str(signature.begin(), signature.end());
            // Return the signature
            return sig_str;
        }
        else if (key_type == KeyType::ERROR_TYPE) // If the key type is not recognized or is not Ed448
        {
            std::string sig_str(signature.begin(), signature.end());
            // Return an empty signature vector
            return sig_str;
        }

        // If the key type is Ed448
        unsigned char *sig = NULL;
        size_t sig_len;
        EVP_PKEY *evp_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL, private_key.data(), private_key.size());

        if (evp_key == NULL)
        {
            std::string sig_str(signature.begin(), signature.end());
            // Return an empty signature vector
            return sig_str;
        }

        // Create a new signing context and initialize it with the private key
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

        if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, evp_key) != 1)
        {
            // If the initialization of the signing context fails, free resources and throw an error
            EVP_PKEY_free(evp_key);
            EVP_MD_CTX_free(mdctx);
            std::string sig_str(signature.begin(), signature.end());
            // Return an empty signature vector
            return sig_str;
        }

        // Get the size of the signature buffer needed
        EVP_DigestSign(mdctx, NULL, &sig_len, message.data(), message.size());

        // Resize the signature buffer to the correct size
        signature = std::vector<unsigned char>(sig_len);

        // Sign the message
        EVP_DigestSign(mdctx, signature.data(), &sig_len, message.data(), message.size());

        // Free the resources used by the signing context and the EVP_PKEY object
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(evp_key);

        std::string sig_str(signature.begin(), signature.end());
        // Return the signature
        return sig_str;
    }

    // Verify the signature of a message using the specified public key and key type
    bool verify_signature(const std::vector<unsigned char> &message, std::vector<unsigned char> &signature, std::vector<unsigned char> &public_key)
    {

        if(signature.size() == 0 || public_key.size() == 0 || message.size() == 0)
        {
            //logging::print("Signature, public key, or message is empty");
            return false;
        }

        std::vector<uint8_t> pub_key_extract;
        KeyType key_type = extract_public_key(public_key, pub_key_extract);
        std::string pub_key_extract_str(pub_key_extract.begin(), pub_key_extract.end());
        std::string signature_str(signature.begin(), signature.end());

        if (key_type == KeyType::ED25519)
        {
            return crypto_sign_verify_detached(signature.data(), message.data(), message.size(), pub_key_extract.data()) == 0;
        }
        else if (key_type == KeyType::ERROR_TYPE)
        {
            // If the key type is not recognized, return false
            return false;
        }

        // For Ed448 keys, create an EVP_PKEY object from the public key
        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, pub_key_extract.data(), pub_key_extract.size());

        if (pkey == NULL)
        {
            //logging::print("Failed to create EVP_PKEY object");
            return false;
        }

        // Create a new message digest context and initialize it with the public key
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1)
        {
            // If the context fails to initialize, free the resources and throw an error
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(md_ctx);
            //logging::print("Failed to initialize verification context");
            return false;
        }

        // Verify the message digest signature
        if (EVP_DigestVerify(md_ctx, signature.data(), signature.size(), message.data(), message.size()) != 1)
        {
            //logging::print("Failed to initialize verification context v2");
            // If the signature is not valid, free the resources and return false
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(md_ctx);
            return false;
        }
        else
        {
            // If the signature is valid, free the resources and return true
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(md_ctx);
            return true;
        }
    }
    // ##################################################
    //                   VERIFYING
    // ##################################################
    template <typename TXType>
    bool multi_signature(TXType &tx)
    {
        TXType tx_copy;
        tx_copy.CopyFrom(tx);
        zera_txn::BaseTXN *base = tx_copy.mutable_base();

        zera_txn::MultiKey *multi_key = base->mutable_public_key()->mutable_multi();

        if (multi_key->multi_patterns_size() <= 0)
        {
            return false;
        }

        base->release_hash();

        int x = multi_key->signatures_size() - 1;
        std::map<std::string, std::vector<std::string>> class_keys;

        while (x >= 0)
        {
            std::string *signature = multi_key->mutable_signatures()->ReleaseLast();

            if(signature == nullptr || signature->empty())
            {
                return false;
            }

            std::smatch match;
            std::string public_key;
            std::string prefix;
            std::string pub_str = multi_key->public_keys(x);

            size_t prefix_end = pub_str.find_first_of('_');

            if (prefix_end != std::string::npos && prefix_end > 1 && pub_str[0] == 'c' && isdigit(pub_str[1]))
            {
                // Extract the prefix
                prefix = pub_str.substr(0, prefix_end);

                // Extract the rest of the string
                public_key = pub_str.substr(prefix_end + 1);
            }
            else
            {
                continue;
            }

            if (public_key == "")
            {
                return false;
            }
            else if (*signature != "")
            {
                std::string message_str = tx_copy.SerializeAsString();

                if (signatures::verify_multi(public_key, *signature, message_str))
                {

                    class_keys[prefix].push_back(public_key);
                }
            }
            x--;
        }

        bool valid = false;
        for (auto pattern : multi_key->multi_patterns())
        {
            std::map<std::string, int> class_reqs;

            if (pattern.class__size() != pattern.required_size())
            {
                continue;
            }

            int y = 0;
            while (y < pattern.class__size())
            {
                std::string class_name = "c" + std::to_string(pattern.class_(y));
                class_reqs[class_name] = pattern.required(y);
                y++;
            }

            for (auto req : class_reqs)
            {
                if (class_keys[req.first].size() < req.second)
                {
                    valid = false;
                    break;
                }
                else
                {
                    valid = true;
                }
            }

            if (valid)
            {
                break;
            }
        }
        return valid;
    }
}

int signatures::get_key_size(const KeyType &key_type)
{
    switch (key_type)
    {
    case KeyType::ED25519:
        return 32;
    case KeyType::ED448:
        return 57;
    default:
        return 0;
    }
}
KeyType signatures::get_key_type(const std::string &public_key, bool restricted)
{
    std::string key_type_str = public_key.substr(0, 2);

    KeyType key_type;

    if (key_type_str == "A_")
    {
        key_type = KeyType::ED25519;
    }
    else if (key_type_str == "B_")
    {
        key_type = KeyType::ED448;
    }
    else if (key_type_str == "r_")
    {
        if (restricted)
        {
            key_type = KeyType::ERROR_TYPE;
        }
        else
        {
            std::string extract_string = public_key.substr(2, public_key.size() - 1);
            key_type = get_key_type(extract_string, true);
        }
    }
    else
    {
        key_type = KeyType::ERROR_TYPE;
    }

    return key_type;
}
bool signatures::verify_activity_response(const zera_api::SmartContractEventsResponse *response)
{
    zera_api::SmartContractEventsResponse response_copy;
    response_copy.CopyFrom(*response);

    if(response_copy.public_key().single().empty() || response_copy.signature().empty())
    {
        std::cout << "Public key or signature is empty" << std::endl;
        return false;
    }

    zera_txn::PublicKey *public_key = response_copy.mutable_public_key();

    std::string* signature = response_copy.release_signature();
    std::string message_str = response_copy.SerializeAsString();
    std::vector<unsigned char> message(message_str.begin(), message_str.end());
    std::vector<unsigned char> signature_vec(signature->begin(), signature->end());
    std::vector<unsigned char> public_key_vec(public_key->single().begin(), public_key->single().end());
    return verify_signature(message, signature_vec, public_key_vec);
}

void signatures::sign_activity_request(zera_api::ActivityRequest& request, KeyPair key_pair)
{
    std::string message_str = request.SerializeAsString();
    std::vector<unsigned char> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);

    request.set_signature(signature);
}

std::vector<uint8_t> signatures::sign_hash(std::vector<uint8_t> &hash, KeyPair key_pair)
{
    std::string signature = sign_message(hash, key_pair);
    return std::vector<uint8_t>(signature.begin(), signature.end());
}
bool signatures::verify_hash(const std::string& hash, const std::string& signature, const std::string& public_key, bool is_zera)
{
    if(hash.empty() || signature.empty() || public_key.empty())
    {
        return false;
    }

    auto hash_vec = hex_to_bytes(hash);
    std::vector<unsigned char> public_key_vec;
    if(is_zera)
    {
        public_key_vec = base58_decode_public_key(public_key);
        auto signature_vec = base58_decode(signature);
        return verify_signature(hash_vec, signature_vec, public_key_vec);
    }
    else
    {
        public_key_vec = base58_decode(public_key);
        auto signature_vec = base58_decode(signature);
        return crypto_sign_verify_detached(signature_vec.data(), hash_vec.data(), hash_vec.size(), public_key_vec.data()) == 0;  
    }

    std::cout << "public key is not zera and is_zera is false" << std::endl;
    return false;
}
bool signatures::verify_contract_response(const zera_api::ContractResponse *response)
{
    zera_api::ContractResponse response_copy;
    response_copy.CopyFrom(*response);

    if(response_copy.public_key().single().empty() || response_copy.signature().empty())
    {
        std::cout << "Public key or signature is empty" << std::endl;
        return false;
    }
    
    zera_txn::PublicKey *public_key = response_copy.mutable_public_key();
    std::string* signature = response_copy.release_signature();
    std::string message_str = response_copy.SerializeAsString();
    std::vector<unsigned char> message(message_str.begin(), message_str.end());
    std::vector<unsigned char> signature_vec(signature->begin(), signature->end());
    std::vector<unsigned char> public_key_vec(public_key->single().begin(), public_key->single().end());
    
    return verify_signature(message, signature_vec, public_key_vec);
}

template <typename TXType>
void signatures::sign_txns(TXType* txn, KeyPair key_pair)
{
    std::string message_str = txn->SerializeAsString();
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    std::string signature = sign_message(message, key_pair);
    txn->mutable_base()->set_signature(signature);
}
template void signatures::sign_txns<zera_txn::SmartContractExecuteTXN>(zera_txn::SmartContractExecuteTXN*, KeyPair);
