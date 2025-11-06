#include "events.h"
#include "db_base.h"
#include "const.h"
#include "guardian.pb.h"
#include "txn_client.h"
#include "hashing.h"
#include "signatures.h"
#include "payload.h"
#include "encoding.h"
#include "metadata_program.h"
#include <sstream>

namespace
{
    static std::vector<uint8_t> push_u16_le(uint16_t x)
    {
        std::vector<uint8_t> out;
        out.push_back(static_cast<uint8_t>(x & 0xFF));
        out.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
        return out;
    }

    static std::vector<uint8_t> push_u64_le(uint64_t x)
    {
        std::vector<uint8_t> out;
        for (int i = 0; i < 8; ++i)
        {
            out.push_back(static_cast<uint8_t>(x >> (8 * i)));
        }
        return out;
    }
    static inline std::string trim(const std::string &s)
    {
        size_t a = 0, b = s.size();
        while (a < b && std::isspace(static_cast<unsigned char>(s[a])))
            ++a;
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
            --b;
        return s.substr(a, b - a);
    }

    void ExtractResKeyValues(const std::string &text,
                             std::vector<std::string> &keys,
                             std::vector<std::string> &values)
    {
        keys.clear();
        values.clear();
        const std::string start = "[res]";
        const std::string end = "[end]";
        size_t pos = 0;

        while (true)
        {
            size_t a = text.find(start, pos);
            if (a == std::string::npos)
                break;
            a += start.size();
            size_t b = text.find(end, a);
            if (b == std::string::npos)
                break;

            std::string item = trim(text.substr(a, b - a));
            size_t colon = item.find(':');

            if (colon == std::string::npos)
            {
                if (!item.empty())
                {
                    keys.push_back("event");
                    values.push_back(item);
                }
            }
            else
            {
                std::string key = trim(item.substr(0, colon));
                std::string val = trim(item.substr(colon + 1));
                keys.push_back(key);
                values.push_back(val);
            }
            pos = b + end.size();
        }
    }
}

void events::process_zera_events(const zera_api::SmartContractEventsResponse *request)
{

    std::string event_data = request->event_data();
    std::vector<std::string> keys;
    std::vector<std::string> values;

    ExtractResKeyValues(event_data, keys, values);

    if (keys.size() == 0 || values.size() == 0)
    {
        std::cout << "No keys or values found in event data" << std::endl;
        return;
    }

    if (keys[0] != "EVENT")
    {
        std::cout << "Event type not found in event data" << std::endl;
        return;
    }

    EventType event_type = GetEventType(values[0]);

    std::string txn_hash = request->txn_hash();

    if(db_guardians_payloads::exist(txn_hash) || db_payloads::exist(txn_hash))
    {
        std::cout << "Payload already processed" << std::endl;
        return;
    }

    if (event_type == EventType::SEND_NATIVE_ZERA_TO_SOLANA)
    {
        std::cout << "Sending native zera to solana" << std::endl;
        send_native_zera_to_solana(keys, values, txn_hash, request->timestamp().seconds());
    }
    else if (event_type == EventType::RELEASE_NATIVE_SOLANA_TO_SOLANA)
    {
        std::cout << "Sending solana to solana" << std::endl;
        release_native_solana_to_solana(keys, values, txn_hash, request->timestamp().seconds());
    }
    else if (event_type == EventType::UPDATE_TOKEN_BRIDGE)
    {
        std::cout << "Upgrading token bridge" << std::endl;
        upgrade_token_bridge(keys, values, txn_hash, request->timestamp().seconds(), true);
    }
    else if (event_type == EventType::UPDATE_CORE_BRIDGE)
    {
        std::cout << "Updating core bridge" << std::endl;
        upgrade_token_bridge(keys, values, txn_hash, request->timestamp().seconds(), false);
    }
    else if (event_type == EventType::PAUSE_BRIDGE)
    {
        std::cout << "Pausing bridge" << std::endl;
        pause_bridge(keys, values, txn_hash, request->timestamp().seconds());
    }
    else if (event_type == EventType::UPDATE_GUARDIAN_KEYS)
    {
        std::cout << "Updating guardian keys" << std::endl;
        update_guardian_keys(keys, values, txn_hash, request->timestamp().seconds());
    }

    std::cout << "Event data processed" << std::endl;
}

// This function is called when someone on the zera network sends native zera tokens to zera network bridge smart contract to be bridged to the solana network
// Steps:
// 1. Parse the event data to get the amount of the native zera tokens to be bridged
// 2. Get the solana address to which the tokens will be bridged
// 3. Get the denomination of the tokens to be bridged
// 4. Get the contract id of the tokens to be bridged
// 5. Get the token id of the tokens to be bridged
// 6. Get the token account of the tokens to be bridged

void events::update_guardian_keys(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp)
{
    std::string guardian_keys;
    std::string threshold;

    for (int i = 0; i < keys.size(); i++)
    {
        std::cout << keys[i] << ": " << values[i] << std::endl;
        if (keys[i] == "guardian_keys")
        {
            guardian_keys = values[i];
        }
        else if (keys[i] == "threshold")
        {
            threshold = values[i];
        }
    }

    if (guardian_keys.empty() || threshold.empty())
    {
        std::cout << "Missing required fields" << std::endl;
        return;
    }

    std::vector<std::string> guardian_keys_vector;

    std::stringstream ss(guardian_keys);
    std::string key;
    while (std::getline(ss, key, ','))
    {
        guardian_keys_vector.push_back(key);
    }

    std::cout << "Updated guardian keys: " << guardian_keys_vector.size() << " keys" << std::endl;
    std::cout << "Threshold string: '" << threshold << "' (length: " << threshold.length() << ")" << std::endl;

    // Validate and parse threshold
    int threshold_int;
    try {
        threshold_int = std::stoi(threshold);
        std::cout << "Threshold value: " << threshold_int << std::endl;
    } catch (const std::invalid_argument& e) {
        std::cerr << "❌ ERROR: Invalid threshold value - not a number: '" << threshold << "'" << std::endl;
        return;
    } catch (const std::out_of_range& e) {
        std::cerr << "❌ ERROR: Threshold value out of range: '" << threshold << "'" << std::endl;
        return;
    }

    zera_guardian::SolanaUpdateGuardianKeysPayload update_guardian_keys_payload;

    for (int i = 0; i < guardian_keys_vector.size(); i++)
    {
        update_guardian_keys_payload.add_guardian_keys(guardian_keys_vector[i]);
    }

    update_guardian_keys_payload.set_threshold(threshold_int);
    update_guardian_keys_payload.set_txn_hash(txn_hash);

    // threshhold need to be uint8_t
    uint8_t threshold_uint8 = static_cast<uint8_t>(threshold_int);

    auto hash = Hashing::build_update_guardian_keys_hash(guardian_keys_vector, threshold_uint8, txn_hash, timestamp);

    auto hash_hex = to_hex(hash);

    zera_guardian::SolanaPayload solana_payload;
    solana_payload.set_signed_hash(hash_hex);
    solana_payload.mutable_update_guardian_keys_payload()->CopyFrom(update_guardian_keys_payload);
    //solana_payload.mutable_timestamp()->set_seconds(timestamp);

    payload::process_solana_payload(solana_payload, hash, txn_hash, timestamp);

    std::cout << "Updated guardian keys hash: " << hash_hex << std::endl;
}
void events::send_native_zera_to_solana(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp)
{

    std::string contract_id;
    std::string amount;
    std::string solana_address;
    std::string nonce;
    std::string mint_id;

    for (int i = 0; i < keys.size(); i++)
    {
        std::cout << keys[i] << ": " << values[i] << std::endl;

        if (keys[i] == "contract_id")
        {
            contract_id = values[i];
        }
        else if (keys[i] == "amount")
        {
            amount = values[i];
        }
        else if (keys[i] == "solana_address")
        {
            solana_address = values[i];
        }
        else if (keys[i] == "nonce")
        {
            nonce = values[i];
        }
    }

    if (contract_id.empty() || amount.empty() || solana_address.empty())
    {
        std::cout << "Missing required fields" << std::endl;
        return;
    }

    std::string contract_data;

    if (!db_contracts::get_single(contract_id, contract_data))
    {
        std::cout << "Contract not found, creating new contract" << std::endl;
        db_contracts::store_single(contract_id, "1");
        create_wrapped_zera_to_solana(contract_id, amount, solana_address, txn_hash, timestamp);
    }
    else
    {
        mint_native_zera_to_solana(contract_id, amount, solana_address, txn_hash, timestamp);
    }
}

void events::create_wrapped_zera_to_solana(const std::string contract_id, const std::string amount, const std::string solana_address, const std::string txn_hash, const uint64_t timestamp)
{
    zera_txn::InstrumentContract contract = TXNClient::GetContract(contract_id);

    if (contract.contract_id().empty())
    {
        std::cout << "Contract not found" << std::endl;
        return;
    }

    zera_guardian::SolanaContractPayload contract_payload;

    std::string uri = "";
    for (auto kvp : contract.custom_parameters())
    {
        if (kvp.key() == "uri")
        {
            uri = kvp.value();
            contract_payload.set_uri(kvp.value());
            break;
        }
    }
    contract_payload.set_uri(uri);

    size_t decimals_size = contract.coin_denomination().amount().size() - 1;
    std::string decimals = std::to_string(decimals_size);

    uint64_t amt = std::stoull(amount);
    contract_payload.set_amount(amt);
    contract_payload.set_zera_contract_id(contract_id);
    contract_payload.set_solana_wallet_address(solana_address);
    contract_payload.set_decimals(decimals);
    contract_payload.set_name(contract.name());
    contract_payload.set_symbol(contract.symbol());
    contract_payload.set_txn_hash(txn_hash);

    uint64_t usd_amount = 0;

    auto hash = Hashing::build_wrapped_zera_to_solana_hash(amt, solana_address, contract_id, contract.name(), contract.symbol(), decimals_size, uri, txn_hash, timestamp, usd_amount);

    auto hash_hex = to_hex(hash);

    zera_guardian::SolanaPayload solana_payload;
    solana_payload.set_signed_hash(hash_hex);
    solana_payload.mutable_contract_payload()->CopyFrom(contract_payload);
    //solana_payload.mutable_timestamp()->set_seconds(timestamp);

    payload::process_solana_payload(solana_payload, hash, txn_hash, timestamp);
}

void events::mint_native_zera_to_solana(const std::string contract_id, const std::string amount, const std::string solana_address, const std::string txn_hash, const uint64_t timestamp)
{

    zera_guardian::SolanaMintPayload mint_payload;

    uint64_t amt = std::stoull(amount);
    mint_payload.set_amount(amt);
    mint_payload.set_zera_contract_id(contract_id);
    mint_payload.set_solana_wallet_address(solana_address);
    mint_payload.set_txn_hash(txn_hash);

    uint64_t usd_amount = 0;
    std::string mint_id;
    if (db_contracts::get_single(contract_id, mint_id))
    {
        double usd_price = 0.0;
        metadata::get_usd_price_from_jupiter(mint_id, usd_price);
        usd_amount = static_cast<uint64_t>(usd_price * 100);
    }

    auto hash = Hashing::build_wrapped_zera_to_solana_mint_hash(amt, solana_address, contract_id, txn_hash, timestamp, usd_amount);

    auto hash_hex = to_hex(hash);

    zera_guardian::SolanaPayload solana_payload;
    solana_payload.set_signed_hash(hash_hex);
    solana_payload.mutable_mint_payload()->CopyFrom(mint_payload);
    //solana_payload.mutable_timestamp()->set_seconds(timestamp);

    payload::process_solana_payload(solana_payload, hash, txn_hash, timestamp);
}

void events::release_native_solana_to_solana(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp)
{

    std::string contract_id;
    std::string amount;
    std::string solana_address;
    std::string mint_id;
    double usd_price = 0.0;

    for (int i = 0; i < keys.size(); i++)
    {
        std::cout << keys[i] << ": " << values[i] << std::endl;
        if (keys[i] == "contract_id")
        {
            contract_id = values[i];
        }
        else if (keys[i] == "amount")
        {
            amount = values[i];
        }
        else if (keys[i] == "solana_address")
        {
            solana_address = values[i];
        }
        else if (keys[i] == "mint_id")
        {
            mint_id = values[i];
        }
    }

    std::string used_mint_id = mint_id;
    if (used_mint_id == SOL_MINT_ID)
    {
        used_mint_id = WRAPPED_SOL_MINT_ID;
    }

    metadata::get_usd_price_from_jupiter(used_mint_id, usd_price);

    uint64_t usd_amount_u64 = static_cast<uint64_t>(usd_price * 100);

    if (contract_id.empty() || amount.empty() || solana_address.empty() || mint_id.empty())
    {
        std::cout << "Missing required fields" << std::endl;
        return;
    }

    // std::string contract_data;
    // if(!db_contracts::get_single(contract_id, contract_data))
    // {
    //     return;
    // }

    zera_guardian::SolanaReleasePayload release_payload;

    uint64_t amt = std::stoull(amount);
    release_payload.set_zera_contract_id(contract_id);
    release_payload.set_amount(amt);
    release_payload.set_solana_wallet_address(solana_address);
    release_payload.set_solana_mint_address(mint_id);
    release_payload.set_txn_hash(txn_hash);
    release_payload.set_usd_amount(usd_amount_u64);

    std::vector<uint8_t> hash;
    if (mint_id != SOL_MINT_ID)
    {
        hash = Hashing::build_release_spl_hash(amt, release_payload.solana_wallet_address(), txn_hash, mint_id, timestamp, usd_amount_u64);
    }
    else
    {
        hash = Hashing::build_release_hash(amt, release_payload.solana_wallet_address(), txn_hash, timestamp, usd_amount_u64);
    }

    auto hash_hex = to_hex(hash);

    std::cout << "Release hash hex: " << hash_hex << std::endl;
    zera_guardian::SolanaPayload solana_payload;
    solana_payload.set_signed_hash(hash_hex);
    solana_payload.mutable_release_payload()->CopyFrom(release_payload);
    //solana_payload.mutable_timestamp()->set_seconds(timestamp);

    payload::process_solana_payload(solana_payload, hash, txn_hash, timestamp);
}