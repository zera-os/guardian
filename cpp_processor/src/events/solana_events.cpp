#include "events.h"

#include <google/protobuf/util/time_util.h>

#include "db_base.h"
#include "const.h"
#include "guardian.pb.h"
#include "hashing.h"
#include "encoding.h"
#include "payload.h"
#include "metadata_program.h"
#include "string_utils.h"
#include "solana_subscriber.h"

void events::process_solana_events(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string &slot, const std::string &tx_signature)
{
    if (keys.size() == 0 || values.size() == 0 || keys.size() != values.size() || keys[0] != "EVENT")
    {
        std::cout << "No keys or values found in event data : " << keys.size() << " " << values.size() << std::endl;
        std::cout << "key[0]: " << keys[0] << std::endl;
        std::cout << "value[0]: " << values[0] << std::endl;
        return;
    }

    if(db_guardians_payloads::exist(tx_signature) || db_payloads::exist(tx_signature))
    {
        std::cout << "Payload already processed" << std::endl;
        return;
    }

    EventType event_type = GetEventType(values[0]);

    if (event_type == EventType::MINT_NATIVE_SOLANA_TO_ZERA)
    {
        std::cout << "MINT NATIVE SOLANA TO ZERA LOGGED" << std::endl;
        mint_native_solana_to_zera(keys, values, slot, tx_signature);
    }
    else if (event_type == EventType::RELEASE_NATIVE_ZERA_TO_ZERA)
    {
        std::cout << "RELEASE NATIVE ZERA TO ZERA LOGGED" << std::endl;
        release_native_zera_to_zera(keys, values, slot, tx_signature);
    }
    else if (event_type == EventType::CREATE_WRAPPED_SOLANA_TO_ZERA)
    {
        std::cout << "CREATE WRAPPED SOLANA TO ZERA LOGGED" << std::endl;
        create_wrapped_solana_to_zera(keys, values, slot, tx_signature);
    }
}
void events::create_wrapped_solana_to_zera(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string &slot, const std::string &tx_signature)
{

    std::string amount;
    std::string solana_mint_id;
    std::string recipient;

    for (size_t i = 0; i < keys.size(); i++)
    {
        auto key = sanitize_string(keys[i]);
        auto value = sanitize_string(values[i]);
        std::cout << key << ": " << value << std::endl;

        if (key == "recipient")
        {
            recipient = value;
        }
        else if (key == "amount")
        {
            amount = value;
        }
        else if (key == "solana_mint_id")
        {
            solana_mint_id = value;
        }
    }

    if (amount.empty() || solana_mint_id.empty() || recipient.empty())
    {
        return;
    }

    MetadataProgram metadata_program;

    
    if (solana_mint_id != SOL_MINT_ID)
    {
        if (metadata::metadata_program(solana_mint_id, metadata_program))
        {
            //get first 5 character of mint id
            std::string mint_id_prefix = solana_mint_id.substr(0, 5);
            metadata_program.symbol = mint_id_prefix;
            metadata_program.name = solana_mint_id;
            metadata_program.decimals = "1000000000";
            metadata_program.uri = "";
            metadata_program.update_authority = "";
        }
    }
    else
    {
        metadata_program.symbol = "SOL";
        metadata_program.name = "SOLANA";
        metadata_program.decimals = "1000000000";
        metadata_program.uri = "";
        metadata_program.update_authority = "";
    }

    zera_guardian::ZeraContractPayload contract_payload;

    contract_payload.set_symbol(metadata_program.symbol);
    contract_payload.set_name(metadata_program.name);
    contract_payload.set_denomination(metadata_program.decimals);
    contract_payload.set_zera_wallet_address(recipient);
    contract_payload.set_amount(amount);
    contract_payload.set_solana_mint_address(solana_mint_id);
    contract_payload.set_uri(metadata_program.uri);
    contract_payload.set_solana_authorized_address(metadata_program.update_authority);

    contract_payload.set_tx_signature(tx_signature);


    std::vector<std::string> hash_strings;
    hash_strings.push_back(contract_payload.symbol());
    hash_strings.push_back(contract_payload.name());
    hash_strings.push_back(contract_payload.denomination());
    hash_strings.push_back(contract_payload.zera_wallet_address());
    hash_strings.push_back(contract_payload.amount());
    hash_strings.push_back(contract_payload.solana_mint_address());
    hash_strings.push_back(contract_payload.uri());
    hash_strings.push_back(contract_payload.solana_authorized_address());
    hash_strings.push_back(tx_signature);

    auto hash = Hashing::hash_strings(hash_strings);
    auto hash_hex = to_hex(hash);

    zera_guardian::ZeraPayload zera_payload;
    zera_payload.set_signed_hash(hash_hex);

    zera_payload.mutable_contract_payload()->CopyFrom(contract_payload);

    payload::process_zera_payload(zera_payload, hash, tx_signature);
}
void events::release_native_zera_to_zera(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string &slot, const std::string &tx_signature)
{

    std::string amount;
    std::string zera_recipient;
    std::string zera_contract_id;

    for (size_t i = 0; i < keys.size(); i++)
    {
        auto key = sanitize_string(keys[i]);
        auto value = sanitize_string(values[i]);
        std::cout << key << ": " << value << std::endl;

        if (key == "amount")
        {
            amount = value;
        }
        else if (key == "recipient")
        {
            zera_recipient = value;
        }
        else if (key == "zera_contract_id")
        {
            zera_contract_id = value;
        }
    }

    if (amount.empty() || zera_recipient.empty() || zera_contract_id.empty())
    {
        return;
    }

    std::string contract_key = ZERA_CONTRACT_KEY;
    //contract_key += "_" + solana_mint_id;


    //std::string contract_id = "$ZRA+0000";

    // TODO maybe store more data about the contract??
    // TODO: add back in!
    //  if(!db_contracts::get_single(contract_key, contract_id))
    //  {
    //      return;
    //  }

    // release zera contract
    zera_guardian::ZeraReleasePayload zera_release_payload;
    zera_release_payload.set_zera_contract_id(zera_contract_id);
    zera_release_payload.set_amount(amount);
    zera_release_payload.set_zera_wallet_address(zera_recipient);
    zera_release_payload.set_tx_signature(tx_signature);
    zera_release_payload.set_zera_contract_id(zera_contract_id);

    std::vector<std::string> hash_strings;
    hash_strings.push_back(zera_release_payload.zera_contract_id());
    hash_strings.push_back(zera_release_payload.amount());
    hash_strings.push_back(zera_release_payload.zera_wallet_address());
    hash_strings.push_back(tx_signature);

    auto hash = Hashing::hash_strings(hash_strings);
    auto hash_hex = to_hex(hash);

    zera_guardian::ZeraPayload zera_payload;
    zera_payload.set_signed_hash(hash_hex);

    zera_payload.mutable_release_payload()->CopyFrom(zera_release_payload);

    payload::process_zera_payload(zera_payload, hash, tx_signature);
}

void events::mint_native_solana_to_zera(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string &slot, const std::string &tx_signature)
{
    std::string amount;
    std::string solana_mint_id;
    std::string recipient;

    for (size_t i = 0; i < keys.size(); i++)
    {
        auto key = sanitize_string(keys[i]);
        auto value = sanitize_string(values[i]);
        std::cout << key << ": " << value << std::endl;

        if (key == "recipient")
        {
            recipient = value;
        }
        else if (key == "amount")
        {
            amount = value;
        }
        else if (key == "solana_mint_id")
        {
            solana_mint_id = value;
        }
    }

    if (amount.empty() || solana_mint_id.empty() || recipient.empty())
    {
        std::cout << "No amount, solana mint id, or recipient found in event data" << std::endl;
        return;
    }

    zera_guardian::ZeraMintPayload mint_payload;

    mint_payload.set_solana_mint_address(solana_mint_id);
    mint_payload.set_amount(amount);
    mint_payload.set_zera_wallet_address(recipient);
    mint_payload.set_tx_signature(tx_signature);

    std::vector<std::string> hash_strings;
    hash_strings.push_back(mint_payload.solana_mint_address());
    hash_strings.push_back(mint_payload.amount());
    hash_strings.push_back(mint_payload.zera_wallet_address());
    hash_strings.push_back(mint_payload.tx_signature());

    auto hash = Hashing::hash_strings(hash_strings);
    auto hash_hex = to_hex(hash);

    zera_guardian::ZeraPayload zera_payload;
    zera_payload.set_signed_hash(hash_hex);

    zera_payload.mutable_mint_payload()->CopyFrom(mint_payload);

    payload::process_zera_payload(zera_payload, hash, tx_signature);
}