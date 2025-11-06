#include "payload.h"

#include "signatures.h"
#include "guardian_config.h"
#include "db_base.h"
#include "encoding.h"
#include "const.h"
#include "guardians_client.h"

#include "google/protobuf/util/time_util.h"
namespace
{

    void store_guardian_payload(const std::string &txn_hash, zera_guardian::SolanaPayload &payload)
    {
        if(db_guardians_payloads::exist(txn_hash))
        {
            std::cout << "Guardian Solana payload already exists" << std::endl;
            return;
        }

        zera_guardian::GuardianPayload guardian_payload;
        guardian_payload.mutable_solana_payload()->CopyFrom(payload);
        guardian_payload.set_payload_hash(payload.signed_hash());
        guardian_payload.mutable_timestamp()->set_seconds(payload.timestamp().seconds());

        zera_guardian::GuardianPayloadResponse guardian_payload_response;
        guardian_payload_response.set_zera_key(GuardianConfig::get_public_key_b58());
        guardian_payload_response.set_solana_key(GuardianConfig::get_solana_public_key_b58());
        guardian_payload_response.set_payload_hash(payload.signed_hash());
        guardian_payload_response.set_signature(payload.signatures(0));
        guardian_payload_response.set_txn_hash(txn_hash);
        guardian_payload.add_guardians()->CopyFrom(guardian_payload_response);

        db_guardians_payloads::store_single(txn_hash, guardian_payload.SerializeAsString());
        db_guardians_payloads::store_single(txn_hash + "_OWN", guardian_payload_response.SerializeAsString());

        std::cout << "Authenticating guardian: " << GuardianConfig::get_public_key_b58() << " for payload: " << txn_hash << std::endl;
        GuardiansClient::AuthenticateGuardian(guardian_payload_response);
    }

    void store_guardian_payload(const std::string &txn_signature, zera_guardian::ZeraPayload &payload)
    {

        if(db_guardians_payloads::exist(txn_signature))
        {
            std::cout << "Guardian Zera payload already exists" << std::endl;
            return;
        }

        zera_guardian::GuardianPayload guardian_payload;
        guardian_payload.mutable_zera_payload()->CopyFrom(payload);
        guardian_payload.set_payload_hash(payload.signed_hash());

        zera_guardian::GuardianPayloadResponse guardian_payload_response;
        guardian_payload_response.set_zera_key(GuardianConfig::get_public_key_b58());
        guardian_payload_response.set_solana_key(GuardianConfig::get_solana_public_key_b58());
        guardian_payload_response.set_payload_hash(payload.signed_hash());
        guardian_payload_response.set_signature(payload.signatures(0));
        guardian_payload_response.set_txn_hash(txn_signature);
        guardian_payload.add_guardians()->CopyFrom(guardian_payload_response);

        db_guardians_payloads::store_single(txn_signature, guardian_payload.SerializeAsString());
        db_guardians_payloads::store_single(txn_signature + "_OWN", guardian_payload_response.SerializeAsString());

        std::cout << "Authenticating guardian: " << GuardianConfig::get_public_key_b58() << " for payload: " << txn_signature << std::endl;
        GuardiansClient::AuthenticateGuardian(guardian_payload_response);
    }
}

    void payload::store_payload(const std::string &txn_hash, zera_guardian::SolanaPayload &payload)
    {

        // store payload with txn_hash as key
        db_payloads::store_single(txn_hash, payload.SerializeAsString());

        // make an index of this payload based on timestamp
        zera_guardian::ManageBridgePayload manage_bridge_payload;
        google::protobuf::Timestamp timestamp_proto = google::protobuf::util::TimeUtil::GetCurrentTime();
        std::string manage_bridge_payload_string;
        db_payloads::get_single(MANAGE_BRIDGE_PAYLOAD_KEY, manage_bridge_payload_string);
        manage_bridge_payload.ParseFromString(manage_bridge_payload_string);

        // remove payloads that are older than 3 days
        // TODO: keep all payloads for now - just in case of a catastrophe
        //  for(auto& man_payload : manage_bridge_payload.bridge_payloads()){
        //      if(timestamp_proto.seconds() > (man_payload.second.seconds() + 259200)){
        //          manage_bridge_payload.mutable_bridge_payloads()->erase(man_payload.first);
        //      }
        //  }

        manage_bridge_payload.mutable_bridge_payloads()->insert({txn_hash, timestamp_proto});
        db_payloads::store_single(MANAGE_BRIDGE_PAYLOAD_KEY, manage_bridge_payload.SerializeAsString());
    }

    void payload::store_payload(const std::string &tx_signature, zera_guardian::ZeraPayload &payload)
    {

        // store payload with txn_hash as key
        db_payloads::store_single(tx_signature, payload.SerializeAsString());

        // make an index of this payload based on timestamp
        zera_guardian::ManageBridgePayload manage_bridge_payload;
        google::protobuf::Timestamp timestamp_proto = google::protobuf::util::TimeUtil::GetCurrentTime();
        std::string manage_bridge_payload_string;
        db_payloads::get_single(MANAGE_BRIDGE_PAYLOAD_KEY, manage_bridge_payload_string);
        manage_bridge_payload.ParseFromString(manage_bridge_payload_string);

        // remove payloads that are older than 3 days
        // TODO: keep all payloads for now - just in case of a catastrophe
        //  for(auto& man_payload : manage_bridge_payload.bridge_payloads()){
        //      if(timestamp_proto.seconds() > (man_payload.second.seconds() + 259200)){
        //          manage_bridge_payload.mutable_bridge_payloads()->erase(man_payload.first);
        //      }
        //  }

        manage_bridge_payload.mutable_bridge_payloads()->insert({tx_signature, timestamp_proto});
        db_payloads::store_single(MANAGE_BRIDGE_PAYLOAD_KEY, manage_bridge_payload.SerializeAsString());
    }
void payload::process_solana_payload(zera_guardian::SolanaPayload &payload, std::vector<uint8_t> &hash, const std::string &txn_hash, const uint64_t timestamp)
{

    auto signature = signatures::sign_hash(hash, GuardianConfig::get_key_pair());

    std::cout << "Setting timestamp: " << timestamp << std::endl;
    payload.mutable_timestamp()->set_seconds(timestamp);

    std::string signature_b58 = base58_encode(signature);
    auto payload_copy = payload; // make a mutable copy
    payload_copy.add_signatures(signature_b58);
    payload_copy.add_public_keys(GuardianConfig::get_solana_public_key_b58());

    std::string test_pub = "A_c_9aZ6ZymbUETdA9neSnLjvjj9iD8SqHfKo8L9QFtv1PGJ";
    std::string test_priv = "TW2VE33nQ5hag4UTC4ue1GHgMyj1cY7eBHmVEAueM6ggv3jg5Tc65jukcyQUZT8M2AenxhQmxy6bApGp7vvhAu4";
    KeyPair test_key_pair;
    test_key_pair.public_key = base58_decode_public_key(test_pub);
    test_key_pair.private_key = base58_decode(test_priv);

    // auto test_signature = signatures::sign_hash(hash, test_key_pair);
    // std::string test_signature_b58 = base58_encode(test_signature);
    // payload_copy.add_signatures(test_signature_b58);
    // std::string test_solana_pub = "9aZ6ZymbUETdA9neSnLjvjj9iD8SqHfKo8L9QFtv1PGJ";
    // payload_copy.add_public_keys(test_solana_pub);

    if (GuardianConfig::get_number_of_guardians() == 1)
    {

        store_payload(txn_hash, payload_copy);
    }
    else
    {
        std::cout << "Processing solana payload guardian 2" << std::endl;
        store_guardian_payload(txn_hash, payload_copy);
    }
}

void payload::process_zera_payload(zera_guardian::ZeraPayload &payload, std::vector<uint8_t> &hash, const std::string &tx_signature)
{

    auto signature = signatures::sign_hash(hash, GuardianConfig::get_key_pair());
    std::string signature_b58 = base58_encode(signature);
    auto payload_copy = payload; // make a mutable copy
    payload_copy.add_signatures(signature_b58);
    payload_copy.add_public_keys(GuardianConfig::get_public_key_b58());

    std::string test_pub = "A_c_9aZ6ZymbUETdA9neSnLjvjj9iD8SqHfKo8L9QFtv1PGJ";
    std::string test_priv = "TW2VE33nQ5hag4UTC4ue1GHgMyj1cY7eBHmVEAueM6ggv3jg5Tc65jukcyQUZT8M2AenxhQmxy6bApGp7vvhAu4";

    KeyPair test_key_pair;
    test_key_pair.public_key = base58_decode_public_key(test_pub);
    test_key_pair.private_key = base58_decode(test_priv);

    // auto test_signature = signatures::sign_hash(hash, test_key_pair);
    // std::string test_signature_b58 = base58_encode(test_signature);
    // payload_copy.add_signatures(test_signature_b58);
    // payload_copy.add_public_keys(test_pub);

    if (GuardianConfig::get_number_of_guardians() == 1)
    {

        store_payload(tx_signature, payload_copy);
    }
    else
    {
        store_guardian_payload(tx_signature, payload_copy);
    }
}