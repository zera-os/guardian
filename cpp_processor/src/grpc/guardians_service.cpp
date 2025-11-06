#include "grpc_service.h"
#include "db_base.h"
#include "signatures.h"
#include <algorithm>
#include <mutex>
#include <unordered_map>
#include "guardian_config.h"
#include "payload.h"

namespace
{
    // Mutex map to protect concurrent modifications to the same payload
    static std::mutex map_mutex;
    static std::unordered_map<std::string, std::shared_ptr<std::mutex>> payload_mutexes;
    
    std::shared_ptr<std::mutex> get_payload_mutex(const std::string& payload_hash)
    {
        std::lock_guard<std::mutex> lock(map_mutex);
        auto it = payload_mutexes.find(payload_hash);
        if(it == payload_mutexes.end())
        {
            auto new_mutex = std::make_shared<std::mutex>();
            payload_mutexes[payload_hash] = new_mutex;
            return new_mutex;
        }
        return it->second;
    }
}

grpc::Status GuardianImpl::AuthenticateGuardian(grpc::ServerContext *context, const zera_guardian::GuardianPayloadRequest *request, zera_guardian::GuardianPayloadResponse *response)
{
    try {
        std::cout << "🔐 AuthenticateGuardian called from: " << request->zera_key() << " for payload: " << request->payload_hash() << std::endl;
        
        std::string guardian_auth_string;
        zera_guardian::GuardianAuth guardian_auth;
        //Does guardian exist?
        if(!db_guardians::get_single(request->zera_key(), guardian_auth_string) || !guardian_auth.ParseFromString(guardian_auth_string))
        {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "Guardian not found");
        }

        if(guardian_auth.zera_key() != request->zera_key() || guardian_auth.solana_key() != request->solana_key()){
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Guardian not found");
        }

        std::string guardian_payload_string;
        zera_guardian::GuardianPayload guardian_payload;
        //Does payload exist?
        if(!db_guardians_payloads::get_single(request->txn_hash(), guardian_payload_string) || !guardian_payload.ParseFromString(guardian_payload_string))
        {
            std::cout << "❌ Guardian payload not found: AuthenticateGuardian 1" << request->txn_hash() << std::endl;
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "Guardian payload not found");
        }
        std::string guardian_payload_own_string;
    zera_guardian::GuardianPayloadResponse guardian_payload_own;
    //Have I made my own copy of the payload?
    if(!db_guardians_payloads::get_single(request->txn_hash() + "_OWN", guardian_payload_own_string) || !guardian_payload_own.ParseFromString(guardian_payload_own_string))
    {
        std::cout << "Guardian payload own not found: " << request->payload_hash() + "_OWN" << std::endl;
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Guardian payload own not found");
    }

    //Is the payload a solana payload?
    //verify hash and signature
    if(request->is_solana()){
        if(!signatures::verify_hash(request->payload_hash(), request->signature(), request->solana_key(), false))
        {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid signature");
        }
        if(!guardian_payload.has_solana_payload() || guardian_payload.has_zera_payload()){
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Guardian payload is not a solana payload");
        }
    }
    else{
        if(!signatures::verify_hash(request->payload_hash(), request->signature(), request->zera_key(), true))
        {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid signature");
        }
        if(!guardian_payload.has_zera_payload() || guardian_payload.has_solana_payload()){
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Guardian payload is not a zera payload");
        }
    }

    //Copy my own payload to the response
    response->CopyFrom(guardian_payload_own);

    if(db_payloads::exist(request->payload_hash())){
        return grpc::Status::OK;
    }

    // Acquire payload-specific mutex to prevent concurrent modifications
    {
        auto payload_mutex = get_payload_mutex(request->payload_hash());
        std::lock_guard<std::mutex> lock(*payload_mutex);
        // Reload payload inside the lock to get latest state
        if(!db_guardians_payloads::get_single(request->txn_hash(), guardian_payload_string) || 
           !guardian_payload.ParseFromString(guardian_payload_string))
        {
            std::cout << "❌ Guardian payload not found: AuthenticateGuardian" << request->txn_hash() << std::endl;
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "Guardian payload not found");
        }
        bool already_confirmed = false;
        //Have they already confirmed this payload?
        for(auto &guardian : guardian_payload.guardians()){
            if(guardian.zera_key() == request->zera_key() && guardian.solana_key() == request->solana_key())
            {
                already_confirmed = true;
                break;
            }
        }
        //If I haven't confirmed this payload, add it to main payload and not my own copy
        if(!already_confirmed){
            zera_guardian::GuardianPayloadResponse guardian_payload_response;
            guardian_payload_response.set_zera_key(request->zera_key());
            guardian_payload_response.set_solana_key(request->solana_key());
            guardian_payload_response.set_payload_hash(request->payload_hash());
            guardian_payload_response.set_txn_hash(request->txn_hash());
            guardian_payload_response.set_signature(request->signature());
            guardian_payload.add_guardians()->CopyFrom(guardian_payload_response);
            db_guardians_payloads::store_single(request->txn_hash(), guardian_payload.SerializeAsString());
        }
    } // Mutex released here

    //if we have threshold number of guardians, we can store the payload for relayers
    if(guardian_payload.guardians().size() >= GuardianConfig::get_threshold()){
        std::vector<zera_guardian::GuardianPayloadResponse> guardian_responses;
        int threshold = GuardianConfig::get_threshold();
        for(auto& guardian : guardian_payload.guardians()){
            guardian_responses.push_back(guardian);
        }
        // Sort guardian keys alphabetically by zera_key
        std::sort(guardian_responses.begin(), guardian_responses.end(), [](const zera_guardian::GuardianPayloadResponse& a, const zera_guardian::GuardianPayloadResponse& b){
            return a.zera_key() < b.zera_key();
        });
        if(request->is_solana()){

            zera_guardian::SolanaPayload solana_payload;
            solana_payload.CopyFrom(guardian_payload.solana_payload());
            solana_payload.set_signed_hash(request->payload_hash());
            int x = 0;
            for(auto& guardian : guardian_responses){
                solana_payload.add_signatures(guardian.signature());
                solana_payload.add_public_keys(guardian.solana_key());
                x++;
                if(x >= threshold){
                    break;
                }
            }
            payload::store_payload(request->txn_hash(), solana_payload);

        }
        else{
            zera_guardian::ZeraPayload zera_payload;
            zera_payload.CopyFrom(guardian_payload.zera_payload());
            zera_payload.set_signed_hash(request->payload_hash());
            int x = 0;
            for(auto& guardian : guardian_responses){
                zera_payload.add_signatures(guardian.signature());
                zera_payload.add_public_keys(guardian.zera_key());
                x++;
                if(x >= threshold){
                    break;
                }
            }
            payload::store_payload(request->txn_hash(), zera_payload);
        }
    }

        std::cout << "✅ AuthenticateGuardian completed successfully" << std::endl;
        return grpc::Status::OK;
        
    } catch (const std::exception& e) {
        std::cerr << "💥 EXCEPTION in AuthenticateGuardian: " << e.what() << std::endl;
        return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Exception: ") + e.what());
    } catch (...) {
        std::cerr << "💥 UNKNOWN EXCEPTION in AuthenticateGuardian" << std::endl;
        return grpc::Status(grpc::StatusCode::INTERNAL, "Unknown exception");
    }
}