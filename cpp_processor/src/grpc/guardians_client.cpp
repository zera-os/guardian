#include "guardians_client.h"
#include "db_base.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/util/time_util.h>
#include <grpcpp/grpcpp.h>
#include "const.h"
#include "signatures.h"
#include "guardian_config.h"
#include "encoding.h"
#include "payload.h"
#include <algorithm>
#include <thread>
#include <mutex>
#include <unordered_map>

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

    void process_response(const zera_guardian::GuardianPayloadResponse& response)
    {
        // Acquire payload-specific mutex to prevent concurrent modifications
        auto payload_mutex = get_payload_mutex(response.payload_hash());
        std::lock_guard<std::mutex> lock(*payload_mutex);
        
        // Load the main GuardianPayload (with repeated guardians field)
        std::string guardian_payload_string;
        zera_guardian::GuardianPayload guardian_payload;
        if(!db_guardians_payloads::get_single(response.txn_hash(), guardian_payload_string) || 
           !guardian_payload.ParseFromString(guardian_payload_string))
        {
            std::cerr << "Failed to load guardian payload for process_response: " << response.txn_hash() << std::endl;
            return;
        }

        // Verify the guardian is registered
        std::string guardian_auth_string;
        zera_guardian::GuardianAuth guardian_auth;
        if(!db_guardians::get_single(response.zera_key(), guardian_auth_string) || 
           !guardian_auth.ParseFromString(guardian_auth_string))
        {
            std::cerr << "Guardian not registered: " << response.zera_key() << std::endl;
            return;
        }

        // Verify keys match
        if(guardian_auth.zera_key() != response.zera_key() || guardian_auth.solana_key() != response.solana_key())
        {
            std::cerr << "Guardian keys mismatch for: " << response.zera_key() << std::endl;
            return;
        }

        // Verify signature based on payload type
        if(guardian_payload.has_solana_payload())
        {
            if(!signatures::verify_hash(response.payload_hash(), response.signature(), response.solana_key(), false))
            {
                std::cerr << "Invalid Solana signature from guardian: " << response.zera_key() << std::endl;
                return;
            }
        }
        else if(guardian_payload.has_zera_payload())
        {
            if(!signatures::verify_hash(response.payload_hash(), response.signature(), response.zera_key(), true))
            {
                std::cerr << "Invalid Zera signature from guardian: " << response.zera_key() << std::endl;
                return;
            }
        }
        else
        {
            std::cerr << "Guardian payload has no valid payload type" << std::endl;
            return;
        }

        // Check if this guardian already confirmed
        bool already_confirmed = false;
        for(auto& guardian : guardian_payload.guardians()){
            if(guardian.zera_key() == response.zera_key() && guardian.solana_key() == response.solana_key())
            {
                already_confirmed = true;
                break;
            }
        }

        // If not already confirmed, add their confirmation to our list
        if(!already_confirmed){
            zera_guardian::GuardianPayloadResponse* new_guardian = guardian_payload.add_guardians();
            new_guardian->CopyFrom(response);
            
            // Save updated payload
            db_guardians_payloads::store_single(response.txn_hash(), guardian_payload.SerializeAsString());
            
            std::cout << "Added verified confirmation from guardian: " << response.zera_key() << std::endl;
        }
        // Mutex released here automatically when lock_guard goes out of scope

        // Check if we've reached threshold
        if(guardian_payload.guardians().size() >= GuardianConfig::get_threshold()){
            std::vector<zera_guardian::GuardianPayloadResponse> guardian_responses;
            int threshold = GuardianConfig::get_threshold();

            for(auto& guardian : guardian_payload.guardians()){
                guardian_responses.push_back(guardian);
            }
            
            // Sort guardian keys alphabetically by zera_key
            std::sort(guardian_responses.begin(), guardian_responses.end(), 
                [](const zera_guardian::GuardianPayloadResponse& a, const zera_guardian::GuardianPayloadResponse& b){
                    return a.zera_key() < b.zera_key();
                });

            // Create final payload based on type
            if(guardian_payload.has_solana_payload()){
                zera_guardian::SolanaPayload solana_payload;
                solana_payload.CopyFrom(guardian_payload.solana_payload());
                solana_payload.set_signed_hash(response.payload_hash());
                solana_payload.mutable_timestamp()->set_seconds(guardian_payload.timestamp().seconds());
                
                int x = 0;
                for(auto& guardian : guardian_responses){
                    solana_payload.add_signatures(guardian.signature());
                    solana_payload.add_public_keys(guardian.solana_key());
                    x++;
                    if(x >= threshold){
                        break;
                    }
                }

                payload::store_payload(response.txn_hash(), solana_payload);
            }
            else if(guardian_payload.has_zera_payload()){
                zera_guardian::ZeraPayload zera_payload;
                zera_payload.CopyFrom(guardian_payload.zera_payload());
                zera_payload.set_signed_hash(response.payload_hash());

                int x = 0;
                for(auto& guardian : guardian_responses){
                    zera_payload.add_signatures(guardian.signature());
                    zera_payload.add_public_keys(guardian.zera_key());
                    x++;
                    if(x >= threshold){
                        break;
                    }
                }
                payload::store_payload(response.txn_hash(), zera_payload);
            }
        }
    }
}
void GuardiansClient::AuthenticateGuardian(const zera_guardian::GuardianPayloadResponse& my_response)
{

    // Load the guardian payload to determine if it's Solana or Zera
    std::string guardian_payload_string;
    zera_guardian::GuardianPayload guardian_payload;

    if(!db_guardians_payloads::get_single(my_response.txn_hash(), guardian_payload_string) || 
       !guardian_payload.ParseFromString(guardian_payload_string))
    {
        std::cerr << "Failed to load guardian payload for AuthenticateGuardian: " << my_response.txn_hash() << std::endl;
        return;
    }


    // Convert GuardianPayloadResponse to GuardianPayloadRequest
    zera_guardian::GuardianPayloadRequest request;
    request.set_zera_key(my_response.zera_key());
    request.set_solana_key(my_response.solana_key());
    request.set_payload_hash(my_response.payload_hash());
    request.set_signature(my_response.signature());
    request.set_is_solana(guardian_payload.has_solana_payload());
    request.set_txn_hash(my_response.txn_hash());

    std::cout << "payload hash: " << my_response.payload_hash() << std::endl;

    // Get all guardians to contact
    std::string all_guardian_auth_string;
    zera_guardian::AllGuardianAuth all_guardian_auth;
    if(!db_guardians::get_single(ALL_GUARDIAN_AUTH_KEY, all_guardian_auth_string) ||
       !all_guardian_auth.ParseFromString(all_guardian_auth_string))
    {
        std::cerr << "Failed to load guardian list" << std::endl;
        return;
    }

    std::vector<zera_guardian::GuardianAuth> retry_guardians;

    // Contact each guardian
    for(auto& guardian : all_guardian_auth.guardians())
    {
        // Skip ourselves
        if(guardian.zera_key() == request.zera_key())
        {
            continue;
        }

        grpc::ClientContext context;
        zera_guardian::GuardianPayloadResponse response;
        
        std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(
            guardian.host() + ":" + guardian.port(), 
            grpc::InsecureChannelCredentials()
        );
        std::unique_ptr<zera_guardian::GuardianService::Stub> stub(
            zera_guardian::GuardianService::NewStub(channel)
        );
        
        grpc::Status status = stub->AuthenticateGuardian(&context, request, &response);
        if(status.ok())
        {
            std::cout << "Received confirmation from guardian: " << response.zera_key() << std::endl;
            process_response(response);
        }
        else
        {
            std::cout << "host: " << guardian.host() << ":" << guardian.port() << std::endl;
            std::cout << "Failed to contact guardian " << guardian.zera_key() 
                      << " at " << guardian.host() << ":" << guardian.port()
                      << " - Code: " << status.error_code()
                      << " - Message: '" << status.error_message() << "'"
                      << " - Details: '" << status.error_details() << "'" << std::endl;
            retry_guardians.push_back(guardian);
        }
    }

    // Retry failed guardians with exponential backoff
    if(!retry_guardians.empty())
    {
        // First check if threshold already reached before starting retries
        std::string check_payload_string;
        zera_guardian::GuardianPayload check_payload;
        if(db_guardians_payloads::get_single(my_response.txn_hash(), check_payload_string) && 
           check_payload.ParseFromString(check_payload_string) &&
           check_payload.guardians().size() >= GuardianConfig::get_threshold())
        {
            std::cout << "Threshold already reached (" << check_payload.guardians().size() << "/" 
                      << GuardianConfig::get_threshold() << "), skipping retries entirely" << std::endl;
            return;
        }
        
        std::cout << "Retrying " << retry_guardians.size() << " failed guardians..." << std::endl;
        
        for(int retry_attempt = 0; retry_attempt < 3; retry_attempt++)
        {
            if(retry_guardians.empty()) break;
            
            // Exponential backoff: 200ms, 400ms, 800ms
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * (1 << retry_attempt)));
            
            // Reload the payload to check if guardians confirmed via reverse path
            std::string updated_payload_string;
            zera_guardian::GuardianPayload updated_payload;
            if(db_guardians_payloads::get_single(my_response.txn_hash(), updated_payload_string) && 
               updated_payload.ParseFromString(updated_payload_string))
            {
                // Check if we've already reached threshold - no need to continue retrying
                if(updated_payload.guardians().size() >= GuardianConfig::get_threshold())
                {
                    std::cout << "Threshold reached (" << updated_payload.guardians().size() << "/" 
                              << GuardianConfig::get_threshold() << "), stopping retries" << std::endl;
                    break;
                }
                
                std::vector<zera_guardian::GuardianAuth> still_failing;
                
                for(auto& guardian : retry_guardians)
                {
                    // Check if this guardian already confirmed (they called us instead)
                    bool already_confirmed = false;
                    for(auto& confirmed_guardian : updated_payload.guardians())
                    {
                        if(confirmed_guardian.zera_key() == guardian.zera_key() && 
                           confirmed_guardian.solana_key() == guardian.solana_key())
                        {
                            already_confirmed = true;
                            std::cout << "Guardian " << guardian.zera_key() << " already confirmed via reverse path, skipping retry" << std::endl;
                            break;
                        }
                    }
                    
                    // Skip retry if already confirmed
                    if(already_confirmed) continue;
                    
                    // Try to contact guardian again
                    grpc::ClientContext context;
                    zera_guardian::GuardianPayloadResponse response;
                    
                    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(
                        guardian.host() + ":" + guardian.port(), 
                        grpc::InsecureChannelCredentials()
                    );
                    std::unique_ptr<zera_guardian::GuardianService::Stub> stub(
                        zera_guardian::GuardianService::NewStub(channel)
                    );
                    
                    grpc::Status status = stub->AuthenticateGuardian(&context, request, &response);
                    if(status.ok())
                    {
                        std::cout << "Retry successful for guardian: " << response.zera_key() << std::endl;
                        process_response(response);
                    }
                    else
                    {
                        still_failing.push_back(guardian);
                    }
                }
                
                retry_guardians = still_failing;
            }
            else
            {
                std::cerr << "Failed to reload guardian payload during retry" << std::endl;
                break;
            }
        }
        
        if(!retry_guardians.empty())
        {
            std::cerr << "Permanently failed to contact " << retry_guardians.size() << " guardians after retries" << std::endl;
        }
    }
}