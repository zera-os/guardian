

#include "grpc_service.h"
#include "signatures.h"
#include "threadpool.h"
#include "events.h"
#include "const.h"
#include "db_base.h"

grpc::Status APIImpl::SmartContractEvents(grpc::ServerContext *context, const zera_api::SmartContractEventsResponse *request, google::protobuf::Empty *response)
{
    zera_api::SmartContractEventsResponse *request_copy = new zera_api::SmartContractEventsResponse();
    request_copy->CopyFrom(*request);

    ThreadPool::enqueueTask([request_copy](){ 
        APIImpl::ProcessSmartContractEvents(request_copy);
        delete request_copy;
    });

    return grpc::Status::OK;
}


void APIImpl::ProcessSmartContractEvents(const zera_api::SmartContractEventsResponse *request)
{
    if(!signatures::verify_activity_response(request))
    {
        return;
    }

    std::cout << "Smart Contract Events received:\n" << request->DebugString() << std::endl;
    
    events::process_zera_events(request);
}

grpc::Status GuardianImpl::GetPayload(grpc::ServerContext *context, const zera_guardian::PayloadRequest *request, zera_guardian::PayloadResponse *response)
{
    // std::string payload_hash = request->payload_id();
    // zera_guardian::PayloadResponse *response = new zera_guardian::PayloadResponse();
    // ThreadPool::enqueueTask([request, response](){ 
    //     GuardianImpl::GetPayload(request, response);
    //     delete response;
    // });
    return grpc::Status::OK;

}

grpc::Status GuardianImpl::SearchPayload(grpc::ServerContext *context, const zera_guardian::SearchPayloadRequest *request, zera_guardian::SearchPayloadResponse *response)
{
    
    uint64_t timestamp = request->search_start_time().seconds();
    std::string manage_bridge_payload_string;
    db_payloads::get_single(MANAGE_BRIDGE_PAYLOAD_KEY, manage_bridge_payload_string);
    zera_guardian::ManageBridgePayload manage_bridge_payload;
    manage_bridge_payload.ParseFromString(manage_bridge_payload_string);

    for(auto& man_payload : manage_bridge_payload.bridge_payloads()){
        if(man_payload.second.seconds() > timestamp){
            std::string bridge_payload_string;
            db_payloads::get_single(man_payload.first, bridge_payload_string);

            zera_guardian::SolanaPayload solana_payload;

            if(solana_payload.ParseFromString(bridge_payload_string)){
                response->add_solana_payloads()->CopyFrom(solana_payload);
            }
            else{
                zera_guardian::ZeraPayload zera_payload;
                if(zera_payload.ParseFromString(bridge_payload_string)){
                    response->add_zera_payloads()->CopyFrom(zera_payload);
                }
            }
        }
    }

    return grpc::Status::OK;
}
