#include "grpc_client.h"
#include "events.h"

std::string GrpcClient::server_address_ = "";

namespace{
    void process_events(const zera_api::SmartContractEventsSearchResponse& response)
    {
        for(auto& event : response.events())
        {
            events::process_zera_events(&event);
        }
        
    }
}
void GrpcClient::ActivityRequest(const zera_api::ActivityRequest& request)
{
    ClientContext context;
    std::shared_ptr<Channel> channel = grpc::CreateChannel(server_address_, grpc::InsecureChannelCredentials());

    std::unique_ptr<zera_api::APIService::Stub> stub(zera_api::APIService::NewStub(channel));

    Empty response;

    // Make the RPC call
    Status status = stub->SmartContractActivityRequest(&context, request, &response);

    // Check if the RPC call was successful
    if (status.ok()) {
        std::cout << "Smart Contract Activity Request RPC call succeeded" << std::endl;
    }
    else {
        std::cout << "Smart Contract Activity Request RPC call failed" << std::endl;
        std::cout << status.error_message() << std::endl;
    }
}

void GrpcClient::set_server_address(const std::string& server_address)
{
    server_address_ = server_address;
}

void GrpcClient::SmartContractEventsSearchRequest(const zera_api::SmartContractEventsSearchRequest& request)
{
    ClientContext context;

    std::shared_ptr<Channel> channel = grpc::CreateChannel(server_address_, grpc::InsecureChannelCredentials());

    std::unique_ptr<zera_api::APIService::Stub> stub(zera_api::APIService::NewStub(channel));

    zera_api::SmartContractEventsSearchResponse response;

    Status status = stub->SmartContractEventsSearch(&context, request, &response);

    if(status.ok())
    {
        std::cout << "Smart Contract Events Search RPC call succeeded" << std::endl;
        process_events(response);
    }
    else
    {
        std::cout << "Smart Contract Events Search RPC call failed" << std::endl;
        std::cout << status.error_message() << std::endl;
    }
}
