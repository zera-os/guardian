#include "txn_client.h"

#include "wallets.h"
#include "encoding.h"
#include "guardian_config.h"

std::string TXNClient::server_address_ = "";
std::string TXNClient::api_server_address_ = "";

void TXNClient::SmartContractExecute(const zera_txn::SmartContractExecuteTXN &request)
{
    Empty response;
    ClientContext context;
    std::shared_ptr<Channel> channel = grpc::CreateChannel(server_address_, grpc::InsecureChannelCredentials());
    std::unique_ptr<zera_txn::TXNService::Stub> stub(zera_txn::TXNService::NewStub(channel));

    // Make the RPC call
    Status status = stub->SmartContractExecute(&context, request, &response);

    // Check if the RPC call was successful
    if (status.ok())
    {
        std::cout << "Smart contract execute RPC call succeeded" << std::endl;
    }
    else
    {
        std::cout << "Smart contract execute RPC call failed: " << status.error_code() << ": " << status.error_message() << std::endl;
    }
}

uint64_t TXNClient::GetNonce(const zera_txn::PublicKey &public_key)
{

    uint64_t nonce = 0;
    zera_api::NonceRequest request;
    zera_api::NonceResponse response;

    std::string wallet = wallets::generate_wallet(public_key);
    request.set_encoded(false);
    request.set_wallet_address(wallet);

    ClientContext context;
    std::shared_ptr<Channel> channel = grpc::CreateChannel(api_server_address_, grpc::InsecureChannelCredentials());
    std::unique_ptr<zera_api::APIService::Stub> stub(zera_api::APIService::NewStub(channel));
    Status status = stub->Nonce(&context, request, &response);
    if (status.ok())
    {
        std::cout << "Nonce RPC call succeeded" << std::endl;
    }
    else
    {
        std::cout << "Nonce RPC call failed: " << status.error_code() << ": " << status.error_message() << std::endl;
        return nonce;
    }

    nonce = response.nonce();
    nonce++;

    return nonce;
}

void TXNClient::set_server_address(const std::string &server_address)
{
    std::cout << "Setting server address: " << server_address << std::endl;
    server_address_ = server_address;
}

void TXNClient::set_api_server_address(const std::string& server_address)
{
    api_server_address_ = server_address;
}

zera_txn::InstrumentContract TXNClient::GetContract(const std::string& contract_id)
{
    zera_api::ContractRequest request;
    zera_api::ContractResponse response;

    request.set_contract_id(contract_id);

    ClientContext context;
    std::shared_ptr<Channel> channel = grpc::CreateChannel(api_server_address_, grpc::InsecureChannelCredentials());
    std::unique_ptr<zera_api::APIService::Stub> stub(zera_api::APIService::NewStub(channel));
    Status status = stub->Contract(&context, request, &response);

    if(status.ok())
    {

        std::string trusted_zera_public_key_b58 = GuardianConfig::get_trusted_zera_public_key_b58();
        std::string contract_response_public_key_b58 = base58_encode_public_key(response.public_key().single());
        

        if(contract_response_public_key_b58 != trusted_zera_public_key_b58)
        {
            std::cout << "Contract response is not valid 1" << std::endl;
            return zera_txn::InstrumentContract();
        }

        if(signatures::verify_contract_response(&response))
        {
            return response.contract();
        }
        else
        {
            std::cout << "Contract response is not valid 2" << std::endl;
            return zera_txn::InstrumentContract();
        }
        return response.contract();
    }
    else
    {
        std::cout << "Contract RPC call failed: " << status.error_code() << ": " << status.error_message() << std::endl;
        return zera_txn::InstrumentContract();
    }
}