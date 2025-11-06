#pragma once

// Standard Library
#include <random>
#include <thread>

// Third-party Libraries
#include <google/protobuf/empty.pb.h>
#include <google/protobuf/timestamp.pb.h>
#include <grpcpp/grpcpp.h>

#include "zera_api.pb.h"
#include "zera_api.grpc.pb.h"
#include "guardian.pb.h"
#include "guardian.grpc.pb.h"
#include "encoding.h"
#include "wallets.h"

class APIImpl final : public zera_api::APIService::Service
{
public:
    grpc::Status SmartContractEvents(grpc::ServerContext *context, const zera_api::SmartContractEventsResponse *request, google::protobuf::Empty *response);


    void StartService(const std::string &port = "50053")
    {
        grpc::ServerBuilder builder;
        std::string listening = "0.0.0.0:" + port;

        builder.AddListeningPort(listening, grpc::InsecureServerCredentials());
        builder.RegisterService(this);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        server->Wait();
    }

    private:
        static void ProcessSmartContractEvents(const zera_api::SmartContractEventsResponse *request);
};

class GuardianImpl final : public zera_guardian::GuardianService::Service {
    public:
    grpc::Status GetPayload(grpc::ServerContext *context, const zera_guardian::PayloadRequest *request, zera_guardian::PayloadResponse *response);
    grpc::Status SearchPayload(grpc::ServerContext *context, const zera_guardian::SearchPayloadRequest *request, zera_guardian::SearchPayloadResponse *response);
    grpc::Status AuthenticateGuardian(grpc::ServerContext *context, const zera_guardian::GuardianPayloadRequest *request, zera_guardian::GuardianPayloadResponse *response);
    
    void StartService(const std::string &port = "50054")
    {
        grpc::ServerBuilder builder;
        std::string listening = "0.0.0.0:" + port;
        builder.AddListeningPort(listening, grpc::InsecureServerCredentials());
        builder.RegisterService(this);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        server->Wait();
    }
};
