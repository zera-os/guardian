#pragma once

#include <iostream>
#include <vector>
#include <string>
#include "txn.pb.h"
#include "validator.pb.h"
#include "zera_api.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/util/time_util.h>
#include <grpcpp/grpcpp.h>
#include "txn.grpc.pb.h"
#include "validator.grpc.pb.h"
#include "zera_api.grpc.pb.h"
#include <thread>
#include <random>


using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using google::protobuf::Empty;



class GrpcClient {
public:
    void ActivityRequest(const zera_api::ActivityRequest& request); 
    static void set_server_address(const std::string& server_address);
    static void SmartContractEventsSearchRequest(const zera_api::SmartContractEventsSearchRequest& request);

    
    private:
    static std::string server_address_;
};