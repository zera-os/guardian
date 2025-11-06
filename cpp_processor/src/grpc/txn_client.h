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
#include "txn.grpc.pb.h"
#include "txn.pb.h"
#include <thread>
#include <random>

using google::protobuf::Empty;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

class TXNClient
{
public:
    void SmartContractExecute(const zera_txn::SmartContractExecuteTXN &request);
    static uint64_t GetNonce(const zera_txn::PublicKey &public_key);
    static zera_txn::InstrumentContract GetContract(const std::string& contract_id);
    static void set_server_address(const std::string& server_address);
    static void set_api_server_address(const std::string& server_address);

private:
    static std::string server_address_;
    static std::string api_server_address_;
};