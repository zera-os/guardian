#include <dlfcn.h>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <array>

#include "encoding.h"
#include "grpc_client.h"
#include "signatures.h"
#include "grpc_service.h"
#include "threadpool.h"
#include "db_base.h"
#include "events.h"
#include "threadpool.h"
#include "encoding.h"
#include "guardian_config.h"
#include "grpc/txn_client.h"
#include "solana_subscriber.h"
#include "const.h"
#include "metadata_program.h"
#include "guardian.pb.h"

#include "google/protobuf/util/time_util.h"

extern "C" unsigned int start_solana_logs_subscription(const char *, const char *, void (*)(const char *, uint64_t, const char *));
extern "C" void stop_solana_logs_subscription(unsigned int);
extern "C" bool backfill_past_events(const char *http_url, const char *program_id, void (*)(const char *, uint64_t, const char *));

// dynamic load only

static std::atomic<bool> g_should_stop{false};

void send_sc_request()
{
    GrpcClient::set_server_address(std::getenv("TRUSTED_VALIDATOR_HOST"));
    GrpcClient client;
    zera_api::ActivityRequest request;
    std::vector<uint8_t> private_key = base58_decode(std::getenv("PRIVATE_KEY"));
    std::vector<uint8_t> public_key_vec = base58_decode_public_key(std::getenv("PUBLIC_KEY"));
    std::string public_key(public_key_vec.begin(), public_key_vec.end());
    KeyPair key_pair;
    key_pair.public_key = public_key_vec;
    key_pair.private_key = private_key;

    uint64_t nonce = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    request.set_host(std::getenv("HOST"));
    request.set_port(std::stoi(std::getenv("PORT")));
    request.set_subscribe(true);
    request.set_smart_contract_id(std::getenv("SMART_CONTRACT_ID"));
    request.set_instance(std::stoi(std::getenv("INSTANCE")));
    request.set_level(zera_api::CONFIRMATION_LEVEL_MAX);

    request.set_nonce(nonce);
    request.mutable_public_key()->set_single(public_key);

    signatures::sign_activity_request(request, key_pair);

    client.ActivityRequest(request);
}

void RunGrpcService()
{
    ThreadPool::setNumThreads();
    APIImpl service;
    service.StartService("50054");
}

void RunGuardianGrpcService()
{
    GuardianImpl service;
    service.StartService("50055");
}

void config_program()
{
    const char * txn_host = std::getenv("TRUSTED_VALIDATOR_TXN_HOST");
    //make string for host its only the host not the port
    std::string host = "";
    if(txn_host){
        host = std::string(txn_host);
    }
    TXNClient::set_server_address(host + ":50052");
    TXNClient::set_api_server_address(host + ":50053");
    open_dbs();

    const char *reset = std::getenv("DATABASE_RESET");

    if (reset && std::string(reset) == "true")
    {
        reset_dbs();
    }
    zera_guardian::AllGuardianAuth all_guardian_auth;
    zera_guardian::GuardianAuth *auth = all_guardian_auth.add_guardians();

    auth->set_zera_key("A_c_C68BgMJks69fsn5yr4cKNnYuw9yztW3vBNyk4hCyr3iE");
    auth->set_solana_key("C68BgMJks69fsn5yr4cKNnYuw9yztW3vBNyk4hCyr3iE");
    auth->set_host("64.23.237.183");
    auth->set_port("50055");

    zera_guardian::GuardianAuth *auth1 = all_guardian_auth.add_guardians();

    auth1->set_zera_key("A_c_B1NgczXgVbJjJLUdbHkQ5xe6fxnzvzQk7MP7o6JqK3dp");
    auth1->set_solana_key("B1NgczXgVbJjJLUdbHkQ5xe6fxnzvzQk7MP7o6JqK3dp");
    auth1->set_host("194.182.188.19");
    auth1->set_port("50055");

    zera_guardian::GuardianAuth *auth2 = all_guardian_auth.add_guardians();

    auth2->set_zera_key("A_c_9aZ6ZymbUETdA9neSnLjvjj9iD8SqHfKo8L9QFtv1PGJ");
    auth2->set_solana_key("9aZ6ZymbUETdA9neSnLjvjj9iD8SqHfKo8L9QFtv1PGJ");
    auth2->set_host("194.182.163.71");
    auth2->set_port("50055");

    all_guardian_auth.set_threshold(2);
    
    db_guardians::store_single(auth->zera_key(), auth->SerializeAsString());
    db_guardians::store_single(auth1->zera_key(), auth1->SerializeAsString());
    db_guardians::store_single(auth2->zera_key(), auth2->SerializeAsString());
    db_guardians::store_single(ALL_GUARDIAN_AUTH_KEY, all_guardian_auth.SerializeAsString());

    GuardianConfig::set_config();
    GuardianConfig::set_threshold(all_guardian_auth.threshold());
    GuardianConfig::set_number_of_guardians(all_guardian_auth.guardians_size());
    GuardianConfig::set_guardian_index(0);

    send_sc_request();
}

extern "C" void on_log_callback(const char *signature, uint64_t slot, const char *logs_json)
{
    solana_subscriber::parse_and_process_program_data(signature, slot, logs_json);
}

static void handle_signal(int)
{
    g_should_stop.store(true);
}

int main()
{
    config_program();

    std::thread thread1(RunGrpcService);

    std::thread thread2(RunGuardianGrpcService);

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    const char *zera_search_time = std::getenv("ZERA_SEARCH_TIME");  
    if (!zera_search_time || std::atoi(zera_search_time) == 0)
    {
        // Skip - either doesn't exist or is 0
        std::cout << "ZERA_SEARCH_TIME not set or 0, skipping..." << std::endl;
    }
    else{
        auto search_time = std::atoi(zera_search_time);
        zera_api::SmartContractEventsSearchRequest request;
        request.set_smart_contract_id("bridge_proxy_1");
        request.mutable_search_start()->set_seconds(search_time);
        GrpcClient::SmartContractEventsSearchRequest(request);
    }

    const char *ws_url = std::getenv("WS_URL");
    if (!ws_url || std::strlen(ws_url) == 0)
    {
        ws_url = "wss://api.mainnet-beta.solana.com/";
    }
    std::cout << "WS_URL: " << ws_url << std::endl;

    const char *program_id = std::getenv("SOLANA_PROGRAM_ID");

    if (!program_id || std::strlen(program_id) == 0)
    {
        std::cerr << "ERROR: SOLANA_PROGRAM_ID env var is required" << std::endl;
        return 2;
    }
    std::cout << "SOLANA_PROGRAM_ID: " << program_id << std::endl;

    // Get HTTP URL for backfill
    const char *http_url = std::getenv("HTTP_URL");
    if (!http_url || std::strlen(http_url) == 0)
    {
        http_url = "https://api.mainnet-beta.solana.com/";
    }
    std::cout << "HTTP_URL: " << http_url << std::endl;

    // Call backfill function - only runs if BACKFILL_ENABLED=true
    std::cout << "Checking for past events..." << std::endl;
    bool backfilled = backfill_past_events(http_url, program_id, on_log_callback);
    if (backfilled)
    {
        std::cout << "Past events backfill completed" << std::endl;
    }
    else
    {
        std::cout << "Past events backfill skipped or disabled" << std::endl;
    }

    auto start = &start_solana_logs_subscription;
    auto stop = &stop_solana_logs_subscription;

    unsigned int sub_id = start(ws_url, program_id, on_log_callback);
    if (sub_id == 0)
    {
        std::cerr << "Subscription failed to start" << std::endl;
        return 1;
    }
    std::cout << "Subscription started (id=" << sub_id << ") for program " << program_id << std::endl;

    while (!g_should_stop.load())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    stop(sub_id);
    std::cout << "Stopped subscription" << std::endl;
    return 0;
}
