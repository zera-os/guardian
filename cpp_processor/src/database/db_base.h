#pragma once

#include <vector>
#include <string>
#include "database.h"
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/write_batch.h>
#include "validator.pb.h"

#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <leveldb/options.h>

template <typename T>
class db_base
{
    friend class db_validators_tag;
    friend class db_blocks_tag;
    friend class db_headers_tag;

public:
    static int open_db();
    static void close_db();
    static int get_all_data(std::vector<std::string> &keys, std::vector<std::string> &values);
    static int get_single(const std::string &key, std::string &value);
    static int store_single(const std::string &key, const std::string &value);
    static int store_batch(rocksdb::WriteBatch &batch);
    static int remove_single(const std::string &key);
    static int remove_all();
    static int exist(const std::string &key);
    static int compact_all();

private:
    static rocksdb::DB *db;
    static rocksdb::Options options;
    static std::mutex db_mutex;
};

class db_contracts_tag
{
public:
    static const char *const DB_NAME;
};

class db_payloads_tag
{
public:
    static const char *const DB_NAME;
};
class guardians_tag
{
    public:
    static const char *const DB_NAME;
};
class guardians_payloads_tag
{
    public:
    static const char *const DB_NAME;
};

void open_dbs();
void close_dbs();
void reset_dbs();

// Type aliases for each database
using db_contracts = db_base<db_contracts_tag>;                   // store ALL Created Contracts
using db_payloads = db_base<db_payloads_tag>;                   // store ALL Created Payloads
using db_guardians = db_base<guardians_tag>;                   // store ALL Guardian Keys
using db_guardians_payloads = db_base<guardians_payloads_tag>; // store ALL Guardian Payloads