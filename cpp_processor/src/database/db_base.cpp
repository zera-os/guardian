#include "db_base.h"

#include <iostream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <set>
#include <map>

#include "const.h"

const char *const db_contracts_tag::DB_NAME = "contracts";
const char *const db_payloads_tag::DB_NAME = "payloads";
const char *const guardians_tag::DB_NAME = "guardians";
const char *const guardians_payloads_tag::DB_NAME = "guardians_payloads";

template <typename T>
rocksdb::DB *db_base<T>::db = nullptr;
template <typename T>
rocksdb::Options db_base<T>::options;
template <typename T>
std::mutex db_base<T>::db_mutex;

template <typename T>
int db_base<T>::open_db()
{
    std::string database = DB_DIRECTORY + std::string(T::DB_NAME);
    return database::open_db(db, options, database);
}
template int db_base<db_contracts_tag>::open_db();
template int db_base<db_payloads_tag>::open_db();
template int db_base<guardians_tag>::open_db();
template int db_base<guardians_payloads_tag>::open_db();

template <typename T>
void db_base<T>::close_db()
{
    database::close_db(db);
}
template void db_base<db_contracts_tag>::close_db();
template void db_base<db_payloads_tag>::close_db();
template void db_base<guardians_tag>::close_db();
template void db_base<guardians_payloads_tag>::close_db();

template <typename T>
int db_base<T>::get_single(const std::string &key, std::string &value)
{
    return database::get_data(db, key, value);
}
template int db_base<db_contracts_tag>::get_single(const std::string &key, std::string &value);
template int db_base<db_payloads_tag>::get_single(const std::string &key, std::string &value);
template int db_base<guardians_tag>::get_single(const std::string &key, std::string &value);
template int db_base<guardians_payloads_tag>::get_single(const std::string &key, std::string &value);

template <typename T>
int db_base<T>::exist(const std::string &key)
{
    std::string value;
    return database::get_data(db, key, value);
}
template int db_base<db_contracts_tag>::exist(const std::string &key);
template int db_base<db_payloads_tag>::exist(const std::string &key);
template int db_base<guardians_tag>::exist(const std::string &key);
template int db_base<guardians_payloads_tag>::exist(const std::string &key);

template <typename T>
int db_base<T>::store_single(const std::string &key, const std::string &value)
{
    return database::store_single(db, key, value);
}
template int db_base<db_contracts_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<db_payloads_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<guardians_tag>::store_single(const std::string &key, const std::string &value);
template int db_base<guardians_payloads_tag>::store_single(const std::string &key, const std::string &value);

template <typename T>
int db_base<T>::store_batch(rocksdb::WriteBatch &batch)
{
    return database::store_batch(db, batch);
}
template int db_base<db_contracts_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<db_payloads_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<guardians_tag>::store_batch(rocksdb::WriteBatch &batch);
template int db_base<guardians_payloads_tag>::store_batch(rocksdb::WriteBatch &batch);

template <typename T>
int db_base<T>::remove_single(const std::string &key)
{
    return database::remove_single(db, key);
}
template int db_base<db_contracts_tag>::remove_single(const std::string &key);
template int db_base<db_payloads_tag>::remove_single(const std::string &key);
template int db_base<guardians_tag>::remove_single(const std::string &key);
template int db_base<guardians_payloads_tag>::remove_single(const std::string &key);

template <typename T>
int db_base<T>::get_all_data(std::vector<std::string> &keys, std::vector<std::string> &values)
{
    if (!database::get_all_data(db, keys, values))
    {
        return 0;
    }
    return 1;
}
template int db_base<db_contracts_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<db_payloads_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<guardians_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);
template int db_base<guardians_payloads_tag>::get_all_data(std::vector<std::string> &values, std::vector<std::string> &keys);

template <typename T>
int db_base<T>::remove_all()
{
    rocksdb::WriteBatch batch;

    // Iterate over each item in the database and add them to the write batch for deletion
    rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());

    for (it->SeekToFirst(); it->Valid(); it->Next())
    {
        batch.Delete(it->key());
    }

    delete it;

    std::lock_guard<std::mutex> lock(db_mutex);
    return database::store_batch(db, batch);
}
template int db_base<db_contracts_tag>::remove_all();
template int db_base<db_payloads_tag>::remove_all();
template int db_base<guardians_tag>::remove_all();
template int db_base<guardians_payloads_tag>::remove_all();

template <typename T>
int db_base<T>::compact_all()
{
    return database::compact_all(db);
}
template int db_base<db_contracts_tag>::compact_all();
template int db_base<db_payloads_tag>::compact_all();
template int db_base<guardians_tag>::compact_all();
template int db_base<guardians_payloads_tag>::compact_all();