#include "database.h"
#include <locale>
#include <iostream>
#include <string>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/iterator.h>
#include <rocksdb/write_batch.h>
#include <filesystem>

#include "const.h"

int database::open_db(rocksdb::DB*& db, rocksdb::Options& options, const std::string& db_type)
{
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, db_type, &db);

    if (!status.ok()) {
        return 0;
    }

    return 1;
}

void database::close_db(rocksdb::DB*& db)
{
    commit(db);
    delete db;
    db = nullptr;
}

int database::store_single(rocksdb::DB* db, const std::string& key, const std::string& data)
{
    rocksdb::Status status = db->Put(rocksdb::WriteOptions(), key, data);
    if (!status.ok()) {
        return 0;
    }
    return 1;
}

int database::get_data(rocksdb::DB* db, const std::string& key, std::string& data)
{
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), key, &data);
    if (!status.ok() || status.IsNotFound()) {
        return 0;
    }
    return 1;
}

int database::store_batch(rocksdb::DB* db, rocksdb::WriteBatch& batch)
{
    rocksdb::Status status = db->Write(rocksdb::WriteOptions(), &batch);
    if (!status.ok()) {
        return 0;
    }
    return 1;
}

int database::get_all_data(rocksdb::DB* db, std::vector<std::string>& keys, std::vector<std::string>& values)
{
    rocksdb::Iterator* iterator = db->NewIterator(rocksdb::ReadOptions());
    int x = 0;
    for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
        std::string key = iterator->key().ToString();
        std::string value = iterator->value().ToString();

        if (value != "commit_marker_value" && key != "commit_marker_key")
        {
            keys.push_back(key);
            values.push_back(value);
        }

        x++;
    }

    if (!iterator->status().ok()) {
        delete iterator;
        return 0;
    }

    delete iterator;

    if (keys.empty() || values.empty()) {
        return 0;
    }

    return 1;
}

int database::get_multi_data(rocksdb::DB* db, std::string& start_key, int amount, std::vector<std::string>& keys, std::vector<std::string>& values)
{
    rocksdb::Iterator* iterator = db->NewIterator(rocksdb::ReadOptions());
    int x = 0;

    iterator->Seek(start_key);
    if (iterator->Valid()) {
        if (start_key == EMPTY_KEY)
        {
            std::string key = iterator->key().ToString();
            std::string value = iterator->value().ToString();
            if (value != "commit_marker_value" && key != "commit_marker_key")
            {
                keys.push_back(key);
                values.push_back(value);
            }
            x++;
        }
        iterator->Next();
    }

    for (; iterator->Valid() && x < amount; iterator->Next()) {
        std::string key = iterator->key().ToString();
        std::string value = iterator->value().ToString();

        if (value != "commit_marker_value" && key != "commit_marker_key")
        {
            keys.push_back(key);
            values.push_back(value);
        }

        x++;
    }

    if (!iterator->status().ok()) {
        delete iterator;
        return 0;
    }

    delete iterator;

    return 1;
}

int database::get_last_amount(rocksdb::DB* db, std::vector<std::string>& keys, std::vector<std::string>& values, int amount)
{
    rocksdb::Iterator* iterator = db->NewIterator(rocksdb::ReadOptions());
    int x = 0;

    iterator->SeekToLast();
    if (iterator->Valid()) {
        std::string key = iterator->key().ToString();
        std::string value = iterator->value().ToString();
        if (value != "commit_marker_value" && key != "commit_marker_key")
        {
            keys.push_back(key);
            values.push_back(value);
            x++;
        }
        iterator->Prev();
    }

    for (; iterator->Valid() && x < amount; iterator->Prev()) {
        std::string key = iterator->key().ToString();
        std::string value = iterator->value().ToString();

        if (value != "commit_marker_value" && key != "commit_marker_key")
        {
            keys.push_back(key);
            values.push_back(value);
        }

        x++;
    }

    if (!iterator->status().ok()) {
        delete iterator;
        return 0;
    }

    delete iterator;

    return 1;
}

int database::get_last_data(rocksdb::DB* db, std::string& last_key, std::string& last_value)
{
    rocksdb::ReadOptions readOptions;
    readOptions.fill_cache = false;
    rocksdb::Iterator* it = db->NewIterator(readOptions);

    it->SeekToLast();

    if (it->Valid()) {
        last_key = it->key().ToString();
        last_value = it->value().ToString();
        if (last_value == "commit_marker_value" && last_key == "commit_marker_key") {
            it->Prev();
            if (it->Valid())
            {
                last_key = it->key().ToString();
                last_value = it->value().ToString();
            }
            else {
                last_key = "";
                last_value = "";
            }
        }
        delete it;
        return 1;
    }
    else {
        delete it;
        return 0;
    }
}

int database::remove_single(rocksdb::DB* db, const std::string& key)
{
    rocksdb::Status status = db->Delete(rocksdb::WriteOptions(), key);

    if (status.ok()) {
        return 1;
    }
    else {
        return 0;
    }
}

void database::commit(rocksdb::DB* db)
{
    rocksdb::WriteOptions writeOptions;
    writeOptions.sync = true;
    db->Put(writeOptions, "commit_marker_key", "commit_marker_value");
}

int database::get_all_keys(rocksdb::DB* db, std::vector<std::string>& keys)
{
    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        keys.push_back(it->key().ToString());
    }
    if (!it->status().ok()) {
        std::cout << "Error during key iteration:" << it->status().ToString() << std::endl;
        delete it;
        return 0;
    }

    delete it;
    return 1;
}

int database::compact_all(rocksdb::DB* db)
{
    db->CompactRange(rocksdb::CompactRangeOptions(), nullptr, nullptr);
    return 1;
}
