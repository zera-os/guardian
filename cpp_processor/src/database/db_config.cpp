#include "db_base.h"
#include <rocksdb/write_batch.h>

void open_dbs()
{
    db_contracts::open_db();
    db_payloads::open_db();
    db_guardians::open_db();
    db_guardians_payloads::open_db();
}

void close_dbs()
{
    db_contracts::close_db();
    db_payloads::close_db();
    db_guardians::close_db();
    db_guardians_payloads::close_db();
}

void reset_dbs()
{
    db_contracts::remove_all();
    db_payloads::remove_all();
    db_guardians::remove_all();
    db_guardians_payloads::remove_all();
}