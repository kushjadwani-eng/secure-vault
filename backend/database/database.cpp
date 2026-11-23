#include "database.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace securevault {

static std::string current_utc_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%d %H:%M:%SZ");
    return ss.str();
}

Database& Database::instance() {
    static Database instance;
    return instance;
}

Database::Database() = default;

Database::~Database() {
    close();
}

bool Database::init(const std::string& db_path) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (db_ != nullptr) {
        return true;
    }

    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "[Database] Failed to open database: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    // Enable WAL mode for concurrent reading/writing and enforce foreign keys
    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Database] Warning setting WAL mode: " << (err_msg ? err_msg : "") << std::endl;
        sqlite3_free(err_msg);
    }

    rc = sqlite3_exec(db_, "PRAGMA foreign_keys = ON;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Database] Warning setting foreign keys: " << (err_msg ? err_msg : "") << std::endl;
        sqlite3_free(err_msg);
    }

    // Schema definition as designed in the project handover
    const char* schema_sql = 
        "CREATE TABLE IF NOT EXISTS Users ("
        "    user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    name TEXT NOT NULL,"
        "    email TEXT NOT NULL UNIQUE,"
        "    master_hash TEXT NOT NULL,"
        "    vault_salt BLOB NOT NULL,"
        "    created_at TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS VaultEntries ("
        "    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    user_id INTEGER NOT NULL,"
        "    website TEXT NOT NULL,"
        "    website_url TEXT,"
        "    username TEXT,"
        "    encrypted_password BLOB NOT NULL,"
        "    nonce BLOB NOT NULL,"
        "    category TEXT,"
        "    created_at TEXT NOT NULL,"
        "    updated_at TEXT,"
        "    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE"
        ");";

    rc = sqlite3_exec(db_, schema_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Database] Error initializing schema: " << (err_msg ? err_msg : "") << std::endl;
        sqlite3_free(err_msg);
        return false;
    }

    std::cout << "[Database] SQLite initialized successfully at: " << db_path << std::endl;
    return true;
}

void Database::close() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Database::email_exists(const std::string& email) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    const char* sql = "SELECT 1 FROM Users WHERE email = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

bool Database::create_user(const std::string& name, const std::string& email,
                           const std::string& master_hash,
                           const std::vector<unsigned char>& vault_salt,
                           int64_t& out_user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    const char* sql = "INSERT INTO Users (name, email, master_hash, vault_salt, created_at) "
                      "VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[Database] Prepare error create_user: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string now_str = current_utc_time();

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, master_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, vault_salt.data(), static_cast<int>(vault_salt.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, now_str.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "[Database] Step error create_user: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    out_user_id = sqlite3_last_insert_rowid(db_);
    return true;
}

bool Database::get_user_by_email(const std::string& email, UserRecord& out_user) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    const char* sql = "SELECT user_id, name, email, master_hash, vault_salt, created_at "
                      "FROM Users WHERE email = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out_user.user_id = sqlite3_column_int64(stmt, 0);
        out_user.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        out_user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        out_user.master_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

        const void* blob_data = sqlite3_column_blob(stmt, 4);
        int blob_bytes = sqlite3_column_bytes(stmt, 4);
        if (blob_data && blob_bytes > 0) {
            const unsigned char* p = static_cast<const unsigned char*>(blob_data);
            out_user.vault_salt.assign(p, p + blob_bytes);
        }

        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        if (created) out_user.created_at = created;

        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool Database::get_user_by_id(int64_t user_id, UserRecord& out_user) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    const char* sql = "SELECT user_id, name, email, master_hash, vault_salt, created_at "
                      "FROM Users WHERE user_id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, user_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out_user.user_id = sqlite3_column_int64(stmt, 0);
        out_user.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        out_user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        out_user.master_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

        const void* blob_data = sqlite3_column_blob(stmt, 4);
        int blob_bytes = sqlite3_column_bytes(stmt, 4);
        if (blob_data && blob_bytes > 0) {
            const unsigned char* p = static_cast<const unsigned char*>(blob_data);
            out_user.vault_salt.assign(p, p + blob_bytes);
        }

        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        if (created) out_user.created_at = created;

        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool Database::create_vault_entry(int64_t user_id, const std::string& website,
                                  const std::string& website_url, const std::string& username,
                                  const std::vector<unsigned char>& encrypted_password,
                                  const std::vector<unsigned char>& nonce,
                                  const std::string& category, int64_t& out_entry_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    const char* sql = "INSERT INTO VaultEntries (user_id, website, website_url, username, "
                      "encrypted_password, nonce, category, created_at, updated_at) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    std::string now_str = current_utc_time();

    sqlite3_bind_int64(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, website.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, website_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, encrypted_password.data(), static_cast<int>(encrypted_password.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 6, nonce.data(), static_cast<int>(nonce.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, category.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, now_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, now_str.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return false;
    }

    out_entry_id = sqlite3_last_insert_rowid(db_);
    return true;
}

bool Database::get_vault_entries_by_user(int64_t user_id, std::vector<VaultEntryRecord>& out_entries) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;
    out_entries.clear();

    const char* sql = "SELECT entry_id, user_id, website, website_url, username, "
                      "encrypted_password, nonce, category, created_at, updated_at "
                      "FROM VaultEntries WHERE user_id = ? ORDER BY website COLLATE NOCASE ASC;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, user_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        VaultEntryRecord entry;
        entry.entry_id = sqlite3_column_int64(stmt, 0);
        entry.user_id = sqlite3_column_int64(stmt, 1);
        
        const char* w = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        if (w) entry.website = w;

        const char* u = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (u) entry.website_url = u;

        const char* un = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        if (un) entry.username = un;

        const void* p_blob = sqlite3_column_blob(stmt, 5);
        int p_len = sqlite3_column_bytes(stmt, 5);
        if (p_blob && p_len > 0) {
            const unsigned char* p = static_cast<const unsigned char*>(p_blob);
            entry.encrypted_password.assign(p, p + p_len);
        }

        const void* n_blob = sqlite3_column_blob(stmt, 6);
        int n_len = sqlite3_column_bytes(stmt, 6);
        if (n_blob && n_len > 0) {
            const unsigned char* n = static_cast<const unsigned char*>(n_blob);
            entry.nonce.assign(n, n + n_len);
        }

        const char* cat = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        if (cat) entry.category = cat;

        const char* c_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        if (c_at) entry.created_at = c_at;

        const char* u_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        if (u_at) entry.updated_at = u_at;

        out_entries.push_back(std::move(entry));
    }

    sqlite3_finalize(stmt);
    return true;
}

bool Database::get_vault_entry_by_id(int64_t entry_id, int64_t user_id, VaultEntryRecord& out_entry) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    // Strict ownership rule: always filter by both entry_id AND user_id
    const char* sql = "SELECT entry_id, user_id, website, website_url, username, "
                      "encrypted_password, nonce, category, created_at, updated_at "
                      "FROM VaultEntries WHERE entry_id = ? AND user_id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, entry_id);
    sqlite3_bind_int64(stmt, 2, user_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out_entry.entry_id = sqlite3_column_int64(stmt, 0);
        out_entry.user_id = sqlite3_column_int64(stmt, 1);
        
        const char* w = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        if (w) out_entry.website = w;

        const char* u = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (u) out_entry.website_url = u;

        const char* un = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        if (un) out_entry.username = un;

        const void* p_blob = sqlite3_column_blob(stmt, 5);
        int p_len = sqlite3_column_bytes(stmt, 5);
        if (p_blob && p_len > 0) {
            const unsigned char* p = static_cast<const unsigned char*>(p_blob);
            out_entry.encrypted_password.assign(p, p + p_len);
        }

        const void* n_blob = sqlite3_column_blob(stmt, 6);
        int n_len = sqlite3_column_bytes(stmt, 6);
        if (n_blob && n_len > 0) {
            const unsigned char* n = static_cast<const unsigned char*>(n_blob);
            out_entry.nonce.assign(n, n + n_len);
        }

        const char* cat = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        if (cat) out_entry.category = cat;

        const char* c_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        if (c_at) out_entry.created_at = c_at;

        const char* u_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        if (u_at) out_entry.updated_at = u_at;

        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool Database::update_vault_entry(int64_t entry_id, int64_t user_id, const std::string& website,
                                  const std::string& website_url, const std::string& username,
                                  const std::vector<unsigned char>& encrypted_password,
                                  const std::vector<unsigned char>& nonce,
                                  const std::string& category) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    // Strict ownership rule: always verify user_id
    const char* sql = "UPDATE VaultEntries SET website = ?, website_url = ?, username = ?, "
                      "encrypted_password = ?, nonce = ?, category = ?, updated_at = ? "
                      "WHERE entry_id = ? AND user_id = ?;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    std::string now_str = current_utc_time();

    sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, website_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, encrypted_password.data(), static_cast<int>(encrypted_password.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, nonce.data(), static_cast<int>(nonce.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, category.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, now_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 8, entry_id);
    sqlite3_bind_int64(stmt, 9, user_id);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE && changes > 0);
}

bool Database::delete_vault_entry(int64_t entry_id, int64_t user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;

    // Strict ownership rule: always verify user_id
    const char* sql = "DELETE FROM VaultEntries WHERE entry_id = ? AND user_id = ?;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, entry_id);
    sqlite3_bind_int64(stmt, 2, user_id);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE && changes > 0);
}

} // namespace securevault
