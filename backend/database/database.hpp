#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>
#include "sqlite3.h"

namespace securevault {

struct UserRecord {
    int64_t user_id;
    std::string name;
    std::string email;
    std::string master_hash;
    std::vector<unsigned char> vault_salt;
    std::string created_at;
};

struct VaultEntryRecord {
    int64_t entry_id;
    int64_t user_id;
    std::string website;
    std::string website_url;
    std::string username;
    std::vector<unsigned char> encrypted_password;
    std::vector<unsigned char> nonce;
    std::string category;
    std::string created_at;
    std::string updated_at;
};

class Database {
public:
    static Database& instance();

    bool init(const std::string& db_path);
    void close();

    // User operations
    bool email_exists(const std::string& email);
    bool create_user(const std::string& name, const std::string& email, 
                     const std::string& master_hash, 
                     const std::vector<unsigned char>& vault_salt, 
                     int64_t& out_user_id);
    bool get_user_by_email(const std::string& email, UserRecord& out_user);
    bool get_user_by_id(int64_t user_id, UserRecord& out_user);

    // Vault entry operations
    bool create_vault_entry(int64_t user_id, const std::string& website,
                            const std::string& website_url, const std::string& username,
                            const std::vector<unsigned char>& encrypted_password,
                            const std::vector<unsigned char>& nonce,
                            const std::string& category, int64_t& out_entry_id);

    bool get_vault_entries_by_user(int64_t user_id, std::vector<VaultEntryRecord>& out_entries);
    bool get_vault_entry_by_id(int64_t entry_id, int64_t user_id, VaultEntryRecord& out_entry);
    bool update_vault_entry(int64_t entry_id, int64_t user_id, const std::string& website,
                            const std::string& website_url, const std::string& username,
                            const std::vector<unsigned char>& encrypted_password,
                            const std::vector<unsigned char>& nonce,
                            const std::string& category);
    bool delete_vault_entry(int64_t entry_id, int64_t user_id);

private:
    Database();
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    sqlite3* db_{nullptr};
    std::mutex db_mutex_;
};

} // namespace securevault
