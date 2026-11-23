#include "session_service.hpp"
#include "crypto_service.hpp"
#include <iostream>

namespace securevault {

SessionService& SessionService::instance() {
    static SessionService instance;
    return instance;
}

SessionService::~SessionService() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& pair : sessions_) {
        if (!pair.second.vault_key.empty()) {
            CryptoService::wipe_memory(pair.second.vault_key.data(), pair.second.vault_key.size());
        }
    }
    sessions_.clear();
}

std::string SessionService::create_session(int64_t user_id, const std::string& name, 
                                           const std::string& email, 
                                           const std::vector<unsigned char>& vault_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string token = CryptoService::generate_session_token();

    SessionData session;
    session.token = token;
    session.user_id = user_id;
    session.name = name;
    session.email = email;
    session.vault_key = vault_key;
    session.last_activity = std::chrono::steady_clock::now();

    sessions_[token] = std::move(session);
    return token;
}

bool SessionService::get_session(const std::string& token, SessionData& out_session) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(token);
    if (it == sessions_.end()) {
        return false;
    }

    // Check expiration (60 minutes idle limit)
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_activity).count() > 60) {
        CryptoService::wipe_memory(it->second.vault_key.data(), it->second.vault_key.size());
        sessions_.erase(it);
        return false;
    }

    // Update last activity timestamp
    it->second.last_activity = now;
    out_session = it->second;
    return true;
}

void SessionService::destroy_session(const std::string& token) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(token);
    if (it != sessions_.end()) {
        if (!it->second.vault_key.empty()) {
            CryptoService::wipe_memory(it->second.vault_key.data(), it->second.vault_key.size());
        }
        sessions_.erase(it);
    }
}

void SessionService::cleanup_expired(std::chrono::minutes max_idle_time) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_activity) > max_idle_time) {
            if (!it->second.vault_key.empty()) {
                CryptoService::wipe_memory(it->second.vault_key.data(), it->second.vault_key.size());
            }
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace securevault
