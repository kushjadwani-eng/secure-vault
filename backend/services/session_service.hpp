#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>

namespace securevault {

struct SessionData {
    std::string token;
    int64_t user_id{0};
    std::string name;
    std::string email;
    std::vector<unsigned char> vault_key;
    std::chrono::steady_clock::time_point last_activity;
};

class SessionService {
public:
    static SessionService& instance();

    // Create a new session with user credentials and derived vault key
    std::string create_session(int64_t user_id, const std::string& name, 
                               const std::string& email, 
                               const std::vector<unsigned char>& vault_key);

    // Validate token and retrieve session information
    bool get_session(const std::string& token, SessionData& out_session);

    // Destroy session and securely wipe vault key from memory
    void destroy_session(const std::string& token);

    // Purge expired sessions
    void cleanup_expired(std::chrono::minutes max_idle_time = std::chrono::minutes(60));

private:
    SessionService() = default;
    ~SessionService();
    SessionService(const SessionService&) = delete;
    SessionService& operator=(const SessionService&) = delete;

    std::unordered_map<std::string, SessionData> sessions_;
    std::mutex mutex_;
};

} // namespace securevault
