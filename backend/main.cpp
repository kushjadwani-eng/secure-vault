#include "crow_all.h"
#include "database/database.hpp"
#include "services/crypto_service.hpp"
#include "services/session_service.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace securevault;

// Extract session token from either Authorization header or session_token Cookie
std::string extract_token(const crow::request& req) {
    std::string auth = req.get_header_value("Authorization");
    if (auth.rfind("Bearer ", 0) == 0 && auth.length() > 7) {
        return auth.substr(7);
    }

    std::string cookie_header = req.get_header_value("Cookie");
    if (!cookie_header.empty()) {
        size_t pos = cookie_header.find("session_token=");
        if (pos != std::string::npos) {
            size_t start = pos + 14;
            size_t end = cookie_header.find(';', start);
            if (end == std::string::npos) {
                return cookie_header.substr(start);
            } else {
                return cookie_header.substr(start, end - start);
            }
        }
    }
    return "";
}

// Authenticate request and populate session data
bool authenticate_request(const crow::request& req, SessionData& session) {
    std::string token = extract_token(req);
    if (token.empty()) {
        return false;
    }
    return SessionService::instance().get_session(token, session);
}

int main() {
    // 1. Initialize Cryptographic Engine
    if (!CryptoService::init()) {
        std::cerr << "Fatal: Failed to initialize CryptoService (libsodium)" << std::endl;
        return 1;
    }

    // 2. Initialize Database & Tables
    if (!Database::instance().init("data/securevault.db")) {
        std::cerr << "Fatal: Failed to initialize Database (SQLite)" << std::endl;
        return 1;
    }

    crow::SimpleApp app;

    // ==========================================
    // STATIC FRONTEND ROUTES
    // ==========================================

    CROW_ROUTE(app, "/")([](crow::response& res) {
        res.set_static_file_info("frontend/index.html");
        res.end();
    });

    CROW_ROUTE(app, "/login")([](crow::response& res) {
        res.set_static_file_info("frontend/login.html");
        res.end();
    });

    CROW_ROUTE(app, "/register")([](crow::response& res) {
        res.set_static_file_info("frontend/register.html");
        res.end();
    });

    CROW_ROUTE(app, "/dashboard")([](crow::response& res) {
        res.set_static_file_info("frontend/dashboard.html");
        res.end();
    });

    CROW_ROUTE(app, "/css/<string>")([](crow::response& res, std::string filename) {
        res.set_static_file_info("frontend/css/" + filename);
        res.end();
    });

    CROW_ROUTE(app, "/js/<string>")([](crow::response& res, std::string filename) {
        res.set_static_file_info("frontend/js/" + filename);
        res.end();
    });

    // ==========================================
    // HEALTH CHECK
    // ==========================================

    CROW_ROUTE(app, "/api/health")([]() {
        crow::json::wvalue res;
        res["status"] = "ok";
        res["service"] = "SecureVault Backend";
        res["version"] = "1.0.0";
        return crow::response(200, res);
    });

    // ==========================================
    // AUTHENTICATION ROUTES
    // ==========================================

    // POST /api/register
    CROW_ROUTE(app, "/api/register").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("name") || !body.has("email") || !body.has("password")) {
            crow::json::wvalue res;
            res["error"] = "Invalid request payload. 'name', 'email', and 'password' are required.";
            return crow::response(400, res);
        }

        std::string name = body["name"].s();
        std::string email = body["email"].s();
        std::string password = body["password"].s();

        // Validation
        if (name.empty() || email.empty() || password.length() < 8) {
            crow::json::wvalue res;
            res["error"] = "Password must be at least 8 characters, and all fields must be filled.";
            return crow::response(400, res);
        }

        // Email uniqueness check
        if (Database::instance().email_exists(email)) {
            crow::json::wvalue res;
            res["error"] = "An account with this email address already exists.";
            return crow::response(409, res);
        }

        try {
            // Generate user vault salt (for key derivation)
            std::vector<unsigned char> vault_salt = CryptoService::generate_salt();

            // Hash master password with Argon2id
            std::string master_hash = CryptoService::hash_master_password(password);

            // Persist user record in SQLite
            int64_t user_id = 0;
            if (!Database::instance().create_user(name, email, master_hash, vault_salt, user_id)) {
                crow::json::wvalue res;
                res["error"] = "Database error creating user account.";
                return crow::response(500, res);
            }

            crow::json::wvalue res;
            res["success"] = true;
            res["message"] = "Account created successfully. You can now log in.";
            res["user_id"] = user_id;
            return crow::response(201, res);
        } catch (const std::exception& ex) {
            crow::json::wvalue res;
            res["error"] = "Registration failed: " + std::string(ex.what());
            return crow::response(500, res);
        }
    });

    // POST /api/login
    CROW_ROUTE(app, "/api/login").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("email") || !body.has("password")) {
            crow::json::wvalue res;
            res["error"] = "Email and password are required.";
            return crow::response(400, res);
        }

        std::string email = body["email"].s();
        std::string password = body["password"].s();

        UserRecord user;
        if (!Database::instance().get_user_by_email(email, user)) {
            crow::json::wvalue res;
            res["error"] = "Invalid email or master password.";
            return crow::response(401, res);
        }

        // Verify master password hash using Argon2id
        if (!CryptoService::verify_master_password(user.master_hash, password)) {
            crow::json::wvalue res;
            res["error"] = "Invalid email or master password.";
            return crow::response(401, res);
        }

        // Derive user's 256-bit vault encryption key
        std::vector<unsigned char> vault_key;
        if (!CryptoService::derive_vault_key(password, user.vault_salt, vault_key)) {
            crow::json::wvalue res;
            res["error"] = "Key derivation failed.";
            return crow::response(500, res);
        }

        // Create secure server-side session
        std::string token = SessionService::instance().create_session(user.user_id, user.name, user.email, vault_key);

        // Wipe local copy of vault key from stack
        CryptoService::wipe_memory(vault_key.data(), vault_key.size());

        crow::json::wvalue res;
        res["success"] = true;
        res["token"] = token;
        res["user"]["id"] = user.user_id;
        res["user"]["name"] = user.name;
        res["user"]["email"] = user.email;

        crow::response response(200, res);
        // Set secure session cookie
        response.add_header("Set-Cookie", "session_token=" + token + "; Path=/; HttpOnly; SameSite=Lax");
        return response;
    });

    // POST /api/logout
    CROW_ROUTE(app, "/api/logout").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        std::string token = extract_token(req);
        if (!token.empty()) {
            SessionService::instance().destroy_session(token);
        }

        crow::json::wvalue res;
        res["success"] = true;
        res["message"] = "Logged out successfully.";

        crow::response response(200, res);
        // Expire cookie
        response.add_header("Set-Cookie", "session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        return response;
    });

    // GET /api/auth/me
    CROW_ROUTE(app, "/api/auth/me")([](const crow::request& req) {
        SessionData session;
        if (!authenticate_request(req, session)) {
            crow::json::wvalue res;
            res["error"] = "Unauthenticated";
            return crow::response(401, res);
        }

        crow::json::wvalue res;
        res["authenticated"] = true;
        res["user"]["id"] = session.user_id;
        res["user"]["name"] = session.name;
        res["user"]["email"] = session.email;
        return crow::response(200, res);
    });

    // ==========================================
    // VAULT CRUD ROUTES (Authenticated & Encrypted)
    // ==========================================

    // GET /api/vault - List all entries for authenticated user
    CROW_ROUTE(app, "/api/vault")([](const crow::request& req) {
        SessionData session;
        if (!authenticate_request(req, session)) {
            crow::json::wvalue res;
            res["error"] = "Unauthenticated";
            return crow::response(401, res);
        }

        std::vector<VaultEntryRecord> entries;
        if (!Database::instance().get_vault_entries_by_user(session.user_id, entries)) {
            crow::json::wvalue res;
            res["error"] = "Failed to load vault entries.";
            return crow::response(500, res);
        }

        std::vector<crow::json::wvalue> json_entries;
        json_entries.reserve(entries.size());

        for (const auto& entry : entries) {
            std::string decrypted_password;
            bool ok = CryptoService::decrypt(entry.encrypted_password, session.vault_key, entry.nonce, decrypted_password);

            crow::json::wvalue item;
            item["entry_id"] = entry.entry_id;
            item["website"] = entry.website;
            item["website_url"] = entry.website_url;
            item["username"] = entry.username;
            item["password"] = ok ? decrypted_password : "[Decryption Failed]";
            item["category"] = entry.category;
            item["created_at"] = entry.created_at;
            item["updated_at"] = entry.updated_at;

            // Clean decrypted string from memory as soon as serialized
            CryptoService::wipe_memory(&decrypted_password[0], decrypted_password.size());

            json_entries.push_back(std::move(item));
        }

        crow::json::wvalue res;
        res["entries"] = std::move(json_entries);
        return crow::response(200, res);
    });

    // POST /api/vault - Create new encrypted entry
    CROW_ROUTE(app, "/api/vault").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        SessionData session;
        if (!authenticate_request(req, session)) {
            crow::json::wvalue res;
            res["error"] = "Unauthenticated";
            return crow::response(401, res);
        }

        auto body = crow::json::load(req.body);
        if (!body || !body.has("website") || !body.has("password")) {
            crow::json::wvalue res;
            res["error"] = "Website name and password are required.";
            return crow::response(400, res);
        }

        std::string website = body["website"].s();
        std::string website_url = body.has("website_url") ? std::string(body["website_url"].s()) : "";
        std::string username = body.has("username") ? std::string(body["username"].s()) : "";
        std::string password = std::string(body["password"].s());
        std::string category = body.has("category") ? std::string(body["category"].s()) : "Personal";

        // Generate unique 24-byte nonce for XChaCha20-Poly1305
        std::vector<unsigned char> nonce = CryptoService::generate_nonce();
        std::vector<unsigned char> ciphertext;

        if (!CryptoService::encrypt(password, session.vault_key, nonce, ciphertext)) {
            crow::json::wvalue res;
            res["error"] = "Encryption failed.";
            return crow::response(500, res);
        }

        int64_t entry_id = 0;
        if (!Database::instance().create_vault_entry(session.user_id, website, website_url, username,
                                                     ciphertext, nonce, category, entry_id)) {
            crow::json::wvalue res;
            res["error"] = "Failed to save vault entry.";
            return crow::response(500, res);
        }

        crow::json::wvalue res;
        res["success"] = true;
        res["entry_id"] = entry_id;
        res["message"] = "Credential safely encrypted and saved.";
        return crow::response(201, res);
    });

    // PUT /api/vault/<int> - Update entry
    CROW_ROUTE(app, "/api/vault/<int>").methods(crow::HTTPMethod::PUT)([](const crow::request& req, int entry_id) {
        SessionData session;
        if (!authenticate_request(req, session)) {
            crow::json::wvalue res;
            res["error"] = "Unauthenticated";
            return crow::response(401, res);
        }

        auto body = crow::json::load(req.body);
        if (!body || !body.has("website") || !body.has("password")) {
            crow::json::wvalue res;
            res["error"] = "Website name and password are required.";
            return crow::response(400, res);
        }

        std::string website = body["website"].s();
        std::string website_url = body.has("website_url") ? std::string(body["website_url"].s()) : "";
        std::string username = body.has("username") ? std::string(body["username"].s()) : "";
        std::string password = std::string(body["password"].s());
        std::string category = body.has("category") ? std::string(body["category"].s()) : "Personal";

        // Generate a fresh nonce for every encryption update
        std::vector<unsigned char> nonce = CryptoService::generate_nonce();
        std::vector<unsigned char> ciphertext;

        if (!CryptoService::encrypt(password, session.vault_key, nonce, ciphertext)) {
            crow::json::wvalue res;
            res["error"] = "Encryption failed.";
            return crow::response(500, res);
        }

        if (!Database::instance().update_vault_entry(entry_id, session.user_id, website, website_url, 
                                                     username, ciphertext, nonce, category)) {
            crow::json::wvalue res;
            res["error"] = "Entry not found or unauthorized.";
            return crow::response(404, res);
        }

        crow::json::wvalue res;
        res["success"] = true;
        res["message"] = "Credential updated successfully.";
        return crow::response(200, res);
    });

    // DELETE /api/vault/<int> - Delete entry
    CROW_ROUTE(app, "/api/vault/<int>").methods(crow::HTTPMethod::DELETE)([](const crow::request& req, int entry_id) {
        SessionData session;
        if (!authenticate_request(req, session)) {
            crow::json::wvalue res;
            res["error"] = "Unauthenticated";
            return crow::response(401, res);
        }

        if (!Database::instance().delete_vault_entry(entry_id, session.user_id)) {
            crow::json::wvalue res;
            res["error"] = "Entry not found or unauthorized.";
            return crow::response(404, res);
        }

        crow::json::wvalue res;
        res["success"] = true;
        res["message"] = "Credential deleted.";
        return crow::response(200, res);
    });

    std::cout << "========================================\n";
    std::cout << "  SecureVault Backend Server Running    \n";
    std::cout << "  Database: data/securevault.db         \n";
    std::cout << "  Server:   http://localhost:8080       \n";
    std::cout << "========================================\n";

    // Run server on port 8080
    app.port(8080).multithreaded().run();

    return 0;
}
