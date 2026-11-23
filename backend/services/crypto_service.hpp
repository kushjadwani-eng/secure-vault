#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace securevault {

class CryptoService {
public:
    static bool init();

    // Argon2id master password hashing and verification
    static std::string hash_master_password(const std::string& master_password);
    static bool verify_master_password(const std::string& master_hash, const std::string& candidate_password);

    // Cryptographically secure random generation
    static std::vector<unsigned char> generate_random_bytes(size_t length);
    static std::vector<unsigned char> generate_salt();
    static std::vector<unsigned char> generate_nonce();

    // Vault key derivation (Argon2id)
    static bool derive_vault_key(const std::string& master_password, 
                                 const std::vector<unsigned char>& salt, 
                                 std::vector<unsigned char>& out_key);

    // Authenticated encryption (XChaCha20-Poly1305)
    static bool encrypt(const std::string& plaintext, 
                        const std::vector<unsigned char>& key, 
                        const std::vector<unsigned char>& nonce, 
                        std::vector<unsigned char>& out_ciphertext);

    static bool decrypt(const std::vector<unsigned char>& ciphertext, 
                        const std::vector<unsigned char>& key, 
                        const std::vector<unsigned char>& nonce, 
                        std::string& out_plaintext);

    // Secure memory erasure
    static void wipe_memory(void* ptr, size_t len);

    // Encoding helpers
    static std::string bytes_to_hex(const std::vector<unsigned char>& bytes);
    static std::vector<unsigned char> hex_to_bytes(const std::string& hex);
    static std::string generate_session_token();
};

} // namespace securevault
