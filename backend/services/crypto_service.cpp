#include "crypto_service.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include "sodium.h"

namespace securevault {

bool CryptoService::init() {
    if (sodium_init() < 0) {
        std::cerr << "[CryptoService] Error initializing libsodium!" << std::endl;
        return false;
    }
    std::cout << "[CryptoService] libsodium initialized successfully (version: " 
              << sodium_version_string() << ")" << std::endl;
    return true;
}

std::string CryptoService::hash_master_password(const std::string& master_password) {
    char hash_str[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(
            hash_str,
            master_password.c_str(),
            master_password.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("Argon2id password hashing failed (out of memory or invalid parameters)");
    }
    return std::string(hash_str);
}

bool CryptoService::verify_master_password(const std::string& master_hash, const std::string& candidate_password) {
    return (crypto_pwhash_str_verify(
                master_hash.c_str(),
                candidate_password.c_str(),
                candidate_password.length()) == 0);
}

std::vector<unsigned char> CryptoService::generate_random_bytes(size_t length) {
    std::vector<unsigned char> bytes(length);
    randombytes_buf(bytes.data(), length);
    return bytes;
}

std::vector<unsigned char> CryptoService::generate_salt() {
    return generate_random_bytes(crypto_pwhash_SALTBYTES);
}

std::vector<unsigned char> CryptoService::generate_nonce() {
    return generate_random_bytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

bool CryptoService::derive_vault_key(const std::string& master_password, 
                                     const std::vector<unsigned char>& salt, 
                                     std::vector<unsigned char>& out_key) {
    if (salt.size() != crypto_pwhash_SALTBYTES) {
        return false;
    }

    out_key.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    if (crypto_pwhash(
            out_key.data(),
            out_key.size(),
            master_password.c_str(),
            master_password.length(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        wipe_memory(out_key.data(), out_key.size());
        return false;
    }

    return true;
}

bool CryptoService::encrypt(const std::string& plaintext, 
                            const std::vector<unsigned char>& key, 
                            const std::vector<unsigned char>& nonce, 
                            std::vector<unsigned char>& out_ciphertext) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES ||
        nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        return false;
    }

    out_ciphertext.resize(plaintext.length() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long actual_ciphertext_len = 0;

    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out_ciphertext.data(),
        &actual_ciphertext_len,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.length(),
        nullptr, 0, // no additional authenticated data
        nullptr,    // secret nonce not needed for IETF
        nonce.data(),
        key.data()
    );

    if (rc != 0) {
        out_ciphertext.clear();
        return false;
    }

    out_ciphertext.resize(actual_ciphertext_len);
    return true;
}

bool CryptoService::decrypt(const std::vector<unsigned char>& ciphertext, 
                            const std::vector<unsigned char>& key, 
                            const std::vector<unsigned char>& nonce, 
                            std::string& out_plaintext) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES ||
        nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
        ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return false;
    }

    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long actual_decrypted_len = 0;

    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted.data(),
        &actual_decrypted_len,
        nullptr, // secret nonce
        ciphertext.data(),
        ciphertext.size(),
        nullptr, 0, // no additional authenticated data
        nonce.data(),
        key.data()
    );

    if (rc != 0) {
        wipe_memory(decrypted.data(), decrypted.size());
        return false;
    }

    out_plaintext.assign(reinterpret_cast<char*>(decrypted.data()), actual_decrypted_len);
    wipe_memory(decrypted.data(), decrypted.size());
    return true;
}

void CryptoService::wipe_memory(void* ptr, size_t len) {
    if (ptr && len > 0) {
        sodium_memzero(ptr, len);
    }
}

std::string CryptoService::bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::vector<unsigned char> CryptoService::hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) return bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string CryptoService::generate_session_token() {
    auto random_bytes = generate_random_bytes(32);
    return bytes_to_hex(random_bytes);
}

} // namespace securevault
