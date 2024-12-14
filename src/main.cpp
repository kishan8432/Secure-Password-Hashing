#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>

#define SALT_SIZE 16 // 128-bit salt

// Function to hash a password with salt using SHA-256
bool hash_password(const std::string &password, unsigned char *salt, unsigned char *output_hash) {
    EVP_MD_CTX *mdctx;
    unsigned int md_len = 0;
    unsigned char md_value[EVP_MAX_MD_SIZE];

    // Initialize OpenSSL message digest context
    mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Error creating EVP_MD_CTX" << std::endl;
        return false;
    }

    // Initialize SHA-256 hash function
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Error initializing digest" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Update the hash with salt and password
    if (EVP_DigestUpdate(mdctx, salt, SALT_SIZE) != 1) {
        std::cerr << "Error updating digest with salt" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    if (EVP_DigestUpdate(mdctx, password.c_str(), password.length()) != 1) {
        std::cerr << "Error updating digest with password" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Finalize the digest (this gives the hashed value)
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        std::cerr << "Error finalizing digest" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Copy the hash to the output buffer
    std::memcpy(output_hash, md_value, md_len);

    // Free the message digest context
    EVP_MD_CTX_free(mdctx);
    
    return true;
}

// Function to generate a random salt
bool generate_salt(unsigned char *salt) {
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        std::cerr << "Error generating salt" << std::endl;
        return false;
    }
    return true;
}

int main() {
    std::string password = "mysecurepassword";  // Password to hash
    unsigned char salt[SALT_SIZE];
    unsigned char hashed_password[EVP_MAX_MD_SIZE];

    // Generate a salt
    if (!generate_salt(salt)) {
        return 1;  // Error generating salt
    }

    // Hash the password with the salt
    if (!hash_password(password, salt, hashed_password)) {
        return 1;  // Error hashing password
    }

    // Print the salt (in hexadecimal format)
    std::cout << "Salt: ";
    for (int i = 0; i < SALT_SIZE; i++) {
        std::cout << std::hex << (int)salt[i];
    }
    std::cout << std::endl;

    // Print the hashed password (in hexadecimal format)
    std::cout << "Hashed Password: ";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        std::cout << std::hex << (int)hashed_password[i];
    }
    std::cout << std::endl;

    return 0;
}
