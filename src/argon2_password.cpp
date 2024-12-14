#include <iostream>
#include <cstring>
#include <argon2.h> // Include Argon2 library

#define SALT_LENGTH 16
#define HASH_LENGTH 32

// Function to generate a random salt
void generateSalt(unsigned char *salt, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        salt[i] = rand() % 256; // Random byte
    }
}

// Function to hash a password with Argon2
bool hashPassword(const std::string &password, unsigned char *salt, size_t saltLen, unsigned char *hash, size_t hashLen) {
    int result = argon2id_hash_raw(
        2,               // Number of iterations
        1 << 16,         // Memory usage (64 MB)
        1,               // Parallelism (threads)
        password.c_str(), password.length(),
        salt, saltLen,
        hash, hashLen
    );

    return result == ARGON2_OK;
}

// Function to verify a password against a stored hash
bool verifyPassword(const std::string &password, unsigned char *salt, size_t saltLen, unsigned char *storedHash, size_t hashLen) {
    unsigned char computedHash[HASH_LENGTH];
    if (!hashPassword(password, salt, saltLen, computedHash, HASH_LENGTH)) {
        return false; // Hashing failed
    }
    return memcmp(computedHash, storedHash, HASH_LENGTH) == 0;
}

int main() {
    // Input Module: Accept user password
    std::string password;
    std::cout << "Enter password: ";
    std::cin >> password;

    // Generate a random salt
    unsigned char salt[SALT_LENGTH];
    generateSalt(salt, SALT_LENGTH);

    // Hash the password
    unsigned char hash[HASH_LENGTH];
    if (!hashPassword(password, salt, SALT_LENGTH, hash, HASH_LENGTH)) {
        std::cerr << "Error: Password hashing failed!" << std::endl;
        return 1;
    }

    // Output the hashed password (for demonstration purposes)
    std::cout << "Password hashed successfully!" << std::endl;
    std::cout << "Hash: ";
    for (size_t i = 0; i < HASH_LENGTH; ++i) {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;

    // Validate the password
    std::string passwordToVerify;
    std::cout << "Re-enter password for verification: ";
    std::cin >> passwordToVerify;

    if (verifyPassword(passwordToVerify, salt, SALT_LENGTH, hash, HASH_LENGTH)) {
        std::cout << "Password verification successful!" << std::endl;
    } else {
        std::cerr << "Password verification failed!" << std::endl;
    }

    return 0;
}
