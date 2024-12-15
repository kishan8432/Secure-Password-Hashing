#include <iostream>
#include <cstring>
#include <sodium.h> // Include libsodium for password hashing

#define SALT_LENGTH crypto_pwhash_SALTBYTES
#define HASH_LENGTH crypto_pwhash_STRBYTES

// Function to hash a password with Argon2 (using libsodium's crypto_pwhash)
bool hashPassword(const std::string &password, unsigned char *hash)
{
    unsigned char salt[SALT_LENGTH];
    randombytes_buf(salt, sizeof salt); // Generate a random salt

    // Hash the password using Argon2 (via libsodium's crypto_pwhash_str)
    return crypto_pwhash_str(
               (char *)hash,                       // Output hash buffer
               password.c_str(),                   // Input password
               password.length(),                  // Length of the password
               crypto_pwhash_OPSLIMIT_INTERACTIVE, // Iterations
               crypto_pwhash_MEMLIMIT_INTERACTIVE  // Memory usage
               ) == 0;
}

// Function to verify a password against a stored hash
bool verifyPassword(const std::string &password, const unsigned char *storedHash)
{
    return crypto_pwhash_str_verify((const char *)storedHash, password.c_str(), password.length()) == 0;
}

int main()
{
    // Initialize sodium (libsodium)
    if (sodium_init() < 0)
    {
        std::cerr << "libsodium initialization failed!" << std::endl;
        return 1;
    }

    // Input Module: Accept user password
    std::string password;
    std::cout << "Enter password: ";
    std::cin >> password;

    // Hash the password
    unsigned char hash[HASH_LENGTH];
    if (!hashPassword(password, hash))
    {
        std::cerr << "Error: Password hashing failed!" << std::endl;
        return 1;
    }

    // Output the hashed password (for demonstration purposes)
    std::cout << "Password hashed successfully!" << std::endl;
    std::cout << "Hash: ";
    for (size_t i = 0; i < HASH_LENGTH; ++i)
    {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;

    // Validate the password
    std::string passwordToVerify;
    std::cout << "Re-enter password for verification: ";
    std::cin >> passwordToVerify;

    if (verifyPassword(passwordToVerify, hash))
    {
        std::cout << "Password verification successful!" << std::endl;
    }
    else
    {
        std::cerr << "Password verification failed!" << std::endl;
    }

    return 0;
}
