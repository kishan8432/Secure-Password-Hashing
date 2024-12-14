#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

#define SALT_SIZE 16   // 128-bit salt
#define HASH_LENGTH 32 // SHA-256 produces a 32-byte hash

// Function to hash a password with salt using SHA-256
bool hash_password(const std::string &password, unsigned char *salt, unsigned char *output_hash)
{
    EVP_MD_CTX *mdctx;
    unsigned int md_len = 0;
    unsigned char md_value[EVP_MAX_MD_SIZE];

    // Initialize OpenSSL message digest context
    mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr)
    {
        std::cerr << "Error creating EVP_MD_CTX" << std::endl;
        return false;
    }

    // Initialize SHA-256 hash function
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
    {
        std::cerr << "Error initializing digest" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Update the hash with salt and password
    if (EVP_DigestUpdate(mdctx, salt, SALT_SIZE) != 1)
    {
        std::cerr << "Error updating digest with salt" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    if (EVP_DigestUpdate(mdctx, password.c_str(), password.length()) != 1)
    {
        std::cerr << "Error updating digest with password" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Finalize the digest (this gives the hashed value)
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1)
    {
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
bool generate_salt(unsigned char *salt)
{
    if (RAND_bytes(salt, SALT_SIZE) != 1)
    {
        std::cerr << "Error generating salt" << std::endl;
        return false;
    }
    return true;
}

// Function to compare two hashes
bool compare_hashes(unsigned char *hash1, unsigned char *hash2, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        if (hash1[i] != hash2[i])
        {
            return false;
        }
    }
    return true;
}

int main()
{
    std::string password = "mysecurepassword"; // Password to hash
    unsigned char salt[SALT_SIZE];
    unsigned char stored_hash[HASH_LENGTH];
    unsigned char entered_hash[HASH_LENGTH];

    // Generate a salt and hash the password with it
    if (!generate_salt(salt))
    {
        return 1; // Error generating salt
    }

    if (!hash_password(password, salt, stored_hash))
    {
        return 1; // Error hashing password
    }

    // Simulate entering the password for verification
    std::string entered_password;
    std::cout << "Enter password to verify: ";
    std::cin >> entered_password;

    // Hash the entered password with the stored salt
    if (!hash_password(entered_password, salt, entered_hash))
    {
        return 1; // Error hashing entered password
    }

    // Compare the entered hash with the stored hash
    if (compare_hashes(stored_hash, entered_hash, HASH_LENGTH))
    {
        std::cout << "Password verified successfully!" << std::endl;
    }
    else
    {
        std::cout << "Invalid password!" << std::endl;
    }

    // Print the salt (in hexadecimal format)
    std::cout << "Salt: ";
    for (int i = 0; i < SALT_SIZE; i++)
    {
        std::cout << std::hex << (int)salt[i];
    }
    std::cout << std::endl;

    // Print the stored hashed password (in hexadecimal format)
    std::cout << "Stored Hashed Password: ";
    for (int i = 0; i < HASH_LENGTH; i++)
    {
        std::cout << std::hex << (int)stored_hash[i];
    }
    std::cout << std::endl;

    return 0;
}
