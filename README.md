# Secure Password Hashing Project

This project implements secure password hashing using two algorithms:

- **SHA-256** (with OpenSSL)
- **Argon2** (with Libsodium)

## Overview

The project demonstrates the secure password hashing process using two popular cryptographic algorithms for secure password storage. The implementation is done in **C++** on **Ubuntu**.

- **SHA-256** is a widely-used cryptographic hash function from the SHA-2 family. It is implemented using **OpenSSL**.
- **Argon2** is the winner of the Password Hashing Competition and is considered the most secure algorithm for hashing passwords, implemented using **Libsodium**.

## Setup

### Prerequisites

- **Ubuntu** operating system (This project is set up for Ubuntu).
- **OpenSSL** library (for SHA-256 hashing).
- **Libsodium** library (for Argon2 hashing).
- **g++** for compiling the C++ code.

### Installing Dependencies

To install the required dependencies on Ubuntu, run the following commands:

```bash
# Install OpenSSL (for SHA-256)
sudo apt-get update
sudo apt-get install libssl-dev

# Install Libsodium (for Argon2)
sudo apt-get install libsodium-dev

# Install g++ (for compiling the C++ code)
sudo apt-get install g++

## Files
SHA256_password.cpp: Implements SHA-256 password hashing using OpenSSL.
argon2_password.cpp: Implements Argon2 password hashing using Libsodium.
Usage
Compile the code for SHA-256 and Argon2 hashing
To compile the SHA-256 hashing code:

bash
Copy code
g++ -o sha256_password_hashing SHA256_password.cpp -lssl -lcrypto
To compile the Argon2 hashing code:
bash
Copy code
g++ -o argon2_password_hashing argon2_password.cpp -lsodium
Run the programs to hash a password securely
For SHA-256:

bash
Copy code
./sha256_password_hashing
For Argon2:

bash
Copy code
./argon2_password_hashing
Verify the Password (in Both Algorithms)
After hashing a password, you can verify the password by comparing the entered password's hash with the stored hash.
The verification functions are built into both implementations.

How it Works
The user enters a password.
The password is hashed using either SHA-256 or Argon2 (with salt for both).
The resulting hash is stored (you can print it to the console or save it to a file).
When verifying a password, the entered password is hashed again, and the hashes are compared.
Benefits
SHA-256:
While SHA-256 is secure for many purposes, it is not ideal for password hashing due to its speed, which makes it vulnerable to brute-force attacks.

Argon2:
Specifically designed for password hashing, Argon2 is computationally intensive and resistant to GPU-based attacks, making it a more secure choice for password storage.

License
This project is licensed under the MIT License - see the LICENSE file for details.