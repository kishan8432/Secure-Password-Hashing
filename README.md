# Secure Password Hashing Project

This project implements secure password hashing using two algorithms:

- **SHA-256** (with OpenSSL)  
- **Argon2** (with Libsodium)

---

## Overview

This project demonstrates the secure password hashing process using two popular cryptographic algorithms for secure password storage. The implementation is done in **C++** on **Ubuntu**.

- **SHA-256**: A widely-used cryptographic hash function from the SHA-2 family, implemented using **OpenSSL**.
- **Argon2**: The winner of the Password Hashing Competition, considered the most secure algorithm for password hashing, implemented using **Libsodium**.

---

## Setup

### Prerequisites

Ensure the following are installed on your Ubuntu system:

- **Ubuntu** operating system  
- **OpenSSL** library (for SHA-256 hashing)  
- **Libsodium** library (for Argon2 hashing)  
- **g++** compiler (for compiling the C++ code)  

### Installing Dependencies

Run the following commands to install the required dependencies:

```bash
# Install OpenSSL (for SHA-256)
sudo apt-get update
sudo apt-get install libssl-dev

# Install Libsodium (for Argon2)
sudo apt-get install libsodium-dev

# Install g++ (for compiling the C++ code)
sudo apt-get install g++
```
## Files

- **SHA256_password.cpp**: Implements SHA-256 password hashing using OpenSSL.  
- **argon2_password.cpp**: Implements Argon2 password hashing using Libsodium.  

---

## Usage

### Compile the Code

#### To compile the SHA-256 hashing code:
```bash
g++ -o SHA256_password_hashing SHA256_password.cpp -lssl -lcrypto
```

#### To compile the Argon2 hashing code:
```bash
g++ -o argon2_password_hashing argon2_password.cpp -lsodium
```

### Run the Programs to Hash a Password Securely

#### For SHA-256:
```bash
./sha256_password_hashing
```

#### For Argon2:
```bash
./argon2_password_hashing
```

## Verify the Password (in Both Algorithms)

After hashing a password, you can verify it by comparing the entered password's hash with the stored hash.  
The verification functions are built into both implementations.

## How it Works

1. The user enters a password.
2. The password is hashed using either **SHA-256** or **Argon2** (with salt for both).
3. The resulting hash is stored (you can print it to the console or save it to a file).
4. When verifying a password, the entered password is hashed again, and the hashes are compared.

## Benefits

### SHA-256
- While **SHA-256** is secure for many purposes, it is not ideal for password hashing due to its speed, making it vulnerable to brute-force attacks.

### Argon2
- Specifically designed for password hashing, **Argon2** is computationally intensive and resistant to GPU-based attacks, making it a more secure choice for password storage.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.







