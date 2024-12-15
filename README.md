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


