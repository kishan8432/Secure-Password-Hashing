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

- **SHA256_password.cpp**: Implements SHA-256 password hashing using OpenSSL.
- **argon2_password.cpp**: Implements Argon2 password hashing using Libsodium.

## Usage

### Compile the code for SHA-256 and Argon2 hashing

#### To compile the SHA-256 hashing code:
```bash
g++ -o sha256_password_hashing SHA256_password.cpp -lssl -lcrypto

