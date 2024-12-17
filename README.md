
# Crypto-Machine Simulator 
# Quantum Cryptography and Post-Quantum Hybrid Secure Communication

## Overview
This project implements a **hybrid cryptographic communication system** that integrates Quantum Key Distribution (QKD) with Post-Quantum Cryptography (PQC) mechanisms to securely exchange messages. It includes robust mechanisms for:
- Key encapsulation using **CRYSTALS-Kyber** and **McEliece** algorithms.
- Authentication via **Dilithium** (Post-Quantum Digital Signatures).
- Quantum Key Distribution using the **BB84 protocol** with Cascade error correction.

The system dynamically assesses the environment's fiber parameters and determines the most suitable secure communication protocol (QKD or PQC) for optimal security and efficiency.

## Features
- **QKD with BB84**: Utilizes time-bin or polarization encoding for secure key exchange.
- **Post-Quantum Cryptography**: Supports:
  - CRYSTALS-Kyber for Key Encapsulation (KEM)
  - McEliece for alternate KEM
  - Dilithium for message authentication
- **AES-256 Encryption**: Ensures confidentiality for exchanged messages.
- **Dynamic Strategy Selection**: The system evaluates fiber parameters and decides:
  - **Static Strategy**: Evaluates fiber parameters to choose QKD or PQC.
  - **Always Try Strategy**: Attempts QKD before falling back to PQC.
- **Authentication Modules**: Implements HMAC-based OTPs (HOTP) and Dilithium signatures for secure device communication.

## Project Structure
```
.
├── config.json                 # Configuration file for simulation parameters
├── code.py                     # Main implementation
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

### Key Components
1. **`cryptoMachine`**: Implements hybrid cryptographic communication.
2. **`QKDManager`**: Manages QKD processes and key exchange using BB84 and Cascade protocols.
3. **`PQCModulesFactory`**: Handles PQC algorithms (Kyber and McEliece).
4. **`authenticationModule`**: Generates HOTPs and Dilithium-authenticated messages.
5. **`AES256`**: Encrypts and decrypts messages with a derived AES-256 key.
6. **`strategyFactory`**: Creates and applies key exchange strategies.

## Prerequisites
- Python 3.8+
- Libraries:
  - SEQUENCE library for QKD simulation
  - pycryptodome and cryptography for encryption
  - pqcrypto for post-quantum cryptographic algorithms
  - numpy for error rate calculations

### Install Dependencies
Run the following command to install the required libraries:
```bash
pip install -r requirements.txt
```

## Configuration
The behavior of the program can be manipulated by editing the `config.json` file. Here is an example:
```json
{
  "qkdParameters": {
    "simTime": 100,
    "keyDim": 256,
    "attenuation": 0.01,
    "polarizationFid": 0.99,
    "distance": 10000
  },
  "executionParameters": {
    "pqcModule": 0,       # 0 for Kyber, 1 for McEliece
    "executionStrategy": 0  # 0 for Static Strategy, 1 for Always Try Strategy
  }
}
```

## Usage
1. Run the program:
   ```bash
   python code.py
   ```
2. Input a message when prompted:
   ```
   Provide a message to share over the Encrypted Channel: Hello Quantum World!
   ```
3. The program will:
   - Assess the communication environment.
   - Execute QKD or PQC-based key exchange.
   - Encrypt and securely transmit the message.

4. Output example:
   ```
   - Crypto-Machines created, coupled, and connected!
   [!] Starting Secret Message Exchange Session...
   [!] Exchange correctly achieved...
       - Sent message: Hello Quantum World!
       - Received message: Hello Quantum World!
       - Shared Key Sender-Side:   <key>
       - Shared Key Receiver-Side: <key>
   ```

## Key Exchange Methods
| Method                  | Description                                               |
|-------------------------|-----------------------------------------------------------|
| **QKD**                | Quantum key exchange via BB84 with Cascade error correction. |
| **CRYSTALS-Kyber**     | NIST-approved PQC algorithm for KEM.                       |
| **McEliece**           | Alternative KEM based on code-based cryptography.          |
| **Dilithium**          | Post-quantum digital signature for HOTP authentication.    |

## License
This project is released under the MIT License.

## Acknowledgments
- SEQUENCE library for QKD simulations.
- NIST's post-quantum cryptographic standards for Kyber and Dilithium.

---

## Future Improvements
- Support for real-world QKD hardware integration.
- Extend compatibility with additional PQC algorithms.

---

## Authors
[Your Name/Team Name]  
[Contact Information]

---

**Secure your communications with quantum and post-quantum cryptography!**
