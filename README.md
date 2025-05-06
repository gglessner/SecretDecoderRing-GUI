# SecretDecoderRing Module

The `SecretDecoderRing` module is a component of the **HACKtiveMQ Suite**, designed to decrypt ciphertexts using various encryption algorithms and modes on a Windows, Linux or MacOS system. It provides a graphical interface to input ciphertexts, keys, and IVs/nonces, and attempts decryption using multiple cryptographic modules.

## Overview

The `SecretDecoderRing` module enables users to:
- Input ciphertexts, keys, and IVs/nonces in Base64, HEX, or ASCII formats.
- Load ciphertexts from files, sort and deduplicate them, and save results to CSV files.
- Attempt decryption using multiple encryption modules (e.g., AES, 3DES, Blowfish, CAST5, ChaCha20) stored in `modules/SecretDecoderRing_modules`.
- Display decryption results in a table, showing ciphertext, plaintext, algorithm, mode, key, and IV/nonce for successful decryptions with typeable ASCII output.
- Log all actions (input processing, decryption attempts, errors) in a status window.

The module dynamically loads encryption modules from the `modules/SecretDecoderRing_modules` directory, which is created automatically if it does not exist.

## Requirements

### Software
- **Python**: Version 3.8 or later recommended.

### Python Dependencies
The following Python packages are required, as specified in `requirements.txt`:
PySide6>=6.0.0
pycryptodome>=3.10.0

## Installation

1. **Obtain the Module**:
   - The `SecretDecoderRing` module is part of the HACKtiveMQ Suite. Clone or download the suite repository, or extract the `4_SecretDecoderRing.py` file and its dependencies.

2. **Install Python Dependencies**:
   - Create a virtual environment (optional but recommended):
     ```bash
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - Install the required packages:
     ```bash
     pip install -r requirements.txt
     ```
   - Alternatively, install directly:
     ```bash
     pip install PySide6>=6.0.0 pycryptodome>=3.10.0
     ```

3. **Set Up Encryption Modules**:
   - Place encryption module files (e.g., `AES_v1.1.py`, `3DES_v1.0.py`, `Blowfish_v1.0.py`, `CAST5_v1.0.py`, `ChaCha20_v1.0.py`) in the `modules/SecretDecoderRing_modules` directory.
   - The module will create this directory automatically if it does not exist.
   - Ensure each module has a `decrypt` function compatible with the interface defined in `AES_v1.1.py`.

## Usage

1. **Launch the Module**:
   - Run the `SecretDecoderRing` module via the ningu framework or the HACKtiveMQ Suite.

2. **Input Data**:
   - **Key**: Enter the encryption key in the `Key` field (Base64, HEX, or ASCII format).
   - **IV/Nonce**: Enter the initialization vector or nonce in the `IV/Nonce` field (optional; defaults to 16 null bytes if empty).
   - **Ciphertext**: Enter one or more ciphertexts in the `CipherText` text box, one per line, or load from a file using the `Load` button.
   - Select the input format (Base64, HEX, ASCII) for each field using the respective combo boxes.

3. **Manage Ciphertexts**:
   - **Load**: Load ciphertexts from a `.txt` file into the `CipherText` text box.
   - **Save**: Save the `CipherText` text box contents to a `.txt` file.
   - **Clear**: Clear the `CipherText` text box.
   - **Sort+Dedup**: Sort and deduplicate ciphertext lines in the `CipherText` text box.

4. **Decrypt**:
   - Click the `Decrypt` button or press `Enter` in the `Key` field to attempt decryption.
   - The module processes each ciphertext using all loaded encryption modules (e.g., AES with modes ECB, CBC, CFB, OFB, CTR, GCM, EAX).
   - Successful decryptions producing typeable ASCII (printable characters 32-126) are displayed in the `PlainText` table with columns: Ciphertext, Plaintext, Algorithm, Mode, Key, IV/Nonce.
   - Logs in the `Status` text box detail input processing, decryption attempts, and errors (e.g., `Decryption succeeded with AES_v1_1 in CBC mode`, `Error processing ciphertext: Invalid base64 input`).

5. **Manage Plaintext**:
   - **Save**: Save the `PlainText` table contents to a `.csv` file.
   - **Clear**: Clear the `PlainText` table.

## Directory Structure
```
HACKtiveMQ_Suite/
├── modules/
│   ├── SecretDecoderRing_modules/   # Place encryption modules here
│   │   ├── AES_v1.1.py
│   │   ├── 3DES_v1.0.py
│   │   ├── Blowfish_v1.0.py
│   │   ├── CAST5_v1.0.py
│   │   ├── ChaCha20_v1.0.py
│   │   └── ...
└── 4_SecretDecoderRing.py          # SecretDecoderRing module
```

## Limitations
- **Encryption Modules**: Requires properly formatted modules in `modules/SecretDecoderRing_modules` with a `decrypt` function. Missing or incompatible modules will prevent decryption.
- **ASCII Output**: Only decryptions producing typeable ASCII (printable characters 32-126) are displayed in the `PlainText` table.

## Troubleshooting
- **No Decryption Results**:
  - Ensure encryption modules are in `modules/SecretDecoderRing_modules` and have a valid `decrypt` function.
  - Verify that the key, IV/nonce, and ciphertext formats match the expected input (e.g., correct Base64 or HEX).
  - Check the `Status` text box for errors (e.g., `Error processing Key: Invalid hex characters`).
- **Modules Not Loaded**:
  - Confirm the `modules/SecretDecoderRing_modules` directory exists and contains `.py` files.
  - Check for error messages in the `Status` text box (e.g., `Error: Directory 'modules/SecretDecoderRing_modules' not found`).
- **Permission Issues**:
  - Run the application with administrator privileges if directory creation or file access fails.
- **Invalid Input**:
  - Ensure ciphertexts, keys, and IVs/nonces are valid for the selected format (Base64, HEX, ASCII).
  - Review the `Status` text box for specific error messages.

## Contributing
Contributions to the `SecretDecoderRing` module are welcome! To contribute:
1. Fork the HACKtiveMQ Suite repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please test changes on Windows and ensure compatibility with the module’s functionality and encryption modules.

## License
This module is licensed under the GNU General Public License v3.0. See the [LICENSE](https://www.gnu.org/licenses/) file for details.

## Contact
For issues, questions, or suggestions, contact Garland Glessner at gglesner@gmail.com.
