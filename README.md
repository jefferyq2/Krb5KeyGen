# Krb5KeyGen

## 📑 Table of Contents

- [❓ What is Krb5KeyGen?](#-what-is-krb5keygen)
- [⭐ Features](#-features)
- [⚙️ Installation](#%EF%B8%8F-installation)
- [▶️ Execution](#%EF%B8%8F-execution)
- [📜 License](#-license)

## ❓ What is **Krb5KeyGen**?

**Krb5KeyGen** is a tool designed to generate NTLM and Kerberos AES encryption keys based on user-provided credentials, domain information, and optional iteration counts.

## ⭐ Features

- Generate NTLM (RC4-HMAC) key.
- Generate AES128 and AES256 Kerberos keys with specified or default iteration counts.

## ⚙️ Installation

### Prerequisites

Ensure you have:

- Python 3.7 or higher

### Clone the Repository

```bash
git clone https://github.com/yourusername/Krb5KeyGen.git
cd Krb5KeyGen
```

## ▶️ Execution

To run **Krb5KeyGen**, use the following syntax:

```bash
python krb5_key_gen.py <username> <password> <domain> [--iterations <iterations>]
```

- `<username>`: The case-sensitive username (e.g., `Administrator` is different from `administrator`).
- `<password>`: The user’s password.
- `<domain>`: The domain, which can be in uppercase or lowercase (e.g., `CONTOSO.LOCAL` or `contoso.local`).
- `--iterations <iterations>` (optional): Specify the number of iterations (default is 4096, commonly used in Kerberos and Active Directory).

### Example Commands

Generate keys with the default iteration count (4096):

```bash
python krb5_key_gen.py alice "mypassword123" contoso.local
```

Generate keys with a custom iteration count:

```bash
python krb5_key_gen.py alice "mypassword123" contoso.local --iterations 5000
```

### Output

The output will include the following:

- **NTLM Key (RC4-HMAC)**: NTLM hash-based key.
- **AES128 Key**: AES 128-bit key for Kerberos.
- **AES256 Key**: AES 256-bit key for Kerberos.

```bash
$> python .\krb5_key_gen.py javier password contoso.local
Key NTLM (RC4-HMAC): 8846f7eaee8fb117ad06bdd830b7586c
Key AES128: 87e00e150694edbf7cedbc4d0ccbca5f
Key AES256: c59c4adaaf06d6758b825e088178aa9fa66639b4dc3b160a6b347704dfd64b9e
```

> **Note**: By default, the tool uses 4096 iterations unless a different value is specified.

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for more information.
