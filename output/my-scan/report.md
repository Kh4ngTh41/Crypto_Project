# SAST SCAN REPORT

## Overview

This report presents the results of the security analysis of repo ****. The analysis was conducted by directly reviewing the source code and verifying each vulnerability.

### Vulnerability Summary
| Severity | Number of vulnerabilities |
|--- |--- |
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 1 |
| Total | 2 |

---

## HIGH VULNERABILITIES

---

### VULN-001: Path Traversal in Key Generation Endpoint Allows Arbitrary File Write (CWE-22)

**Severity:** HIGH

**Location:**
- File: `modules/crypto_utils.py`
- Line: 75-77

**Vulnerable code snippet:**
```
def save_pem(filename, pem_bytes):
    with open(filename, "wb") as f:
        f.write(pem_bytes)
```

**Explanation:**

### Path Traversal in Key Generation Endpoint Allows Arbitrary File Write



**CVSS3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` (Score: 7.1)



**Description:** The `/api/generate_key` endpoint accepts a `username` parameter from user-controlled JSON input and uses it to construct file paths without validation. The `save_pem()` function then opens these paths directly for writing. An attacker can supply a username containing directory traversal sequences (e.g., `../../etc/passwd`) to write PEM-encoded cryptographic key material to arbitrary locations on the server filesystem. Since the endpoint requires no authentication and is accessible over the network, any remote attacker can exploit this. The written content is constrained to PEM-encoded key material, which limits but does not eliminate the risk of overwriting critical files.



**Impact:**

An attacker can write PEM-encoded cryptographic key material to arbitrary file paths the web server process has write access to. This can be used to overwrite configuration files, inject malicious scripts into cron jobs or web-accessible directories, or corrupt existing key files. While the content written is not fully attacker-controlled (it's generated key material), overwriting critical system files can lead to privilege escalation or service disruption.



**Affected Entry Points:**

| Type | Identifier | File | Route | Description |

|------|------------|------|-------|-------------|

| http_endpoint | `api_generate_key` | app.py | `/api/generate_key` | POST /api/generate_key — accepts a username parameter that is used to construct file paths without validation, allowing path traversal to write arbitrary files |



**Data Flow:**

|   Level | Name             | File Path               | Line   |

|--------:|:-----------------|:------------------------|:-------|

|       1 | api_generate_key | app.py                  | 25-60  |

|       2 | save_pem         | modules/crypto_utils.py | 74-76  |



```

[SOURCE] api_generate_key (app.py:28)

    username = data.get("username")  -- user-controlled input

    |

    v

[STEP] api_generate_key (app.py:36)

    pub_file = f"{KEY_DIR}/{username}.ecdsa.pub.pem"  -- concatenated into file path

    |

    v

[STEP] save_pem (modules/crypto_utils.py:75)

    filename  -- passed as argument

    |

    v

[SINK] save_pem (modules/crypto_utils.py:76)

    >>> open(filename, "wb")

```



**Evidence:**

```

def api_generate_key():

    data = request.get_json()

    username = data.get("username")  # <-- [VULN] attacker-controlled input

    key_type = data.get("key_type")

    passphrase = data.get("passphrase", "")

    passphrase_bytes = passphrase.encode()



    try:

        if key_type == "ECDSA":

            pub_bytes, priv_bytes = ecdsa_keygen(passphrase_bytes)

            pub_file = f"{KEY_DIR}/{username}.ecdsa.pub.pem"  # <-- [VULN] traversal sequences not sanitized

            priv_file = f"{KEY_DIR}/{username}.ecdsa.priv.pem"  # <-- [VULN] traversal sequences not sanitized

        elif key_type == "RSA":

            pub_bytes, priv_bytes = rsa_keygen(passphrase_bytes)

            pub_file = f"{KEY_DIR}/{username}.rsa.pub.pem"

            priv_file = f"{KEY_DIR}/{username}.rsa.priv.pem"

        elif key_type == "ML-DSA":

            pub_bytes, priv_bytes = mldsa_keygen(passphrase_bytes)

            pub_file = f"{KEY_DIR}/{username}.mldsa.pub"

            priv_file = f"{KEY_DIR}/{username}.mldsa.priv"

        else:

            return jsonify({"success": False, "message": "Loại khóa không hợp lệ"}), 400



        save_pem(pub_file, pub_bytes)  # <-- [VULN] unsanitized path reaches file write

        save_pem(priv_file, priv_bytes)

        ...



def save_pem(filename, pem_bytes):

    with open(filename, "wb") as f:  # <-- [VULN] no path validation — arbitrary file write

        f.write(pem_bytes)

```



**References:**



- CWE: CWE-22

- OWASP: A01:2021 - Broken Access Control



---

## MEDIUM VULNERABILITIES

---

### VULN-002: AES-CBC Encryption Lacks Integrity Protection (Padding Oracle Risk) (CWE-327)

**Severity:** MEDIUM

**Location:**
- File: `modules/crypto_utils.py`
- Line: 12-19

**Vulnerable code snippet:**
```
def encrypt_bytes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext
```

**Explanation:**

### AES-CBC Encryption Lacks Integrity Protection (Padding Oracle Risk)



**CVSS3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (Score: 5.4)



**Description:** The encrypt_bytes function encrypts data using AES in CBC mode, which only provides confidentiality — not integrity. Without an integrity check (such as HMAC) or an authenticated encryption mode (such as AES-GCM), an attacker who can observe ciphertext and influence decryption can exploit padding validation errors to recover plaintext without knowing the encryption key. This is known as a padding oracle attack. In this application, the function is used to encrypt ML-DSA private keys when they are generated through the /api/generate_key endpoint. The decrypted private key material could be recovered if an attacker can craft malicious ciphertext and observe whether decryption succeeds or fails.



**Impact:**

An attacker who can intercept or craft ciphertext values and observe decryption outcomes (e.g., error messages vs. success responses) can decrypt encrypted private keys without knowing the encryption key. This compromises the confidentiality of stored cryptographic keys. Additionally, an attacker could manipulate ciphertext to produce chosen plaintext when decrypted, potentially injecting malicious content into private key files.



**Affected Entry Points:**

| Type | Identifier | File | Route | Description |

|------|------------|------|-------|-------------|

| http_endpoint | `api_generate_key` | app.py | `/api/generate_key` | POST /api/generate_key — Generates cryptographic keys (ECDSA, RSA, ML-DSA) and encrypts private keys using encrypt_bytes. The ML-DSA path calls mldsa_keygen which uses encrypt_bytes to protect the private key with the user's passphrase. |



**Data Flow:**

|   Level | Name             | File Path               | Line   |

|--------:|:-----------------|:------------------------|:-------|

|       1 | api_generate_key | api/routes.py           |        |

|       2 | mldsa_keygen     | modules/crypto_utils.py | 64-72  |

|       3 | encrypt_bytes    | modules/crypto_utils.py | 11-18  |



```

[SOURCE] mldsa_keygen (modules/crypto_utils.py:65)

    passphrase  -- user-controlled input

    |

    v

[STEP] derive_key_from_passphrase (modules/crypto_utils.py:30)

    key  -- derived from passphrase using PBKDF2

    |

    v

[SINK] encrypt_bytes (modules/crypto_utils.py:12)

    >>> cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

```



**Evidence:**

```

def encrypt_bytes(key, plaintext):

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # <-- [VULN] AES-CBC provides no integrity protection

    encryptor = cipher.encryptor()

    pad_len = 16 - (len(plaintext) % 16)

    padded = plaintext + bytes([pad_len] * pad_len)

    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext  # <-- [VULN] No HMAC or authentication tag appended





def decrypt_bytes(key, ciphertext):

    iv = ciphertext[:16]

    data = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    decryptor = cipher.decryptor()

    padded = decryptor.update(data) + decryptor.finalize()  # <-- [VULN] Padding validation leaks oracle information via exceptions

    pad_len = padded[-1]

    return padded[:-pad_len]

```



**References:**



- CWE: CWE-327

- OWASP: A02:2021 - Cryptographic Failures



---

