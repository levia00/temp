## Exp1 - Caesar cipher
```
function caesarCipher(text, shift) {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    let char = text[i];
    if (char.match(/[a-z]/i)) { // Check if it's a letter
      const code = text.charCodeAt(i);
      let shiftedCode;

      if (char.match(/[a-z]/)) { // Lowercase
        shiftedCode = ((code - 97 + shift) % 26 + 26) % 26 + 97; // Ensure positive modulo
      } else { // Uppercase
        shiftedCode = ((code - 65 + shift) % 26 + 26) % 26 + 65; // Ensure positive modulo
      }
      result += String.fromCharCode(shiftedCode);
    } else {
      result += char; // Non-alphabetic characters remain unchanged
    }
  }
  return result;
}

// Example usage
const plaintext = "Hello, World!";
const shiftAmount = 3;
const ciphertext = caesarCipher(plaintext, shiftAmount);
console.log("Plaintext:", plaintext);
console.log("Ciphertext:", ciphertext);

const shiftedBack = caesarCipher(ciphertext, -shiftAmount);
console.log("Decrypted Text:", shiftedBack);
```
## Exp2 - Monoalphabetic cipher
```
function monoalphabeticCipher(text, key) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';

  for (let char of text.toLowerCase()) {
    if (alphabet.includes(char)) {
      const index = alphabet.indexOf(char);
      result += key[index];
    } else {
      result += char; // Non-alphabetic characters remain unchanged
    }
  }
  return result;
}

function monoalphabeticDecipher(ciphertext, key) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';

  for (let char of ciphertext.toLowerCase()) {
    const index = key.indexOf(char);
    if (index !== -1) {
      result += alphabet[index];
    } else {
      result += char;
    }
  }
  return result;
}

// Example usage
const plaintext = "hello world";
const key = "qwertyuiopasdfghjklzxcvbnm"; // Example key

const ciphertext = monoalphabeticCipher(plaintext, key);
console.log("Ciphertext:", ciphertext);

const decryptedText = monoalphabeticDecipher(ciphertext, key);
console.log("Decrypted Text:", decryptedText);
```
## Exp3 - Message Authentication code
```
import hashlib

def calculate_hashes(text):
    """Calculates and prints SHA hashes for the given text."""

    encoded_text = text.encode()

    # SHA-256
    sha256_hash = hashlib.sha256(encoded_text).hexdigest()
    print(f"The hexadecimal equivalent of SHA256 is: {sha256_hash}")

    # SHA-384
    sha384_hash = hashlib.sha384(encoded_text).hexdigest()
    print(f"The hexadecimal equivalent of SHA384 is: {sha384_hash}")

    # SHA-224
    sha224_hash = hashlib.sha224(encoded_text).hexdigest()
    print(f"The hexadecimal equivalent of SHA224 is: {sha224_hash}")

    # SHA-512
    sha512_hash = hashlib.sha512(encoded_text).hexdigest()
    print(f"The hexadecimal equivalent of SHA512 is: {sha512_hash}")

    # SHA-1
    sha1_hash = hashlib.sha1(encoded_text).hexdigest()
    print(f"The hexadecimal equivalent of SHA1 is: {sha1_hash}")

 Example usage
text = "GeeksforGeeks"
calculate_hashes(text)

 Example to verify data integrity:
original_text = "Data to be protected"
original_hash = hashlib.sha256(original_text.encode()).hexdigest()

 Simulate data transmission/storage (potentially altered)
received_text = "Data to be protected" # or "Data to be protected with a change"

received_hash = hashlib.sha256(received_text.encode()).hexdigest()

if original_hash == received_hash:
    print("\nData integrity verified: Hashes match.")
else:
    print("\nData integrity compromised: Hashes do not match.")
```
## Exp 4 - Data encryption standard
```
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_encrypt(plaintext, key):
    """Encrypts plaintext using DES."""
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(ciphertext, key):
    """Decrypts ciphertext using DES."""
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8')
    return plaintext

 Example usage
key = b'abcdefgh'  # 8-byte key
plaintext = "This is a secret message."

ciphertext = des_encrypt(plaintext, key)
print("Ciphertext:", ciphertext.hex())

decrypted_plaintext = des_decrypt(ciphertext, key)
print("Decrypted plaintext:", decrypted_plaintext)
```
## Exp 5 - Advanced Encryption Standard
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def aes_encrypt(plaintext, key):
    """Encrypts plaintext using AES-256-CBC."""
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = iv + cipher.encrypt(padded_plaintext) # iv prepended to ciphertext
    return ciphertext

def aes_decrypt(ciphertext, key):
    """Decrypts ciphertext using AES-256-CBC."""
    iv = ciphertext[:16] # extract the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext[16:]) # decrypt the ciphertext without the IV
    plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
    return plaintext

 Example usage (AES-256)
key = os.urandom(32)  # 32-byte key (256 bits)
plaintext = "This is a secret message."

ciphertext = aes_encrypt(plaintext, key)
print("Ciphertext (hex):", ciphertext.hex())

decrypted_plaintext = aes_decrypt(ciphertext, key)
print("Decrypted plaintext:", decrypted_plaintext)
```
## Exp 6 - Asymmetric Key Encryption
```
import math

def gcd(a, b):
    """Calculates the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def generate_keypair(p, q):
    """Generates RSA public and private keys."""
    n = p * q
    t = (p - 1) * (q - 1)

    # Find public key e
    e = 2
    while e < t:
        if gcd(e, t) == 1:
            break
        e += 1

    # Find private key d
    d = 1
    while (d * e) % t != 1:
        d += 1

    return (e, n), (d, n)

def encrypt(plaintext, public_key):
    """Encrypts the plaintext using the public key."""
    e, n = public_key
    ciphertext = pow(plaintext, e, n)
    return ciphertext

def decrypt(ciphertext, private_key):
    """Decrypts the ciphertext using the private key."""
    d, n = private_key
    plaintext = pow(ciphertext, d, n)
    return plaintext

 Example usage
p = 53
q = 59
plaintext = 89

public_key, private_key = generate_keypair(p, q)

ciphertext = encrypt(plaintext, public_key)
print("Ciphertext:", ciphertext)

decrypted_plaintext = decrypt(ciphertext, private_key)
print("Decrypted plaintext:", decrypted_plaintext)
```
## Exp 7 - secure key exchange
```
// Prompt for prime number and primitive root
const p = parseInt(prompt("Enter a prime number p (e.g., 23):"));
const g = parseInt(prompt("Enter a primitive root g of p (e.g., 5):"));

// Generate private keys (random numbers)
const alicePrivate = Math.floor(Math.random() * (p - 2)) + 1;
const bobPrivate = Math.floor(Math.random() * (p - 2)) + 1;
const eveA = Math.floor(Math.random() * (p - 2)) + 1;
const eveB = Math.floor(Math.random() * (p - 2)) + 1;

// Generate public keys
const alicePublic = Math.pow(g, alicePrivate) % p;
const bobPublic = Math.pow(g, bobPrivate) % p;
const evePublicA = Math.pow(g, eveA) % p;
const evePublicB = Math.pow(g, eveB) % p;

// Shared secrets
const sharedAliceEve = Math.pow(evePublicA, alicePrivate) % p;
const sharedEveAlice = Math.pow(alicePublic, eveA) % p;

const sharedBobEve = Math.pow(evePublicB, bobPrivate) % p;
const sharedEveBob = Math.pow(bobPublic, eveB) % p;

// Output
console.log("==== Private Keys ====");
console.log("Alice's private:", alicePrivate);
console.log("Bob's private:", bobPrivate);
console.log("Eve's private a, b:", eveA, eveB);

console.log("\n==== Public Keys ====");
console.log("Alice's public:", alicePublic);
console.log("Bob's public:", bobPublic);
console.log("Eve's public A:", evePublicA);
console.log("Eve's public B:", evePublicB);

console.log("\n==== Shared Secrets ====");
console.log("Alice ↔ Eve:", sharedAliceEve, sharedEveAlice);
console.log("Bob ↔ Eve:", sharedBobEve, sharedEveBob);
```
## Exp 8 - digital signature generation
```
(async () => {
  // Step 1: Generate RSA Key Pair
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  console.log("✅ RSA key pair generated");

  // Step 2: Message to sign
  const message = "This is a secret message.";
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  // Step 3: Sign the message using the private key
  const signature = await window.crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5"
    },
    keyPair.privateKey,
    data
  );

  // Convert signature to hex for display
  const hexSignature = Array.from(new Uint8Array(signature))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
  console.log("🔏 Signature (hex):", hexSignature);

  // Step 4: Verify the signature using the public key
  const isValid = await window.crypto.subtle.verify(
    {
      name: "RSASSA-PKCS1-v1_5"
    },
    keyPair.publicKey,
    signature,
    data
  );

  console.log("✅ Is the signature valid?", isValid);
})();
```
## Exp 9 - implementation of mobile security
```
import hashlib
import socket
import ssl
import base64
from cryptography.fernet import Fernet
import getpass

known_malicious_apps = {
    hashlib.md5("malicious_app".encode()).hexdigest()
}

def scan_apps(app_list):
    malicious_apps = []
    for app in app_list:
        app_hash = hashlib.md5(app.encode()).hexdigest()
        if app_hash in known_malicious_apps:
            malicious_apps.append(app)
    return malicious_apps

def generate_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

def monitor_network_traffic():
    print("📡 Monitoring network traffic... (simulated)")

def secure_connection(host, port):
    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print("🔐 Secure connection established to", host)
            print("   TLS version:", ssock.version())


def authenticate_user(username, password, stored_hash):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return password_hash == stored_hash

if __name__ == "__main__":
    print("\n🛡️ Basic Mobile Security Simulation\n")

    # Part 1: Scan for malicious apps
    apps = ["app1", "malicious_app"]
    malicious = scan_apps(apps)
    print("🕵️‍♂️ Malicious Apps Found:", malicious)

    # Part 2: Encrypt and Decrypt sensitive data
    key = generate_key()
    data = "This is a sensitive information"
    encrypted = encrypt_data(data, key)
    decrypted = decrypt_data(encrypted, key)
    print("\n🔐 Encrypted:", encrypted.decode())
    print("🔓 Decrypted:", decrypted)

    # Part 3: Simulate network traffic monitoring
    monitor_network_traffic()

    # Part 4: Establish secure TLS connection
    try:
        secure_connection("www.example.com", 443)
    except Exception as e:
        print("❌ Secure connection failed:", e)

    # Part 5: User authentication
    print("\n👤 User Authentication:")
    stored_hash = hashlib.sha256("secure_password".encode()).hexdigest()
    entered_user = input("Enter username: ")
    entered_pass = getpass.getpass("Enter password: ")
    if authenticate_user(entered_user, entered_pass, stored_hash):
        print("✅ Authentication successful!")
    else:
        print("❌ Authentication failed.")
```
## Exp 10 - IDS with snort algo
```
import re

attack_signatures = {
    "SQL Injection": r"(SELECT\s+.*\s+FROM|DROP\s+TABLE|--|;)",
    "XSS Attack": r"(<script>|javascript:)",
    "Port Scan": r"Nmap scan report",
    "Brute Force": r"Failed password for",
    "Path Traversal": r"(\.\./|\.\.\\)"
}

simulated_logs = [
    "User login failed: Failed password for root from 192.168.1.5",
    "GET /index.php?id=1;DROP TABLE users; --",
    "Nmap scan report for 192.168.1.100",
    "Normal traffic from 192.168.1.10",
    "<script>alert('Hacked!')</script>",
    "GET /../../etc/passwd"
]

def detect_intrusions(logs, signatures):
    alerts = []
    for log in logs:
        for attack_type, pattern in signatures.items():
            if re.search(pattern, log, re.IGNORECASE):
                alerts.append((attack_type, log))
    return alerts

if __name__ == "__main__":
    print("🛡️ Intrusion Detection System (Simulated Snort)\n")
    
    alerts = detect_intrusions(simulated_logs, attack_signatures)
    
    if alerts:
        for attack, log in alerts:
            print(f"🚨 ALERT: {attack} Detected!")
            print(f"    ➤ Log: {log}\n")
    else:
        print("✅ No intrusion detected.")

```
