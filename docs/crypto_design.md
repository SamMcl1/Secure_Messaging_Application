# Cryptographic Design Document

**Group:** The Hangover  
**Module:** CS4455 Cybersecurity  
**Date:** 2026-05-18

---

## 1. Threat Model

Identify which security properties hold against each attacker class:

| Attacker | Confidentiality | Integrity | Authenticity |
|---|---|---|---|
| Passive network attacker | | | |
| Active network attacker | | | |
| Honest-but-curious server | | | |
| Fully compromised server | | | |

Properties NOT held under server compromise must be named explicitly here.

---

## 2. End-to-End Authenticated Encryption

**Scheme chosen:**  
**Justification:**  
**Nonce strategy:**  
**Associated data:**  

---

## 3. Key Establishment and Sender Authentication

**Protocol:**  
**Trust model:**  
**Key publication/lookup:**  
**Forward secrecy properties (or absence thereof):**  

---

## 4. Password and Key Derivation

**Password hashing function:** (e.g. Argon2id)  
**Parameters and justification:**  
**HKDF info strings and domain separation:**  
**At-rest protection of long-term private keys:**  

---

## 5. Construction Walkthrough

### 5.1 Registration

### 5.2 Key Publication

### 5.3 Send Message

### 5.4 Receive Message

### 5.5 Storage at Rest

---

## 6. Known Limitations

State explicitly what the design does not protect against.

---

## 7. References

Cite all RFCs, papers, and specifications with section numbers where relevant.
