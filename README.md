# Skycryptor Python SDK
[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)


## Introduction
[Skycryptor](http://skycryptor.com), SAS, is a Paris, France, based cybersecurity company and a graduate of the Techstars Paris 2017 accelerator program.

We provide "Encryption & Key Management" service in operation with open sourced libraries with support for Javascript, Python, Go, Rust, Java, C++ languages.

Our goal is to enable developers to build ’privacy by design’, end-to-end secured applications, without any technical complexities.

[Skycryptor](http://skycryptor.com) Python SDK provides Key Management Service along with fast data encryption capabilities for adding data privacy & 
cryptographic access control layer into your app with just few lines of code. These easy to use SDK and APIs enable to Encrypt, Decrypt and Manage Access 
of all kinds of data by eliminating data exposure risks and also helping to stay compliant with HIPPA, GDPR and other data regulations.

Use these tools for adding privacy by design into your apps starting from storage encryption or KYC platform to password-less authentication and more. 

One key utility Skycryptor KMS brings to the table are Proxy Re-Encryption algorithms, which enables to build scalable Public Key Infrastructure with 
powerfull access control capabilities.

## Proxy Re-Encryption Overview

Proxy Re-Encryption is a new type of public key cryptography designed to eliminate some major functional constraints associated with standard 
public key cryptography.It starts from extending the standard public key cryptography setup via the third actor - a proxy service. The Proxy service then 
can be authorized by Alice to take any cyphertext encrypted under Alice's public key, and transform (also named re-encrypt) it under Bob's public key. 
The transformed cyphertext can be decrypted by Bob later. 

For making re-encryption, Proxy Service should be provided a special re-encryption key, which is created by Alice specially for Bob. 
The Re-Encryption key generation requires Alice's private key and Bobs' public key. This means  re-encryption key can be generated only by Alice 
and without any interaction with Bob.
It is very important to note, that the proxy service once given the re-encryptin key from Alice to Bob, can re-encrypt Alice's cyphertexts without being able to decrypt them or
get any extra information about the original plaintext. 

Our Data Encapsulation and Proxy Re-Encryption algorithms are and based on standard ECIES approach and are implemented with [OpenSSL] (https://www.openssl.org/) and [libsodium](https://github.com/jedisct1/libsodium) 
utilizing seckp256k1 elliptic curves and based on standard ECIES approach.


## SDK Features

- Generate and Manage User's Public and Private keys.  
- Enable users to generate Re-Encryption keys for their peers.
- Encapsulate a symmetric encryption key via given Public Key (similar to Diffie-Hellman Key Exchange)
- Perform Re-Encryption for the given ciphertext and the re-encryption key
- Decrypt both the original or transformed ciphertexts in order to reveal the encapsulated symmetric encryption key.

## Installation
This is a standard Python package, but it requires to install OpenSSL package separately.
```bash
~# # Install OpenSSL here, depends on OS you are running
~# git clone github.com/skycryptor/skycryptor-sdk-python.git

# Compile Skycryptor C++ library and combine it with SDK
~# cd skycryptor-sdk-python
~# python3 setup.py build
~# python3 setup.py clean
```

## Usage Examples
Before using our SDK make sure to successfully complete the [Installation](#installation) step.


### Initalization


```python 
import skycryptor

from skycryptor.skycryptor import SkyCryptor
from skycryptor.skycryptor import SkyCryptor
from skycryptor.private_key import PrivateKey
from skycryptor.public_key import PublicKey
from skycryptor.re_key import ReEncryptionKey
from skycryptor.capule import Capsule


....

  # Initialize new Skycryptor context from the default encryption context 
  sc = Skycryptor()
```

#### Generate User's Public and Private Keys  
```python
  # randomly generates the private key and corresponding public key 
  alice_private_key = sc.generate()
  alice_public_key = alice_private_key.get_public_key()
  
  bob_private_key = sc.generate()
  bob_public_key = bob_private_key.get_public_key()
  
```
#### Generate random symmetric key and encapsulate it with the Alice's Public Key 
```python
  # Encapsulate function is a Diffie-Hellman style key exchange with randomly generated temprorary keys and Alice Public Key. 
  # It returns both the exchanged symmetric key and the capsule which can be decapsulated later by the corresponding private key
  # The generated symmetric_key can be used to protect and data object. 
  capsule, symmetric_key = alice_public_key.encapsulate()
  
```

#### Revealing the symmetric key by unlocking the original capsule
```python
  # Alice can unlock the capsule and reveals the symmetric encryption key with her own private key
  
  symmetric_key_1 = alice_private_key.decapsulate(capsule)
  if symmetric_key != symmetric_key_1:
      print("Symmetric keys should be equal!")
  
```


#### Re-Encryption Key Generation
```python
  # Alice can create re-encryption key for Bob, which can later be used by the Proxy Service for transform capsules,  
  # locked under Alice's public  key, to another capsule locked under  Bob's public key
  
  re_key_alice_bob = alice_private_key.generate_re_encryption_key(bob_public_key)
```

#### Capsule Transformation (Re-Encryption)
```python
  # Given the re-encryption key re_key_alice_bob, the Proxy Service can transform the capsule locked under Alice's public key, 
  # to another capsule, which is already locked under Bob's public key
  
  transformed_capsule = re_key_alice_bob.re_encrypt(capsule)
```


#### Recovering the symmetric key by unlocking the transformed (re-encrypted) capsule
```python
  # Bob can unlock the transformed capsule and reveal the symmetric encryption key with his own private key
  
  symmetric_key_2 = bob_private_key.decapsulate(transformed_capsule)
  if symmetric_key_1 == symmetric_key_1:
      print("Symmetric keys should be equal!")
  
```

```

import skycryptor
from skycryptor.skycryptor import SkyCryptor
from skycryptor.skycryptor import SkyCryptor
from skycryptor.private_key import PrivateKey
from skycryptor.public_key import PublicKey
from skycryptor.re_key import ReEncryptionKey
from skycryptor.capule import Capsule


if __name__ == "__main__":
    # Making new Skycryptor object from default encryption context 
    sc = Skycryptor()
    
    # Generating Private, Public keys randomly 
    skA = sc.generate()
    pkA = skA.get_public_key()
    print("Private Key bytes: {}".format(skA.to_bytes()))
    print("Public Key bytes: {}".format(pkA.to_bytes()))
  
    # Encapsulating and getting encryption capsule and symmetric key bytes 
    capsule, symmetric_key = pkA.encapsulate()
    print("Capsule Buffer: {}".format(capsule.to_bytes()))
    print("Symmetric Key Buffer: {}".format(symmetric_key.to_bytes()))

```
This basic example demonstrates how to generate random keys, get them as a basic byte arrays, get encryption capsule and symmetric key as a byte buffer out of the generated public key.



## Use Cases
- KYC Applications
- End-to-Enc encrypted cloud collaboration
- Decentralized Supply-Chain management
- Keeping data private from the subset of peers in Hyperledge Fabric Channels

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.skycryptor.com/).
