# AES File encryptor
### Introduction
This script encrypts and decrypts file using AES-256 in CGM mode.

### Theory
Authenticated encryption with associated data(AEAD) modes of encryption provide 2 security guarantees:  
* Confidentiality: The encrypted data will not leak any information about the secret plaintext data without the correct decryption key
* Integrity: The secret plaintext data and associated data were not modified by an adversary after being encrypted with AES GCM  

In a simple words:  
* Only people who know the secret key can read the information that was encrypted
* The information was not changed by anyone once it was encrypted  

The more commonly known modes of encryption CBC, CTR modes don't provide the integrity guarantee that AEAD modes provide. 

### Running the script
#### Dependencies
Requires Python 3 and [Pycryptodome](http://pycryptodome.readthedocs.io/en/latest/src/introduction.html)

#### How to setup virtual environment
```commandline
python3 -m venv ./.venv
source ./.venv/bin/activate
pip install -r requirements.txt 
```

#### How to run
```commandline
python aes_gcm.py help
python aes_gcm.py encrypt /home/user/my_file.jpeg /home/user/my_encrypted_file.jpeg
python aes_gcm.py decrypt /home/user/my_encrypted_file.jpeg /home/user/my_decrypted_file.jpeg
```