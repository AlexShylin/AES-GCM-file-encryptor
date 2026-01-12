# AES File encryptor
### Introduction
This script encrypts and decrypts file using AES in CGM mode.

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
It requires Python and Pycryptodome<http://pycryptodome.readthedocs.io/en/latest/src/introduction.html>  
You can get Pycryptodome by running "pip install pycryptodome"  
You should do it in a virtual environment if you already have pycrypto as it is a fork of pycrypto, and they might interfere with each other in unexpected ways

#### How to run
```commandline
source ./.venv/bin/activate

pip install -r requirements.txt 

python aes_gcm.py help
python aes_gcm.py encrypt /home/user/my_file.jpeg /home/user/my_encrypted_file.jpeg
python aes_gcm.py decrypt /home/user/my_encrypted_file.jpeg /home/user/my_decrypted_file.jpeg
```