from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.asymmetric import rsa 

# Run this code only once and store private key and public key in safe place  

#Private key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

#Public kry generation
public_key = private_key.public_key()


#Saving private key as myPrivateKey.pem. Keep this key safe and secure.
#You can set password for your file if you want.
with open("myPrivateKey.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))

#Saving private key as myPublicKey.pem. If you want to recieve cipherText, send myPublicKey.pem to the message sender.
with open("myPublicKey.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))