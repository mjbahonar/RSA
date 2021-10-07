from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding
  
with open('myPrivateKey.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b"passphrase",
        backend=default_backend()
    )

with open('cipherText.pem', 'rb') as f:
    cipherText = f.read();


plainText = private_key.decrypt(
    cipherText,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    )
)


with open('outPutMessage.txt', 'wb') as f:
    f.write(plainText)
