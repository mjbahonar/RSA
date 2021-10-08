from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding

#After recieving the cipherText, you should decrypt cipher text by your private key

#Opening private key
#To open private key, you need to enter myPrivateKey.pem file password.
with open('myPrivateKey.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b"passphrase",
        backend=default_backend()
    )

#Opening ciphertext
with open('cipherText.pem', 'rb') as f:
    cipherText = f.read();

#Decrypting ciphertext
plainText = private_key.decrypt(
    cipherText,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    )
)

#Save decrypted text as outPutMessage.txt.
with open('outPutMessage.txt', 'wb') as f:
    f.write(plainText)
