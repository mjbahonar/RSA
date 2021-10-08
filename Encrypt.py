
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding

#After genrating private key, use this code to encrypt your message
#Your message should be in message.txt file. You should have your private key.

#Opening message to be encrpted
with open('message.txt', 'r') as f:
    message = f.read()
message = message.encode('utf-8')
    
#Opening public key
with open('myPublicKey.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

#Generating cipherText from publickey
cipherText = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    )
)

#Save the cipherText as cipherText.pem. Send this file to message reciever
with open('cipherText.pem', 'wb') as f:
    f.write(cipherText)
