from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from flask import Flask, render_template, request

app = Flask(__name__,template_folder='templates')

@app.route('/')
def index():
    return render_template('register.html')

if __name__ == '_main_':
    app.run(debug=True)


def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password1 = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        salt = b"saltysalt"
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
        )
        aes_key = kdf.derive(password1)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(password1) + padder.finalize()

# Encrypt the padded input with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

# Generate ECC key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

# Serialize the public key
        public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

# Perform ECDH key exchange to derive a shared key
        shared_key = private_key.exchange(ec.ECDH(), public_key)

# Derive a key from the shared key (this is a simplified example)
        derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
        derived_key.update(shared_key)
        derived_key = derived_key.finalize()

# Use the derived key to encrypt and decrypt the AES key
        cipher_aes_key = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
        encryptor_aes_key = cipher_aes_key.encryptor()
        ciphertext_aes_key = encryptor_aes_key.update(aes_key) + encryptor_aes_key.finalize()

        decryptor_aes_key = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend()).decryptor()
        decrypted_aes_key = decryptor_aes_key.update(ciphertext_aes_key) + decryptor_aes_key.finalize()

# Use the decrypted AES key to decrypt the input
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

        # Print the results
        print(f"Original Text: {password1}")
        print(f"Encrypted Text: {ciphertext.hex()}")
        print(f"Decrypted Text: {decrypted_text.decode()}")
        return render_template('register.html')

if __name__ == '_main_':
    app.run(debug=True)