from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Read RSA keys from files
def load_keys():
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

private_key, public_key = load_keys()

aes_key = os.urandom(32)

messages = {}

@app.route('/')
def index():
    return render_template('index.html', messages=messages, aes_key=aes_key.hex())

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    global private_key, public_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
    return {
        'private_key': private_pem.decode('utf-8'),
        'public_key': public_pem.decode('utf-8')
    }

@app.route('/get_keys', methods=['GET'])
def get_keys():
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        'private_key': private_pem.decode('utf-8'),
        'public_key': public_pem.decode('utf-8')
    }

@app.route('/generate_aes_key', methods=['GET'])
def generate_aes_key():
    global aes_key
    aes_key = os.urandom(32)
    return redirect(url_for('index'))

@app.route('/get_aes_key', methods=['GET'])
def get_aes_key():
    return jsonify({'aes_key': aes_key.hex()})

@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    message = request.form['message']
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    messages['ciphertext'] = ciphertext.hex()
    messages['message'] = message
    return redirect(url_for('index'))

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    private_key_pem = request.form['private_key'].strip()
    logging.debug(f"Private Key PEM: {private_key_pem}")

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
        )
        ciphertext = bytes.fromhex(messages['ciphertext'])
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        messages['decrypted_message'] = plaintext.decode()
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        flash('Invalid private key or incorrect key format.')
        messages['decrypted_message'] = ''
    return redirect(url_for('index'))

@app.route('/encrypt_aes', methods=['POST'])
def encrypt_aes():
    global aes_key
    message = request.form['message']
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    messages['aes_ciphertext'] = (iv + ciphertext).hex()
    messages['message'] = message
    return redirect(url_for('index'))

@app.route('/decrypt_aes', methods=['POST'])
def decrypt_aes():
    aes_key_hex = request.form['aes_key']
    aes_key = bytes.fromhex(aes_key_hex)
    aes_ciphertext = bytes.fromhex(messages['aes_ciphertext'])
    iv = aes_ciphertext[:16]
    ciphertext = aes_ciphertext[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    messages['decrypted_message'] = plaintext.decode()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)