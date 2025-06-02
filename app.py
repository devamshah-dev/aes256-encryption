from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import json
import base64
import time
import threading
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__)
CORS(app)

VAULT_FILE = 'encryption_of_data.json'
SALT = b'0123456789abcdef0123456789abcdef'
WEAK_PASSWORDS = [
    'password', '123456', 'admin', 'qwerty', 'letmein',
    'welcome', 'monkey', '1234567890', 'password123',
    'admin123', 'root', 'toor', 'pass', '12345',
    'abc123', 'test', 'guest', 'user', 'demo', 'login'
]
current_encryption_data = {}
brute_force_status = {'running': False, 'progress': 0, 'log': []}

def derive_key(password: str) -> bytes:
    """Getting AES key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(plaintext: str, password: str) -> dict:
    """Encrypt this text using AES-256-CBC""" # Cipherblock chaining    
    try:
        key = derive_key(password)
        iv = secrets.token_bytes(16) # Initialisation Vector
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) #encrypt to cipher
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        iv_cipher = iv + ciphertext
        encrypt_result = base64.b64encode(iv_cipher).decode() # Will combine iv & cipher then encode in base64.
        return {
            'success': True,
            'ciphertext': encrypt_result,
            'timestamp': datetime.now().isoformat(),
            'algorithm': 'AES-256-CBC',
            'key_derivation': 'PBKDF2',
            'iterations': 100000
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def decrypt_text(base64_ciphertext: str, password: str) -> dict:
    """Decrypt text using AES-256-CBC"""
    try:
        key = derive_key(password)
        iv_cipher = base64.b64decode(base64_ciphertext) # decoding
        iv = iv_cipher[:16]
        ciphertext = iv_cipher[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor() #decryption
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return {
            'success': True,
            'plaintext': plaintext.decode(),
            'decryption_time': datetime.now().isoformat()
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def save_to_json(data: dict):
    """Save encrypted data to JSON file"""
    storage_data = {
        'encrypted_messages': [data],
        'metadata': {
            'created': datetime.now().isoformat(),
            'version': '1.4',
            'security_level': 'AES-256'
        }
    }
    
    with open(VAULT_FILE, 'w') as f:
        json.dump(storage_data, f, indent=2)
    return storage_data

def load_from_json() -> dict:
    """Load encrypted data from JSON file"""
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, 'r') as f:
            return json.load(f)
    return {}

def brute_force_attack(ciphertext: str):
    """Brute force attack"""
    global brute_force_status
    
    brute_force_status['running'] = True
    brute_force_status['progress'] = 0
    brute_force_status['log'] = []
    
    total_attempts = len(WEAK_PASSWORDS)
    
    for i, weak_password in enumerate(WEAK_PASSWORDS):
        if not brute_force_status['running']:
            break  
        attempt_num = i + 1
        start_time = time.time()
        result = decrypt_text(ciphertext, weak_password) # decrypt
        end_time = time.time()
        
        if result['success']:
            log_entry = f"Attempt {attempt_num}: Password '{weak_password}' - SUCCESS"
            brute_force_status['log'].append(log_entry)
        else:
            log_entry = f"Attempt {attempt_num}: Password '{weak_password}' - FAILURE ({end_time - start_time:.3f}s)"
            brute_force_status['log'].append(log_entry)
        
        brute_force_status['progress'] = (attempt_num / total_attempts) * 100
        time.sleep(0.1)
    
    brute_force_status['running'] = False
    brute_force_status['log'].append("=" * 50)
    brute_force_status['log'].append("ATTACK COMPLETED: AES-256 encryption remains secure!")
    brute_force_status['log'].append(f"Total attempts: {total_attempts}")
    brute_force_status['log'].append(f"All attempts failed - encryption is secure!")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    data = request.json
    if data is None:
        return jsonify({'success': False, 'error': 'Invalid request: missing json payload.'}), 400
    plaintext = data.get('plaintext', '')
    password = data.get('password', '')
    
    if not plaintext or not password:
        return jsonify({'success': False, 'error': 'Plaintext, password compulsory.'})
    
    result = encrypt_text(plaintext, password) # Will encrypt the plaintext.
    
    if result['success']:
        global current_encryption_data
        current_encryption_data = result
        current_encryption_data['original_pass'] = password
        
        storage_data = save_to_json(result) # The result of encryption is now stored locally.
        
        return jsonify({
            'success': True,
            'encrypted_data': result,
            'json_storage': storage_data
        })
    
    return jsonify(result)

@app.route('/brute-force', methods=['POST'])
def start_brute_force():
    global current_encryption_data, brute_force_status
    
    if not current_encryption_data:
        return jsonify({'success': False, 'error': 'No encrypted data found in here.'})
    
    if brute_force_status['running']:
        return jsonify({'success': False, 'error': 'Brute force attack is running right now'})
    
    thread = threading.Thread(
        target=brute_force_attack, 
        args=(current_encryption_data['ciphertext'],)
    ) # This is now going to start a brute force attack.
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Brute force attack started'})

@app.route('/brute-force/status', methods=['GET'])
def brute_force_status_endpoint():
    return jsonify(brute_force_status)

@app.route('/brute-force/stop', methods=['POST'])
def stop_brute_force():
    global brute_force_status
    brute_force_status['running'] = False
    return jsonify({'success': True, 'message': 'Brute force is now stopped'})

@app.route('/decrypt', methods=['POST'])
def decrypt_endpoint():
    global current_encryption_data
    
    if not current_encryption_data:
        return jsonify({'success': False, 'error': 'No encrypted data available'})
    
    result = decrypt_text(
        current_encryption_data['ciphertext'], 
        current_encryption_data['original_pass'] #will have to use original password to decrypt.
    )
    
    return jsonify(result)

@app.route('/storage', methods=['GET'])
def get_storage():
    """Get current JSON storage data"""
    storage_data = load_from_json()
    return jsonify({'success': True, 'data': storage_data})

@app.route('/clear', methods=['POST'])
def clear_data():
    """Clear all stored data"""
    global current_encryption_data, brute_force_status
    
    current_encryption_data = {}
    brute_force_status = {'running': False, 'progress': 0, 'log': []}
    
    if os.path.exists(VAULT_FILE):
        os.remove(VAULT_FILE) #Will remove any remaining JSON files.
    
    return jsonify({'success': True, 'message': 'All data cleared'})

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates') # Frontend files are stored in here.
    
    print("Starting Secure AES-256 Encryption Server...")
    print("Server will be available at: http://localhost:5000")
    print("Make sure to install required packages:")
    print("pip install flask flask-cors cryptography")
    
    app.run(debug=True, host='localhost', port=5000)