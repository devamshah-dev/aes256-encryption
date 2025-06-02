import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from typing import Optional

class AESCrypto:
    """AES-256 encryption/decryption class with PBKDF2 key derivation"""
    def __init__(self, salt=None, iterations=10000): # AES 256 cryptoanalysys with salt & finite iteration.
        self.iterations = iterations
        self.salt = salt if salt else b'0123456789abcdef0123456789abcdef'
        
    def derive_key(self, password: str) -> bytes:
        """Derive AES-256 key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256b
            salt=self.salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, plaintext: str, password: str) -> dict:
        """Encrypt plaintext using AES-256-CBC"""
        try:
            key = self.derive_key(password)
            iv = secrets.token_bytes(16) # iv is 16 byte random initialization vector
            padder = padding.PKCS7(128).padder() #will pads plaintext to AES block
            padded_data = padder.update(plaintext.encode('utf-8'))
            padded_data += padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor() # encrypt this cipher
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            iv_cipher = iv + ciphertext #combined ciphertext with iv.
            base64_result = base64.b64encode(iv_cipher).decode('utf-8')
            
            return {
                'success': True,
                'ciphertext': base64_result,
                'algorithm': 'AES-256-CBC',
                'key_derivation': 'PBKDF2',
                'iterations': self.iterations,
                'iv_length': len(iv),
                'ciphertext_length': len(ciphertext),
                'salt_used': base64.b64encode(self.salt).decode('utf-8') 
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def decrypt(self, base64_ciphertext: str, password: str) -> dict:
        """Decrypt ciphertext using AES-256-CBC"""
        try:
            key = self.derive_key(password) # key is gotten from password!
            iv_cipher = base64.b64decode(base64_ciphertext) #decoded in B64 format.
            if len(iv_cipher) < 16:
                raise ValueError("Invalid ciphertext: too short")
            iv = iv_cipher[:16] #first 16 bytes.
            ciphertext = iv_cipher[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor() #decrypt cipher.
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
            plaintext = plaintext_bytes.decode('utf-8')
            return {
                'success': True,
                'plaintext': plaintext,
                'iv_length': len(iv),
                'ciphertext_length': len(ciphertext)
            }
        except (ValueError, TypeError) as e:
            return {'success': False, 'error': f"Decryption failed (wrong password/corrupted data/incorrect salt): {str(e)}"}
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    
    def generate_random_salt(self) -> bytes:
        """Generate a random 32-byte salt"""
        return secrets.token_bytes(32)


class BruteForceAttacker:
    """Simulates brute force attacks against encrypted data"""
    def __init__(self, crypto_instance: AESCrypto):
        """Initialize brute force attacker"""
        self.crypto = crypto_instance
        self.common_passwords = [
            'password', '123456', 'admin', 'qwerty', 'letmein',
            'welcome', 'monkey', '1234567890', 'password123',
            'admin123', 'root', 'toor', 'pass', '12345',
            'abc123', 'test', 'guest', 'user', 'demo', 'login',
            'passw0rd', 'secret', 'default', 'changeme', 'temp'
        ]
    def attack(self, ciphertext: str, max_attempts: Optional[int] = None) -> dict:
        """Perform brute force attack on ciphertext"""
        attempts = []
        successful_passwords = []
        passwords_to_try = self.common_passwords
        if max_attempts is not None:
            if max_attempts < 0:
                passwords_to_try = []
            else:
                passwords_to_try = self.common_passwords[:max_attempts]
        for i, password in enumerate(passwords_to_try):
            attempt_result = {
                'attempt': i + 1,
                'password': password,
                'success': False,
                'error': None
            }
            decrypt_result = self.crypto.decrypt(ciphertext, password) #decryption attempt.
            
            if decrypt_result['success']:
                attempt_result['success'] = True
                attempt_result['plaintext'] = decrypt_result['plaintext']
                successful_passwords.append(password)
            else:
                attempt_result['error'] = decrypt_result['error']
            
            attempts.append(attempt_result)
        return {
            'total_attempts': len(attempts),
            'successful_attempts': len(successful_passwords),
            'cracked_passwords': successful_passwords,
            'attempts': attempts,
            'attack_successful': len(successful_passwords) > 0
        }

def aes_256_encr(): # testing Data.
    print("AES-256 Encryption")
    print("=" * 50)
    crypto = AESCrypto() #cryptanalysis

    plaintext = "This is a secret message that will be encrypted!"
    strong_password = "SuperSecurePassword123!"
    
    print(f"Original text: {plaintext}")
    print(f"Password: {strong_password}")
    print()
    print("Encrypting...")
    encrypt_result = crypto.encrypt(plaintext, strong_password) #encrypt data.
    
    if encrypt_result['success']:
        print("✅ Encryption successful!")
        print(f"Ciphertext: {encrypt_result['ciphertext'][:50]}...")
        print(f"Algorithm: {encrypt_result['algorithm']}")
        print()
        
        print("Decrypting with correct password...")
        decrypt_result = crypto.decrypt(encrypt_result['ciphertext'], strong_password)
        
        if decrypt_result['success']:
            print("✅ Decryption successful!")
            print(f"Decrypted text: {decrypt_result['plaintext']}")
            print()
        else:
            print(f"Decryption failed: {decrypt_result['error']}")
        
        print("launching brute force attack...")
        attacker = BruteForceAttacker(crypto)
        attack_result = attacker.attack(encrypt_result['ciphertext'], max_attempts=10)
        
        print(f"Attack attempts: {attack_result['total_attempts']}")
        print(f"Successful cracks: {attack_result['successful_attempts']}")
        
        if attack_result['attack_successful']:
            print("WARNING: Password was cracked!")
            print(f"Cracked passwords: {attack_result['cracked_passwords']}")
        else:
            print("AES-256 won on brute force attack!")
            
    else:
        print(f"Encryption failed: {encrypt_result['error']}")


if __name__ == "__main__":
    aes_256_encr()