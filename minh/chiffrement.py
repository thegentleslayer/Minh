import base64
import secrets
from cryptography.fernet import Fernet

def generate_the_key():
    key_length = 32
    key = secrets.token_bytes(key_length)
    return key

def save_the_key(key, file='filekey.txt'):
    key_encoded = base64.b64encode(key).decode('utf-8')
    with open(file, 'w') as filekey:
        filekey.write(key_encoded)

def upload_the_key(file='filekey.txt'):
    with open(file, 'r') as filekey:
        key_encoded = filekey.read()
    key = base64.b64decode(key_encoded)
    return key

def encrypt_file(file_path, output_file_path, key):
    fernet = Fernet(base64.b64encode(key).decode('utf-8'))

    try:
        with open(file_path, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        with open(output_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        print(f"Résultat chiffrement : {encrypted}")

        return encrypted

    except Exception as e:
        print(f"Erreur lors du chiffrement : {e}")
        return None

def decrypt_file(file_path, output_file_path, key):
    fernet = Fernet(base64.b64encode(key).decode('utf-8'))

    try:
        with open(file_path, 'rb') as enc_file:
            encrypted = enc_file.read()

        decrypted = fernet.decrypt(encrypted)

        with open(output_file_path, 'wb') as dec_file:
            dec_file.write(decrypted)

        print(f"Résultat déchiffrement : {decrypted}")

        return decrypted

    except Exception as e:
        print(f"Erreur lors du déchiffrement : {e}")
        return None

# Générer une clé et l'enregistrer dans le fichier
key = generate_the_key()
save_the_key(key)

# Chiffrer le fichier
encrypted_data = encrypt_file('pessimistic_poem.txt', 'encrypted_pessimistic_poem.txt', key)

# Décrypter le fichier
if encrypted_data:
    decrypt_file('encrypted_pessimistic_poem.txt', 'decrypted_pessimistic_poem.txt', key)
