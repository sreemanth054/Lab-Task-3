import socket
from Crypto.Cipher import AES
import base64

KEY = b'16charsecretkey!'   
IV = b'1234567890123456' 

def encrypt_message(message):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_message = message + ' ' * (16 - len(message) % 16)
    encrypted = cipher.encrypt(padded_message.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decoded_encrypted_message = base64.b64decode(encrypted_message)
    decrypted = cipher.decrypt(decoded_encrypted_message).decode().strip()
    return decrypted

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    
    message = "Hello from client"
    encrypted_message = encrypt_message(message)
    client_socket.send(encrypted_message.encode())
    
    encrypted_response = client_socket.recv(1024).decode()
    decrypted_response = decrypt_message(encrypted_response)
    print(f"Server response: {decrypted_response}")
    
    client_socket.close()

if __name__ == "__main__":
    client()
