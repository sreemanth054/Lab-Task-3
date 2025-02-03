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

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server listening on port 12345...")
    
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")
    
    encrypted_message = conn.recv(1024).decode()
    print(f"Encrypted: {encrypted_message}")
    decrypted_message = decrypt_message(encrypted_message)
    print(f"Decrypted: {decrypted_message}")
    
    response = "Hello from server"
    encrypted_response = encrypt_message(response)
    conn.send(encrypted_response.encode())
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()
