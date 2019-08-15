import socket
import os
import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def encrypt_request(request, public_key_path):
    encoded_req = request.encode('utf-8')
    public_key = RSA.import_key(open(public_key_path).read())
    session_key = get_random_bytes(16)

    # encrypt session key with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # encrypt data with aes session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(encoded_req)

    return str((enc_session_key, cipher_aes.nonce, tag, cipher_text)).encode()


# TCP_IP = 'localhost'
TCP_IP = "192.168.56.103"
TCP_PORT = 9001
BUFFER_SIZE = 1024


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((TCP_IP, TCP_PORT))

    email = input("email address: ")
    pswd = input("password: ")
    # email = "td37@hw.ac.uk"
    # pswd = "toto"

    sure = input("Are you sure you want to delete your profile and all related information ? (y/n) ")

    if sure == 'y':
        public_key_p = "public1.pem"
        email = hashlib.sha256(email.encode()).hexdigest()
        pswd = hashlib.sha256(pswd.encode()).hexdigest()

        req = "delete,%s,%s" % (email, pswd)
        req_to_send = encrypt_request(req, public_key_p)

        # s.sendall(req.encode('utf-8'))
        s.sendall(req_to_send)
        s.sendall(b"EOR")
        data = s.recv(BUFFER_SIZE)
        data = json.loads(data.decode('utf-8'))
        # print('Received', repr(data))
        if "success" in data:
            if data["success"]:
                print("[INFO] Your profile and all related information have been deleted")
            else:
                print("[ERROR] ", data["reason"])

# s.close()
print('[INFO] connection closed')
