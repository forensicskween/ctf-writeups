
from pwn import remote,xor,process
import string

valid_chars = string.ascii_letters+string.digits+'_'
blk = lambda x: [x[i:i+16] for i in range(0,len(x),16)]

def send_username(t,username):
    t.sendlineafter(b'Choose your path, traveler :: ',b'1')
    t.sendlineafter(b'[+] Speak thy name, so it may be sealed in the archives :: ',username.encode())
    res = t.recvline().decode().strip()
    if res == '[-] The ancient scribes only accept proper names-no forbidden symbols allowed.':
        return False
    else:
        encrypted_creds = bytes.fromhex(res.split(': ')[1])
        return encrypted_creds

def send_password(t,password):
    t.sendlineafter(b'Choose your path, traveler :: ',b'2')
    t.sendlineafter(b'[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ',password.encode())
    res = t.recvline().decode().strip()
    return res

#t = process(['python3.11','server.py'])

host,port = '94.237.61.252','43101'
t = remote(host,port)

STATIC = 'A'*16 
known_pt = ''
for i in range(20):
    for v in valid_chars:
        temp_pt = known_pt + v
        my_idx = (len(temp_pt)//16)+1
        his_idx = my_idx*2
        pos = (16-len(temp_pt))%16
        if pos == 0:
            pos = 16
        username = STATIC + 'A'*pos + temp_pt + 'A'*pos
        blocks = blk(send_username(t,username))
        check = xor(blocks[my_idx],blocks[his_idx])[:pos]
        if check == bytes(pos):
            print(temp_pt)
            known_pt = temp_pt
            break

assert len(known_pt) == 20
res = send_password(t,known_pt)
print(res)
#[+] The gates open before you, Keeper of Secrets! HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_6f095f37e50b00d11a14a785e8d31d28}
