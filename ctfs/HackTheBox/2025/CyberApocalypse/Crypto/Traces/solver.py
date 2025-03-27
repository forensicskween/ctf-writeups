from crib_dragger import CribDragger, xor_key_text_list, check_potential_stream, print_text
from pwn import remote
import re

def bold(msg):
    return ('\033[1m'+msg+'\033[0m')

def ok(msg):
    return ('\033[94m'+msg+'\033[0m')

def err(msg):
    return ('\033[91m'+msg+'\033[0m')

def warn(msg):
    return ('\033[93m'+msg+'\033[0m')

ok_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

class MiniIRCClient:
    def __init__(self,conn):
        self.conn = conn
    
    def join_channel(self,channel_name,channel_key=''):
        warn_string = warn('You must set your channel nickname in your first message at any channel. Format: "!nick <nickname>"').encode()
        self.conn.sendlineafter('> ',f'JOIN {channel_name} {channel_key}')
        messages = self.conn.recvuntil(warn_string).replace(warn_string,b'').decode().strip().split('\n')
        encrypted_messages = []
        print(f'Got encrypted Channels...')
        for msg in messages:
            print(msg)
            encrypted_messages.append(bytes.fromhex(msg.split(': ')[1]) )
        self.conn.sendlineafter(b'guest > ',b'!nick dummy')
        self.conn.sendline(b'!leave')
        return encrypted_messages

    def list_channels(self):
        self.conn.sendlineafter('> ',b'LIST')
        self.conn.recvuntil(bold(f'\n{"*"*10} LIST OF AVAILABLE CHANNELS {"*"*10}\n').encode())
        channels = self.conn.recvuntil(('\n'+'*'*48).encode()).replace(('\n'+'*'*48).encode(),b'').strip().split(b'\n')
        channels = [ok_escape.sub('',x.decode()).split('. ')[1] for x in channels[:-1]]
        return channels
    
    def list_channel_names(self,channel_name):
        self.conn.sendlineafter('> ',f'NAMES {channel_name}'.encode())
        self.conn.recvuntil(bold(f'\n{"*"*10} LIST OF MEMBERS IN {channel_name} {"*"*10}\n').encode())
        names = self.conn.recvuntil(('\n'+'*'*48).encode()).replace(('\n'+'*'*48).encode(),b'').strip().split(b'\n')
        names = [x.split(b'. ')[1].decode() for x in names[:-1]]
        return names
    

def find_potential_key(plaintext: bytes, encrypted_messages: list[bytes]):
    key_set = set()
    keystreams = xor_key_text_list(plaintext, encrypted_messages)
    for idx, key in enumerate(keystreams):
        result = check_potential_stream(key, encrypted_messages, strict=True)
        if result and plaintext in result:
            print(f'\nKeystream ID: {idx}')
            print_text(result)
            print(f'Target Index: {result.index(plaintext)}')
            print(f'Potential Key: {key.hex()}')
            key_set.add(key)
    if len(key_set) == 1:
        return key_set.pop()


crib_dragger = CribDragger()
crib_dragger.initialize_word_list(default=True)


host,port = '94.237.60.20','50984'
conn = remote(host,port)
client = MiniIRCClient(conn)
channels = client.list_channels()
for channel in channels:
    if 'secret' in channel:
        print(f'Channel {channel} cannot list names yet')
        continue
    names = client.list_channel_names(channel)
    for name in names:
        print(f'Channel {channel} member {name}')

known_pt =b'!nick Runeblight'
encrypted_messages = client.join_channel(channels[0])

target_key = find_potential_key(known_pt,encrypted_messages)
result = crib_dragger.interactive_crib_dragging(target_key,encrypted_messages)
PT = xor_key_text_list(result[0],result[1])[0]
print(PT.decode())
#Here is the passphrase for our secure channel: %mi2gvHHCV5f_kcb=Z4vULqoYJ&oR

client.conn.close()
client.conn = remote(host,port)

secret_key = b'%mi2gvHHCV5f_kcb=Z4vULqoYJ&oR'
encrypted_messages_secret_channel = client.join_channel(channels[1],secret_key.decode())
target_key_secret = find_potential_key(known_pt,encrypted_messages_secret_channel)
result_secret = crib_dragger.interactive_crib_dragging(target_key_secret,encrypted_messages_secret_channel)
#Index 5: Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location. 
# It is labeled as: HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}
