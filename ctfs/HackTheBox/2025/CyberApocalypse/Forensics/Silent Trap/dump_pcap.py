import pyshark
from Crypto.Cipher import ARC4
import datetime
import base64

import re

def is_base64(s):
    # Remove whitespace
    s = s.strip().replace(b'\n', b'').replace(b'\r', b'')
    
    # Base64 must be length divisible by 4
    if len(s) % 4 != 0:
        return False

    # Match only valid base64 characters
    base64_bytes_re = re.compile(b'^[A-Za-z0-9+/]+={0,2}$')
    if not base64_bytes_re.match(s):
        return False

    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


rc4_key = bytes([168, 115, 174, 213, 168, 222, 72, 36, 91, 209, 242, 128, 69, 99, 195, 164, 238, 182, 67, 92, 7, 121, 164, 86, 121, 10, 93, 4, 140, 111, 248, 44, 30, 94, 48, 54, 45, 100, 184, 54, 28, 82, 201, 188, 203, 150, 123, 163, 229, 138, 177, 51, 164, 232, 86, 154, 179, 143, 144, 22, 134, 12, 40, 243, 55, 2, 73, 103, 99, 243, 236, 119, 9, 120, 247, 25, 132, 137, 67, 66, 111, 240, 108, 86, 85, 63, 44, 49, 241, 6, 3, 170, 131, 150, 53, 49, 126, 72, 60, 36, 144, 248, 55, 10, 241, 208, 163, 217, 49, 154, 206, 227, 25, 99, 18, 144, 134, 169, 237, 100, 117, 22, 11, 150, 157, 230, 173, 38, 72, 99, 129, 30, 220, 112, 226, 56, 16, 114, 133, 22, 96, 1, 90, 72, 162, 38, 143, 186, 35, 142, 128, 234, 196, 239, 134, 178, 205, 229, 121, 225, 246, 232, 205, 236, 254, 152, 145, 98, 126, 29, 217, 74, 177, 142, 19, 190, 182, 151, 233, 157, 76, 74, 104, 155, 79, 115, 5, 18, 204, 65, 254, 204, 118, 71, 92, 33, 58, 112, 206, 151, 103, 179, 24, 164, 219, 98, 81, 6, 241, 100, 228, 190, 96, 140, 128, 1, 161, 246, 236, 25, 62, 100, 87, 145, 185, 45, 61, 143, 52, 8, 227, 32, 233, 37, 183, 101, 89, 24, 125, 203, 227, 9, 146, 156, 208, 206, 194, 134, 194, 23, 233, 100, 38, 158, 58, 159])

def decrypt_message(msg,rc4_key):
    try:
        if is_base64(msg):
            msg = base64.b64decode(msg)
            pt = ARC4.new(rc4_key).decrypt(msg)
            return pt
    except:
        return None
    

# Replace with your actual PCAP file path
pcap_file = 'capture.pcapng'

# Apply a display filter to only get TCP packets that have a data.data field
capture = list(pyshark.FileCapture(
    pcap_file,
    display_filter='imap',include_raw=True,use_json=True
))


def parse_raw_data(item,rc4_key):
    if isinstance(item[0],list):
        byte_data = [bytes.fromhex(x[0]).strip() for x in item]
        info_ups = []
        for line in item:
            result = decrypt_message(bytes.fromhex(line[0]).strip(),rc4_key)
            if result:
                info_ups.append(result)
        return byte_data,info_ups
    byte_data = [bytes.fromhex(item[0]).strip()]
    info_ups = []
    result = decrypt_message(byte_data[0],rc4_key)
    if result:
        info_ups.append(result)
    return byte_data,info_ups

def parse_imap_sessions(capture,rc4_key):
    imap_sessions = []
    for cap in capture:
        info = {}
        info['time'] = cap.sniff_time
        info['ports'] = (cap)
        byte_data,decrypted = parse_raw_data(cap.imap.line_raw,rc4_key)
        if b'_report_' in b''.join(byte_data):
            info['from'] ="\033[92mVICTIM\033[0m"
        else:
            info['from'] = "\033[91mATTACKER\033[0m"
        if decrypted:
            info['data'] = decrypted
        else:
            info['byte_data'] = byte_data
        if 'imf' in cap:
            if cap.imf._all_fields.get('imf.message_text_raw'):
                imf_byte_data,imf_decrypted = parse_raw_data(cap.imf.message_text_raw,rc4_key)
                if imf_decrypted:
                    info['imf'] = imf_decrypted
        imap_sessions.append(info)
    return imap_sessions

def create_imap_log(imap_sessions):
    imap_sessions_decrypted = []
    for item in imap_sessions:
        if item.get('data'):
            imap_sessions_decrypted.append((item['time'],item['from'],b''.join(item['data'])))
        if item.get('imf'):
            imap_sessions_decrypted.append((item['time'],item['from'],b''.join(item['imf'])))
    imap_sessions_decrypted = sorted(imap_sessions_decrypted,key= lambda x: x[0])
    return imap_sessions_decrypted

imap_sessions =  parse_imap_sessions(capture,rc4_key)
imap_sessions_decrypted = create_imap_log(imap_sessions)

file_data =[]
for (ts,idx,data) in imap_sessions_decrypted:
    data_temp = data.decode()
    readable_ts = ts.strftime('%Y-%m-%d %H:%M:%S')
    print(f'Packet at {readable_ts} from {idx} --> {data_temp}')
    file_data.append(f'Packet at {readable_ts} from {idx} --> {data_temp}')

with open("imap_log.txt",'w') as of:
    of.write('\n\n'.join(file_data))