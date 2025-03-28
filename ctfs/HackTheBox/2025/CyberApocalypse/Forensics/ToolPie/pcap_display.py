import pyshark
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import datetime

# Replace with your actual PCAP file path
pcap_file = 'capture.pcap'

# Apply a display filter to only get TCP packets that have a data.data field
capture = list(pyshark.FileCapture(
    pcap_file,
    display_filter='tcp && data.data && tcp.port == 55155'
))

SEPARATOR = b'<SEPARATOR>'

def find_keys(capture):
    KEYS = []
    for packet in capture:
        packet_bytes = bytes.fromhex(packet.data.data)
        if SEPARATOR in packet_bytes:
            KEYS.append(packet_bytes)
    original_key = KEYS[0].split(SEPARATOR)[1]
    return KEYS,original_key


def aes_decrypt(ct,key):
    cipher = AES.new(key, AES.MODE_CBC, key)
    pt = cipher.decrypt(ct)
    return unpad(pt,16)

def parse_pcap(capture,KEYS,original_key):
    victim,attacker = {},{}
    for packet in capture:
        if packet.tcp.srcport == '55155':
            packet_bytes = bytes.fromhex(packet.data.data)
            ack_r= packet.tcp.get('ack_raw')
            if packet_bytes in KEYS:
                continue
            if ack_r not in attacker:
                attacker[ack_r] = []
            tupled_data = (float(packet.frame_info.time_epoch),packet_bytes)
            attacker[ack_r].append(tupled_data)
        else:
            packet_bytes = bytes.fromhex(packet.data.data)
            if SEPARATOR in packet_bytes:
                KEYS.append(packet_bytes)
            ack_r= packet.tcp.get('ack_raw')
            if packet_bytes in KEYS:
                continue
            if ack_r not in victim:
                victim[ack_r] = []
            tupled_data = (float(packet.frame_info.time_epoch),packet_bytes)
            victim[ack_r].append(tupled_data)

    clean_packets = []
    for k,v in victim.items():
        start_time = v[0][0]
        byte_data = aes_decrypt(b''.join([x[1] for  x in v]),original_key)
        try:
            byte_data = byte_data.decode()
        except:
            pass
        clean_packets.append((start_time,"\033[92mVICTIM\033[0m",byte_data))

    for k,v in attacker.items():
        start_time = v[0][0]
        byte_data = aes_decrypt(b''.join([x[1] for  x in v]),original_key)
        try:
            byte_data = byte_data.decode()
        except:
            pass
        clean_packets.append((start_time,"\033[91mATTACKER\033[0m",byte_data))

    packet_log = sorted(clean_packets,key=lambda x: x[0])
    return packet_log

def dump_pdf_data(PDF_DATA):
    with open('garricks_masterwork.pdf','wb') as of:
        of.write(PDF_DATA)

keys,original_key = find_keys(capture)
print(f'Using Key : {original_key.decode()}')
packet_log = parse_pcap(capture,keys,original_key)

for (ts,idx,data) in packet_log:
    if len(data) >= 1000:
        data_temp = data[:200]
        dump_pdf_data(data)
    else:
        data_temp = data
    readable_ts = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print(f'Packet at {readable_ts} from {idx} --> {data_temp}')

