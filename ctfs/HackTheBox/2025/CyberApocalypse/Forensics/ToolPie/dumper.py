import importlib
import json
import ast
import bz2
import marshal
import dis

with open('http/execute','r') as inf:
    payload = json.loads(inf.read())


script = payload['script']
start = script.find("b'")
end = script[start:].find("')") + start +1

byte_code = ast.literal_eval(script[start:end])
decompressed = bz2.decompress(byte_code)
code_object = marshal.loads(decompressed)

with open(f'decompressed.bin', 'wb') as f:
    f.write(decompressed)

pyc_data = importlib._bootstrap_external._code_to_timestamp_pyc(code_object)
with open(f'decompressed.pyc', 'wb') as f:
    f.write(pyc_data)

dis.dis(code_object)

