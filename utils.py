import json
import random
import string


def send_msg(sock, obj):
    sock.sendall(json.dumps(obj, ensure_ascii=True).encode('ascii') + b'\n')


def recv_msg(sock):
    data = b''
    while not data.endswith(b'\n'):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    if not data:
        return None
    return json.loads(data.decode('ascii').strip())


def random_ascii_key(n=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def is_valid_ascii_key(key, length=16):
    if not isinstance(key, str) or len(key) != length:
        return False
    try:
        key.encode('ascii')
    except UnicodeEncodeError:
        return False
    return True