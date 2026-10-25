import socket
import json
from aes import AES
from utils import send_msg, recv_msg, random_ascii_key


def run_kdc(ip, port, ka, kb):
    print(f"[KDC] Listening on {ip}:{port}")
    print(f"[KDC] K_A = {ka}")
    print(f"[KDC] K_B = {kb}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(1)
    conn, addr = server.accept()
    print(f"[KDC] Connection from {addr}")

    req = recv_msg(conn)
    id_a, id_b, n1 = req['id_a'], req['id_b'], req['n1']
    print(f"[KDC] Step 1 received: ID_A={id_a}, ID_B={id_b}, N1={n1}")

    ks = random_ascii_key(16)
    print(f"[KDC] Generated session key K_S = {ks}")

    # E(Ka, [Ks || ID_A || ID_B || N1])
    payload_a = json.dumps({
        "ks": ks, "id_a": id_a, "id_b": id_b, "n1": n1
    }, ensure_ascii=True).encode('ascii')
    enc_a = AES(ka.encode('ascii')).encrypt_cbc(payload_a).hex()

    # E(Kb, [Ks || ID_A])
    payload_b = json.dumps({
        "ks": ks, "id_a": id_a
    }, ensure_ascii=True).encode('ascii')
    enc_b = AES(kb.encode('ascii')).encrypt_cbc(payload_b).hex()

    send_msg(conn, {"for_alice": enc_a, "for_bob": enc_b})
    print("[KDC] Step 2 sent: E(Ka,[Ks||ID_A||ID_B||N1]) and E(Kb,[Ks||ID_A])")
    conn.close()
    server.close()
    print("[KDC] Done.")