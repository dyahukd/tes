import socket
import json
import threading
from aes import AES
from utils import send_msg, recv_msg, random_ascii_key, is_valid_ascii_key


def start_chat(sock, aes, name):
    running = True
    state = {"aes": aes}

    def receive():
        nonlocal running
        while running:
            try:
                msg = recv_msg(sock)
                if msg is None:
                    print(f"\n[{name}] Peer disconnected.")
                    break
                if 'chat' in msg:
                    try:
                        plain = state["aes"].decrypt_cbc(bytes.fromhex(msg['chat']))
                        print(f"\n[{name} received] {plain.decode('ascii')}")
                    except Exception as e:
                        print(f"\n[{name}] Decrypt error: {e}")
                elif 'rekey' in msg:
                    try:
                        plain = state["aes"].decrypt_cbc(bytes.fromhex(msg['rekey']))
                        new_key = plain.decode('ascii')
                        if not is_valid_ascii_key(new_key):
                            print(f"\n[{name}] Rekey rejected: format invalid.")
                            continue
                        state["aes"] = AES(new_key.encode('ascii'))
                        print(f"\n[{name}] Rekey: switched to new session key.")
                    except Exception as e:
                        print(f"\n[{name}] Rekey decrypt error: {e}")
            except Exception as e:
                if running:
                    print(f"[{name}] Receive error: {e}")
                break
        running = False
        try:
            sock.close()
        except Exception:
            pass

    threading.Thread(target=receive, daemon=True).start()
    print(f"[{name}] Chat ready. '/rekey <16char>' untuk ganti key, 'exit' keluar.")
    try:
        while running:
            text = input()
            if text.lower() == 'exit':
                running = False
                break
            if not text:
                continue
            if text.startswith('/rekey '):
                new_key = text[len('/rekey '):].strip()
                if not is_valid_ascii_key(new_key):
                    print(f"[{name}] Rekey gagal: harus 16 karakter ASCII.")
                    continue
                payload = new_key.encode('ascii')
                cipher_hex = state["aes"].encrypt_cbc(payload).hex()
                send_msg(sock, {"rekey": cipher_hex})
                state["aes"] = AES(new_key.encode('ascii'))
                print(f"[{name}] Rekey dikirim. Session key sekarang = {new_key}")
            else:
                cipher = state["aes"].encrypt_cbc(text.encode('ascii'))
                send_msg(sock, {"chat": cipher.hex()})
    except KeyboardInterrupt:
        running = False
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print(f"[{name}] Chat ended.")


def run_alice(kdc_ip, kdc_port, alice_ip, alice_port, ka, kb):
    print(f"[Alice] K_A = {ka}")
    print(f"[Alice] K_B = {kb}")

    # Step 1: Alice -> KDC
    n1 = random_ascii_key(8)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((kdc_ip, kdc_port))
    send_msg(s, {"id_a": "Alice", "id_b": "Bob", "n1": n1})
    print(f"[Alice] Step 1 sent: ID_A=Alice, ID_B=Bob, N1={n1}")

    # Step 2: terima dari KDC
    resp = recv_msg(s)
    s.close()
    if resp is None:
        print("[Alice] Error: no response from KDC")
        return

    dec_a = AES(ka.encode('ascii')).decrypt_cbc(bytes.fromhex(resp['for_alice']))
    data_a = json.loads(dec_a.decode('ascii'))

    if data_a['n1'] != n1 or data_a['id_b'] != "Bob":
        print("[Alice] Verifikasi KDC gagal")
        return

    ks = data_a['ks']
    print(f"[Alice] Step 2 received & verified. K_S = {ks}")
    for_bob_hex = resp['for_bob']

    # Buka server untuk Bob
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((alice_ip, alice_port))
    server.listen(1)
    print(f"[Alice] Waiting for Bob on {alice_ip}:{alice_port}")
    conn, addr = server.accept()
    print(f"[Alice] Bob connected from {addr}")

    # Step 3: Alice -> Bob
    send_msg(conn, {"step3": for_bob_hex})
    print("[Alice] Step 3 sent: E(Kb,[Ks||ID_A])")

    # Step 4: terima E(Ks,N2)
    aes_s = AES(ks.encode('ascii'))
    msg4 = recv_msg(conn)
    data4 = json.loads(aes_s.decrypt_cbc(bytes.fromhex(msg4['step4'])).decode('ascii'))
    n2 = data4['n2']
    print(f"[Alice] Step 4 received: N2={n2}")

    # Step 5: kirim E(Ks,f(N2))
    n2_plus1 = str(int(n2) + 1)
    payload5 = json.dumps({"n2_plus1": n2_plus1}).encode('ascii')
    send_msg(conn, {"step5": aes_s.encrypt_cbc(payload5).hex()})
    print(f"[Alice] Step 5 sent: f(N2)={n2_plus1}")

    print("[Alice] Key distribution complete. Mulai chat.")
    start_chat(conn, aes_s, "Alice")