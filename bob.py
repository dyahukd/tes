import socket
import json
import random
import threading
from aes import AES
from utils import send_msg, recv_msg, is_valid_ascii_key


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
                cipher_hex = state["aes"].encrypt_cbc(new_key.encode('ascii')).hex()
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


def run_bob(alice_ip, alice_port, kb):
    print(f"[Bob] K_B = {kb}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((alice_ip, alice_port))
    print(f"[Bob] Connected to Alice at {alice_ip}:{alice_port}")

    # Step 3: terima E(Kb,[Ks||ID_A])
    msg3 = recv_msg(sock)
    data3 = json.loads(AES(kb.encode('ascii')).decrypt_cbc(bytes.fromhex(msg3['step3'])).decode('ascii'))
    if data3['id_a'] != "Alice":
        print("[Bob] Verifikasi ID_A gagal")
        sock.close()
        return
    ks = data3['ks']
    print(f"[Bob] Step 3 received & verified. K_S = {ks}")

    aes_s = AES(ks.encode('ascii'))

    # Step 4: Bob -> Alice: E(Ks,N2)
    n2 = str(random.randint(1000, 9999))
    send_msg(sock, {"step4": aes_s.encrypt_cbc(json.dumps({"n2": n2}).encode('ascii')).hex()})
    print(f"[Bob] Step 4 sent: N2={n2}")

    # Step 5: terima E(Ks,f(N2))
    msg5 = recv_msg(sock)
    data5 = json.loads(aes_s.decrypt_cbc(bytes.fromhex(msg5['step5'])).decode('ascii'))
    if data5['n2_plus1'] != str(int(n2) + 1):
        print("[Bob] Verifikasi f(N2) gagal")
        sock.close()
        return
    print(f"[Bob] Step 5 received & verified: f(N2)={data5['n2_plus1']}")

    print("[Bob] Key distribution complete. Mulai chat.")
    start_chat(sock, aes_s, "Bob")