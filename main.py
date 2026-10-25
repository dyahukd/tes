import argparse
import sys

from aes import self_test
from utils import is_valid_ascii_key
from kdc import run_kdc
from alice import run_alice
from bob import run_bob


def prompt_key(name, cli_value):
    """Jika key tidak diberikan via CLI, minta interaktif."""
    if cli_value is not None:
        if not is_valid_ascii_key(cli_value):
            print(f"Error: {name} harus 16 karakter ASCII (saat ini {cli_value!r})")
            sys.exit(1)
        return cli_value
    while True:
        k = input(f"Masukkan {name} (16 karakter ASCII): ").strip()
        if is_valid_ascii_key(k):
            return k
        print(f"Error: {name} harus 16 karakter ASCII. Coba lagi.")


def confirm_keys(keys):
    print("\n=== Konfirmasi Key ===")
    for name, val in keys.items():
        print(f"  {name} = {val}")
    ans = input("Lanjutkan? (Enter=ya, 'u'=ubah): ").strip().lower()
    if ans == 'u':
        for name in keys:
            keys[name] = prompt_key(name, None)
    return keys


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tugas 2 KI: KDC + AES Manual")
    sub = parser.add_subparsers(dest='role', required=True)

    p_test = sub.add_parser('test', help='Jalankan self-test AES-128')

    p_kdc = sub.add_parser('kdc')
    p_kdc.add_argument('--ip', required=True)
    p_kdc.add_argument('--port', type=int, required=True)
    p_kdc.add_argument('--ka', help='16 ASCII; jika kosong -> prompt')
    p_kdc.add_argument('--kb', help='16 ASCII; jika kosong -> prompt')

    p_alice = sub.add_parser('alice')
    p_alice.add_argument('--kdc-ip', required=True)
    p_alice.add_argument('--kdc-port', type=int, required=True)
    p_alice.add_argument('--ip', required=True)
    p_alice.add_argument('--port', type=int, required=True)
    p_alice.add_argument('--ka', help='16 ASCII; jika kosong -> prompt')
    p_alice.add_argument('--kb', help='16 ASCII; jika kosong -> prompt')

    p_bob = sub.add_parser('bob')
    p_bob.add_argument('--alice-ip', required=True)
    p_bob.add_argument('--alice-port', type=int, required=True)
    p_bob.add_argument('--kb', help='16 ASCII; jika kosong -> prompt')

    args = parser.parse_args()

    if args.role == 'test':
        self_test()

    elif args.role == 'kdc':
        keys = {"K_A": prompt_key("K_A", args.ka), "K_B": prompt_key("K_B", args.kb)}
        keys = confirm_keys(keys)
        run_kdc(args.ip, args.port, keys["K_A"], keys["K_B"])

    elif args.role == 'alice':
        keys = {"K_A": prompt_key("K_A", args.ka), "K_B": prompt_key("K_B", args.kb)}
        keys = confirm_keys(keys)
        run_alice(args.kdc_ip, args.kdc_port, args.ip, args.port, keys["K_A"], keys["K_B"])

    elif args.role == 'bob':
        keys = {"K_B": prompt_key("K_B", args.kb)}
        keys = confirm_keys(keys)
        run_bob(args.alice_ip, args.alice_port, keys["K_B"])