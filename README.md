# Langkah Uji

**Langkah 1 — Verifikasi AES dulu (WAJIB sebelum demo):**
```
python main.py test
```
Output harus:
```
[SELF-TEST] AES-128 encrypt/decrypt/CBC: PASSED
  Encrypt(00112233445566778899aabbccddeeff) = 69c4e0d86a7b0430d8cdb78070b4c55a
```
Ini bukti AES manual sudah standar FIPS-197.

**Langkah 2 — Jalankan 3 terminal (IP berbeda):**

Contoh IP: KDC=`192.168.1.10`, Alice=`192.168.1.11`, Bob=`192.168.1.12`.

```
# Terminal 1 — KDC
python main.py kdc --ip 192.168.1.10 --port 5000 --ka "AliceKey12345678" --kb "BobKey1234567890"

# Terminal 2 — Alice
python main.py alice --kdc-ip 192.168.1.10 --kdc-port 5000 --ip 192.168.1.11 --port 5001 --ka "AliceKey12345678" --kb "BobKey1234567890"

# Terminal 3 — Bob
python main.py bob --alice-ip 192.168.1.11 --alice-port 5001 --kb "BobKey1234567890"
```

Urutan: KDC → Alice → Bob.

**Langkah 3 — Uji semua ketentuan saat demo:**

| Test Case | Cara |
|---|---|
| **Key via CLI** | Jalankan seperti di atas |
| **Key interaktif tanpa CLI** | Hapus `--ka`/`--kb` → muncul prompt |
| **Key berubah tanpa restart** | Di chat: Alice ketik `/rekey NewSessionKey16` → Bob otomatis switch; lanjut chat dengan key baru |
| **Dua arah** | Alice ketik pesan → Bob baca; Bob ketik pesan → Alice baca |
| **ASCII & Hex** | Plaintext user terlihat ASCII di layar; Wireshark menampilkan Hex |
| **3 IP berbeda** | Cek `ip.addr` di Wireshark |
| **AES manual** | Tunjukkan `aes_manual.py` dan hasil `main.py test` |
| **KDC manual** | Tunjukkan `kdc.py` step 1 & 2 |

**Filter Wireshark:**
```
ip.addr == 192.168.1.10 || ip.addr == 192.168.1.11 || ip.addr == 192.168.1.12
```
atau
```
tcp.port == 5000 || tcp.port == 5001
```

---

### Fitur Tambahan

- **Runtime rekeying** (`/rekey`) — protokol ganti key terenkripsi tanpa restart, ini fitur kriptografis nyata.
- **Self-test AES-128** menggunakan test vector resmi NIST FIPS-197.
- **Validasi & konfirmasi key** sebelum skenario, memudahkan pengujian berbagai test case saat demo.
