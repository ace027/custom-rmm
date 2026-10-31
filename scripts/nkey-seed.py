#!/usr/bin/env python3
"""Print the NATS user seed (SU...) for a raw 32-byte Ed25519 seed file.

Used by scripts/e2e-enroll.sh to impersonate an agent with nats-box. The
encoding follows nkeys: the seed prefix byte 0x90 (18 << 3) is combined with
the user prefix 0xA0 (20 << 3) into two bytes, followed by the raw seed and a
CRC16-XMODEM checksum (little-endian), base32 encoded without padding.

Usage: scripts/nkey-seed.py <raw-seed-file>
"""

import base64
import sys

PREFIX_SEED = 18 << 3  # 0x90
PREFIX_USER = 20 << 3  # 0xA0


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def user_seed(raw: bytes) -> str:
    if len(raw) != 32:
        raise ValueError(f"expected 32 bytes, got {len(raw)}")
    body = bytes([PREFIX_SEED | (PREFIX_USER >> 5), (PREFIX_USER & 31) << 3]) + raw
    body += crc16_xmodem(body).to_bytes(2, "little")
    return base64.b32encode(body).decode().rstrip("=")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as f:
        raw = f.read()
    try:
        print(user_seed(raw))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
