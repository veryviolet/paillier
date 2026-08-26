"""Точность нашей реализации. Масштаб один: 1e8, зашит в src/lib.rs."""
from acc_common import HEADER, load_values, report

import paillier as p

KEY_BITS = 2048
SCALE = 10 ** 8

values = load_values()

pub, sec = p.generate_keypair(KEY_BITS)
blobs = [bytes(b) for b in p.encrypt_many(pub, values)]
circle = p.decrypt(sec, blobs[0])
got = p.decrypt(sec, p.add_many(pub, blobs))

print(HEADER)
report("наша", SCALE, circle, got, values)
