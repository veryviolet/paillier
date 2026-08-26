"""Точность heu на двух масштабах кодировщика."""
import sys

from acc_common import HEADER, load_values, make_values, report
from heu import phe as hp

KEY_BITS = 2048

values = make_values() if "--make" in sys.argv else load_values()

kit = hp.setup(hp.SchemaType.ZPaillier, KEY_BITS)
enc, dec, ev = kit.encryptor(), kit.decryptor(), kit.evaluator()

print(HEADER)
for scale in (10 ** 6, 10 ** 8):
    encoder = hp.FloatEncoder(hp.SchemaType.ZPaillier, scale)
    blobs = [enc.encrypt(encoder.encode(float(v))) for v in values]
    circle = encoder.decode(dec.decrypt(blobs[0]))
    total = blobs[0]
    for blob in blobs[1:]:
        total = ev.add(total, blob)
    got = encoder.decode(dec.decrypt(total))
    report("heu", scale, circle, got, values)
