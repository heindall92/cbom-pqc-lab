"""Genera un certificado X.509 COMPUESTO de ejemplo (ML-DSA-65 + ECDSA P-256).

OID id-MLDSA65-ECDSA-P256-SHA512 = 1.3.6.1.5.5.7.6.45 (draft-ietf-lamps-pq-composite-sigs-19,
asignación temprana de IANA; provisional hasta su publicación como RFC).
La clave pública es real (mldsaPK || ecPK sin comprimir); la firma es de RELLENO y no se puede verificar:
solo sirve para comprobar que el inventario reconoce el algoritmo. Escribe PEM en stdout.
"""
import base64, datetime, os, subprocess, tempfile

def tlv(tag, body):
    n = len(body)
    if n < 0x80: l = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big"); l = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + l + body
seq = lambda *p: tlv(0x30, b"".join(p))
def oid(s):
    a = [int(x) for x in s.split(".")]; out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7F]; v >>= 7
        while v: enc.insert(0, 0x80 | (v & 0x7F)); v >>= 7
        out += bytes(enc)
    return tlv(0x06, out)
bits = lambda b: tlv(0x03, b"\x00" + b)
utf8 = lambda s: tlv(0x0C, s.encode())
def name(cn):
    atv = lambda o, v: tlv(0x31, seq(oid(o), v))
    return seq(atv("2.5.4.6", tlv(0x13, b"ES")), atv("2.5.4.10", utf8("Banco Ficticio Atlantida S.A. (EJEMPLO)")), atv("2.5.4.3", utf8(cn)))
gt = lambda d: tlv(0x17, d.strftime("%y%m%d%H%M%SZ").encode())

def raw_pub(alg, *opts):
    with tempfile.TemporaryDirectory() as d:
        k = os.path.join(d, "k")
        subprocess.run(["openssl", "genpkey", "-algorithm", alg, *opts, "-out", k], check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", k, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    # SubjectPublicKeyInfo: el BIT STRING es el último elemento; se omite su byte de bits no usados.
    i = der.rfind(b"\x03", 0, 40)
    while True:
        n = der[i + 1]; hl = 2
        if n & 0x80: k_ = n & 0x7F; n = int.from_bytes(der[i + 2:i + 2 + k_], "big"); hl += k_
        if i + hl + n == len(der): return der[i + hl + 1:]
        i = der.rfind(b"\x03", 0, i)

COMP = "1.3.6.1.5.5.7.6.45"
CN = "pasarela-hibrida.atlantida.example"
pk = raw_pub("ML-DSA-65") + raw_pub("EC", "-pkeyopt", "ec_paramgen_curve:P-256")
assert len(pk) == 1952 + 65
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
alg = seq(oid(COMP))
ext = lambda o, v, crit=False: seq(oid(o), *( [tlv(0x01, b"\xff")] if crit else []), tlv(0x04, v))
exts = tlv(0xA3, seq(
    ext("2.5.29.19", seq(), True),
    ext("2.5.29.15", tlv(0x03, b"\x07\x80"), True),
    ext("2.5.29.17", seq(tlv(0x82, CN.encode()))),
))
tbs = seq(tlv(0xA0, tlv(0x02, b"\x02")), tlv(0x02, os.urandom(15).lstrip(b"\x00") or b"\x01"), alg, name(CN),
          seq(gt(now), gt(now + datetime.timedelta(days=397))), name(CN), seq(alg, bits(pk)), exts)
sig = os.urandom(3309) + seq(tlv(0x02, b"\x01" + os.urandom(31)), tlv(0x02, b"\x01" + os.urandom(31)))
cert = seq(tbs, alg, bits(sig))
b = base64.b64encode(cert).decode()
print("-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----")
