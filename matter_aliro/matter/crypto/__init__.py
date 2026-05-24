import collections
import dataclasses
import hashlib
import hmac
import secrets
import typing
import struct
import ecdsa.ellipticcurve
import ecdsa.curves

CRYPTO_HASH_LEN_BYTES = 32
CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES = 16
CRYPTO_CURVE = ecdsa.curves.NIST256p
CRYPTO_GROUP_SIZE_BYTES = 32
CRYPTO_W_SIZE_BYTES = CRYPTO_GROUP_SIZE_BYTES + 8
CRYPTO_AEAD_MIC_LENGTH_BYTES = 16
CRYPTO_PUBLIC_KEY_SIZE_BYTES = 65
POINT_M = ecdsa.ellipticcurve.Point.from_bytes(
    CRYPTO_CURVE.curve,
    b"\x02\x88\x6e\x2f\x97\xac\xe4\x6e\x55\xba\x9d\xd7\x24\x25\x79\xf2\x99\x3b\x64\xe1\x6e\xf3\xdc\xab\x95\xaf\xd4\x97\x33\x3d\x8f\xa1\x2f",
)
POINT_N = ecdsa.ellipticcurve.Point.from_bytes(
    CRYPTO_CURVE.curve,
    b"\x03\xd8\xbb\xd6\xc6\x39\xc6\x29\x37\xb0\x4d\x99\x7f\x38\xc3\x77\x07\x19\xc6\x29\xd7\x01\x4d\x49\xa2\x4b\x4f\x98\xba\xa1\x29\x2b\x49",
)
CONTENT_VALUE_PREFIX = b"CHIP PAKE V1 Commissioning"


@dataclasses.dataclass
class CryptoPBKDFParameterSet:
    iterations: int
    salt: bytes

    @classmethod
    def new(cls) -> "CryptoPBKDFParameterSet":
        return cls(
            iterations=10_000,
            salt=secrets.token_bytes(32)
        )


def crypto_hmac(key: bytes, message: bytes) -> bytes:
    h = hmac.new(key, digestmod=hashlib.sha256)
    h.update(message)
    return h.digest()


def hkdf_extract(salt: bytes, input_key: bytes) -> bytes:
    return crypto_hmac(salt, input_key)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    last_hash = b""
    bytes_generated = []
    num_bytes_generated = 0
    i = 1
    while num_bytes_generated < length:
        num_bytes_generated += CRYPTO_HASH_LEN_BYTES
        m = hmac.new(prk, digestmod=hashlib.sha256)
        m.update(last_hash)
        m.update(info)
        m.update(struct.pack("b", i))
        last_hash = m.digest()
        bytes_generated.append(last_hash)
        i += 1
    return b"".join(bytes_generated)


def crypto_pbkdf(data: bytes, output_len: int, params: CryptoPBKDFParameterSet) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", data, salt=params.salt, iterations=params.iterations, dklen=output_len)


def kdf(input_key: bytes, salt: typing.Optional[bytes], info: bytes, length: int):
    if salt is None:
        salt = bytes(CRYPTO_HASH_LEN_BYTES)
    return hkdf_expand(hkdf_extract(salt, input_key), info, length)[:length]


@dataclasses.dataclass
class CryptoPAKEValuesInitiator:
    w0: int
    w1: int

    @classmethod
    def generate(cls, passcode: int, params: CryptoPBKDFParameterSet) -> "CryptoPAKEValuesInitiator":
        d = crypto_pbkdf(passcode.to_bytes(4, "little"), output_len=2 * CRYPTO_W_SIZE_BYTES, params=params)
        w0s, w1s = d[0:CRYPTO_W_SIZE_BYTES], d[CRYPTO_W_SIZE_BYTES:2 * CRYPTO_W_SIZE_BYTES]
        w0 = int.from_bytes(w0s, "big") % CRYPTO_CURVE.order
        w1 = int.from_bytes(w1s, "big") % CRYPTO_CURVE.order
        return cls(w0=w0, w1=w1)


@dataclasses.dataclass
class CryptoPAKEValuesResponder:
    w0: int
    L: ecdsa.ellipticcurve.PointJacobi

    @classmethod
    def from_bytes(cls, data: bytes) -> "CryptoPAKEValuesResponder":
        assert len(data) == CRYPTO_GROUP_SIZE_BYTES + CRYPTO_PUBLIC_KEY_SIZE_BYTES
        return cls(
            w0=int.from_bytes(data[0:CRYPTO_GROUP_SIZE_BYTES], "big"),
            L=ecdsa.ellipticcurve.PointJacobi.from_bytes(CRYPTO_CURVE.curve, data[CRYPTO_GROUP_SIZE_BYTES:CRYPTO_GROUP_SIZE_BYTES + CRYPTO_PUBLIC_KEY_SIZE_BYTES],),
        )

    @classmethod
    def generate(cls, passcode: int, params: CryptoPBKDFParameterSet) -> "CryptoPAKEValuesResponder":
        v = CryptoPAKEValuesInitiator.generate(passcode, params)
        return cls(w0=v.w0, L=v.w1 * CRYPTO_CURVE.generator)


PAOutput = collections.namedtuple("pAOutput", ["X", "x"])
PBOutput = collections.namedtuple("pBOutput", ["Y", "y"])


def crypto_pa(values: CryptoPAKEValuesInitiator) -> PAOutput:
    n = secrets.randbelow(CRYPTO_CURVE.order)
    x: ecdsa.ellipticcurve.PointJacobi = n * CRYPTO_CURVE.generator + values.w0 * POINT_M
    return PAOutput(X=x.to_bytes("uncompressed"), x=n)


def crypto_pb(values: CryptoPAKEValuesResponder) -> PBOutput:
    n = secrets.randbelow(CRYPTO_CURVE.order)
    y: ecdsa.ellipticcurve.PointJacobi = n * CRYPTO_CURVE.generator + values.w0 * POINT_N
    return PBOutput(Y=y.to_bytes("uncompressed"), y=n)


SharedValues = collections.namedtuple("SharedValues", ["Z", "V"])


def prover_shared_values(values: CryptoPAKEValuesInitiator, pa_output: PAOutput, pb: bytes) -> SharedValues:
    y = ecdsa.ellipticcurve.Point.from_bytes(CRYPTO_CURVE.curve, pb)
    h = CRYPTO_CURVE.curve.cofactor()
    z = h * pa_output.x * (y + (-(values.w0 * POINT_N)))
    v = h * values.w1 * (y + (-(values.w0 * POINT_N)))
    return SharedValues(Z=z, V=v)


def verifier_shared_values(values: CryptoPAKEValuesResponder, pb_output: PBOutput, pa: bytes) -> SharedValues:
    x = ecdsa.ellipticcurve.Point.from_bytes(CRYPTO_CURVE.curve, pa)
    h = CRYPTO_CURVE.curve.cofactor()
    z = h * pb_output.y * (x + (-(values.w0 * POINT_M)))
    v = h * pb_output.y * values.L
    return SharedValues(Z=z, V=v)


def crypto_tt(
        values: typing.Union[CryptoPAKEValuesInitiator, CryptoPAKEValuesResponder],
        pbkdf_param_request: bytes,
        pbkdf_param_response: bytes,
        pa: bytes,
        pb: bytes,
        shared_values: SharedValues,
        id_prover: bytes = b"",
        id_verifier: bytes = b"",
) -> bytes:
    context = hashlib.sha256()
    context.update(CONTENT_VALUE_PREFIX)
    context.update(pbkdf_param_request)
    context.update(pbkdf_param_response)
    context = context.digest()

    elements = (
        context,
        id_prover,  # idProver
        id_verifier,  # idVerifier,
        POINT_M.to_bytes("uncompressed"),
        POINT_N.to_bytes("uncompressed"),
        pa,
        pb,
        shared_values.Z.to_bytes("uncompressed"),
        shared_values.V.to_bytes("uncompressed"),
        values.w0.to_bytes(CRYPTO_CURVE.baselen, "big")
    )

    tt = bytearray()
    for element in elements:
        tt.extend(len(element).to_bytes(8, "little"))
        tt.extend(element)

    return bytes(tt)


P2Output = collections.namedtuple("P2Output", ["cA", "cB", "Ke"])


def crypto_p2(tt: bytes, pa: bytes, pb: bytes) -> P2Output:
    k = hashlib.sha256(tt).digest()
    ka, ke = k[0:CRYPTO_HASH_LEN_BYTES // 2], k[CRYPTO_HASH_LEN_BYTES // 2:CRYPTO_HASH_LEN_BYTES]
    kc = kdf(ka, None, b"ConfirmationKeys", CRYPTO_HASH_LEN_BYTES)
    kc_a, kc_b = kc[0:CRYPTO_HASH_LEN_BYTES // 2], kc[CRYPTO_HASH_LEN_BYTES // 2:CRYPTO_HASH_LEN_BYTES]
    c_a = crypto_hmac(kc_a, pb)
    c_b = crypto_hmac(kc_b, pa)
    return P2Output(c_a, c_b, ke)
