import abc
import hashlib
import cryptography.x509
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec


class GeneralException(Exception):
    pass


class ISO7816Exception(GeneralException):
    def __init__(self, msg: str, sw1: int, sw2: int):
        self.msg = msg
        self.sw1 = sw1
        self.sw2 = sw2

    def __repr__(self):
        return f"ISO7816Exception({self.msg}; sw1=0x{self.sw1:02X}, sw2={self.sw2:02x})"


class EncodingException(GeneralException):
    pass


class CryptoException(GeneralException):
    pass


class PublicKey(metaclass=abc.ABCMeta):
    def public_key(self) -> cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey:
        raise NotImplementedError()

    def aliro_key_slot(self) -> bytes:
        return aliro_key_slot(self.public_key())

    def aliro_key_identifier(self) -> bytes:
        return aliro_key_identifier(self.public_key())


def aliro_key_slot(pk: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
    return cryptography.x509.SubjectKeyIdentifier.from_public_key(pk).digest[:8]


def aliro_key_identifier(pk: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey) -> bytes:
    return hashlib.sha256(b"key-identifier" + pk.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.X962,
        cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
    )).digest()[:8]
