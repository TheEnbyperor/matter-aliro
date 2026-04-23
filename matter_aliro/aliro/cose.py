import dataclasses
import typing
import cbor2
import cryptography.exceptions
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.asymmetric.ec
from . import util

@dataclasses.dataclass
class CoseHeaderCommon:
    algorithm: typing.Optional[typing.Union[int, str]] = None
    critical: typing.List[str] = dataclasses.field(default_factory=list)
    content_type: typing.Optional[typing.Union[int, str]] = None
    key_id: typing.Optional[bytes] = None
    iv: typing.Optional[bytes] = None
    partial_iv: typing.Optional[bytes] = None
    other: typing.Dict[typing.Union[int, str], typing.Any] = dataclasses.field(default_factory=dict)

    @classmethod
    def from_data(cls, data: dict) -> "CoseHeaderCommon":
        out = cls()
        for k, v in data.items():
            if k == 1:
                if not (isinstance(v, int) or isinstance(v, str)):
                    raise util.EncodingException("Invalid algorithm identifier")
                out.algorithm = v
            elif k == 2:
                if not isinstance(v, list):
                    raise util.EncodingException("Invalid critical fields")
                out.critical = v
            elif k == 3:
                if not (isinstance(v, int) or isinstance(v, str)):
                    raise util.EncodingException("Invalid content type")
                out.content_type = v
            elif k == 4:
                if not isinstance(v, bytes):
                    raise util.EncodingException("Invalid key ID")
                out.key_id = v
            elif k == 5:
                if not isinstance(v, bytes):
                    raise util.EncodingException("Invalid IV")
                out.iv = v
            elif k == 6:
                if not isinstance(v, bytes):
                    raise util.EncodingException("Invalid partial IV")
                out.partial_iv = v
            else:
                out.other[k] = v
        return out

@dataclasses.dataclass
class CoseSign1:
    protected_headers: CoseHeaderCommon
    unprotected_headers: CoseHeaderCommon
    payload: typing.Optional[bytes]
    _tbs: bytes
    signature: bytes

    @classmethod
    def from_data(cls, data) -> "CoseSign1":
        if not isinstance(data, list):
            raise util.EncodingException("Invalid COSE Sign1")
        if len(data) != 4:
            raise util.EncodingException("Invalid COSE Sign1")

        if not isinstance(data[0], bytes):
            raise util.EncodingException("Invalid COSE Sign1")
        if not isinstance(data[1], dict):
            raise util.EncodingException("Invalid COSE Sign1")
        if not (isinstance(data[2], bytes) or data[2] is None):
            raise util.EncodingException("Invalid COSE Sign1")
        if not isinstance(data[3], bytes):
            raise util.EncodingException("Invalid COSE Sign1")

        tbs = cbor2.dumps([
            "Signature1",
            data[0],
            b"",
            data[2]
        ])

        try:
            protected_headers = cbor2.loads(data[0])
        except cbor2.CBORDecodeError as e:
            raise util.EncodingException("Invalid COSE Sign1") from e
        if isinstance(protected_headers, bytes):
            if len(protected_headers) != 0:
                raise util.EncodingException("Invalid COSE Sign1")
            protected_headers = {}
        if not isinstance(protected_headers, dict):
            raise util.EncodingException("Invalid COSE Sign1")

        return cls(
            protected_headers=CoseHeaderCommon.from_data(protected_headers),
            unprotected_headers=CoseHeaderCommon.from_data(data[1]),
            payload=data[2],
            signature=data[3],
            _tbs=tbs,
        )

    def verify(self, pub_key) -> bool:
        if self.protected_headers.algorithm == -7:
            if not isinstance(pub_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
                return False
            if len(self.signature) != pub_key.key_size // 4:
                return False
            sig = cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(
                int.from_bytes(self.signature[0:pub_key.key_size // 8], "big"),
                int.from_bytes(self.signature[pub_key.key_size // 8:pub_key.key_size // 4], "big"),
            )
            try:
                pub_key.verify(sig, self._tbs, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA256(),
                ))
                return True
            except cryptography.exceptions.InvalidSignature:
                return False
        else:
            return False

@dataclasses.dataclass
class CoseKey:
    key_type: typing.Union[int, str]
    key_id: typing.Optional[bytes] = None
    algorithm: typing.Optional[typing.Union[int, str]] = None
    key_operations: typing.List[str] = dataclasses.field(default_factory=list)
    base_iv: typing.Optional[bytes] = None
    other: typing.Dict[typing.Union[int, str], typing.Any] = dataclasses.field(default_factory=dict)

    @classmethod
    def from_data(cls, data: dict) -> "CoseKey":
        if 1 not in data:
            raise util.EncodingException("Invalid COSE Key")
        if not (isinstance(data[1], int) or isinstance(data[1], str)):
            raise util.EncodingException("Invalid COSE Key")
        out = cls(
            key_type=data[1]
        )
        for k, v in data.items():
            if k == 1:
                pass
            elif k == 2:
                if not isinstance(v, bytes):
                    raise util.EncodingException("Invalid key ID")
                out.key_id = v
            elif k == 3:
                if not (isinstance(v, int) or isinstance(v, str)):
                    raise util.EncodingException("Invalid algorithm identifier")
                out.algorithm = v
            elif k == 4:
                if not isinstance(v, list):
                    raise util.EncodingException("Invalid key operations")
                out.key_operations = v
            elif k == 5:
                if not isinstance(v, bytes):
                    raise util.EncodingException("Invalid base IV")
                out.base_iv = v
            else:
                out.other[k] = v
        return out