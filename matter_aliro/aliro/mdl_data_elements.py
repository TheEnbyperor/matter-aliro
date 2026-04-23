import dataclasses
import typing
import cbor2
import datetime
import cryptography.hazmat.primitives.asymmetric.ec
from . import cose, util

@dataclasses.dataclass
class Document:
    document_type: str
    namespaces: typing.Dict[str, typing.List[bytes]]
    issuer_auth: cose.CoseSign1

    @classmethod
    def from_dict(cls, data: dict) -> "Document":
        if "5" not in data:
            raise util.EncodingException("Invalid document")
        if not isinstance(data["5"], str):
            raise util.EncodingException("Invalid document")

        if "1" not in data:
            raise util.EncodingException("Invalid document")
        if not isinstance(data["1"], dict):
            raise util.EncodingException("Invalid document")

        issuer_signed = data["1"]
        if "1" not in issuer_signed:
            raise util.EncodingException("Invalid document")
        if not isinstance(issuer_signed["1"], dict):
            raise util.EncodingException("Invalid document")
        namespaces = {}
        for k, v in issuer_signed["1"].items():
            if not isinstance(v, list):
                raise util.EncodingException("Invalid document")
            values = []
            for i in v:
                if not isinstance(i, cbor2.CBORTag):
                    raise util.EncodingException("Invalid document")
                if i.tag != 24:
                    raise util.EncodingException("Invalid document")
                if not isinstance(i.value, bytes):
                    raise util.EncodingException("Invalid document")
                values.append(i.value)
            namespaces[k] = values

        if "2" not in issuer_signed:
            raise util.EncodingException("Invalid document")
        issuer_auth = cose.CoseSign1.from_data(issuer_signed["2"])

        return cls(
            document_type=data["5"],
            namespaces=namespaces,
            issuer_auth=issuer_auth,
        )
    
@dataclasses.dataclass
class DeviceKeyInfo:
    device_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceKeyInfo":
        if "1" not in data:
            raise util.EncodingException("Invalid device key")
        if not isinstance(data["1"], dict):
            raise util.EncodingException("Invalid device key")

        cose_key = cose.CoseKey.from_data(data["1"])

        if cose_key.key_type != 2:
            raise util.EncodingException("Unsupported device key type")

        if -1 not in cose_key.other:
            raise util.EncodingException("Invalid device key")
        if cose_key.other[-1] == 1:
            curve = cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
            x_len = 32
        elif cose_key.other[-1] == 2:
            curve = cryptography.hazmat.primitives.asymmetric.ec.SECP384R1()
            x_len = 48
        elif cose_key.other[-1] == 3:
            curve = cryptography.hazmat.primitives.asymmetric.ec.SECP521R1()
            x_len = 66
        else:
            raise util.EncodingException("Unsupported device key type")

        if -2 not in cose_key.other:
            raise util.EncodingException("Invalid device key")
        if not isinstance(cose_key.other[-2], bytes):
            raise util.EncodingException("Invalid device key")
        if len(cose_key.other[-2]) != x_len:
            raise util.EncodingException("Invalid device key")

        if -3 not in cose_key.other:
            raise util.EncodingException("Invalid device key")
        if isinstance(cose_key.other[-3], bytes):
            if len(cose_key.other[-3]) != x_len:
                raise util.EncodingException("Invalid device key")
            encoded_point = b"\x04" + cose_key.other[-2] + cose_key.other[-3]
        elif isinstance(cose_key.other[-3], bool):
            if cose_key.other[-3]:
                encoded_point = b"\x03" + cose_key.other[-3]
            else:
                encoded_point = b"\x02" + cose_key.other[-2]
        else:
            raise util.EncodingException("Invalid device key")

        device_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(curve, encoded_point)
        return cls(
            device_key=device_key,
        )


@dataclasses.dataclass
class ValidityInfo:
    signed: datetime.datetime
    valid_from: datetime.datetime
    valid_to: datetime.datetime
    expected_update: typing.Optional[datetime.datetime]
    validity_iteration: int

    @classmethod
    def from_dict(cls, data: dict) -> "ValidityInfo":
        if "1" not in data:
            raise RuntimeError("Invalid validity info")
        if not isinstance(data["1"], datetime.datetime):
            raise RuntimeError("Invalid validity info")
        if "2" not in data:
            raise RuntimeError("Invalid validity info")
        if not isinstance(data["2"], datetime.datetime):
            raise RuntimeError("Invalid validity info")
        if "3" not in data:
            raise RuntimeError("Invalid validity info")
        if not isinstance(data["3"], datetime.datetime):
            raise RuntimeError("Invalid validity info")
        if "4" in data:
            if not isinstance(data["4"], datetime.datetime):
                raise RuntimeError("Invalid validity info")
        if "5" in data:
            if not isinstance(data["5"], int):
                raise RuntimeError("Invalid validity info")

        return cls(
            signed=data["1"],
            valid_from=data["2"],
            valid_to=data["3"],
            expected_update=data.get("4"),
            validity_iteration=data.get("5")
        )

@dataclasses.dataclass
class MobileSecurityObject:
    version: str
    digest_algorithm: str
    value_digests: typing.Dict[str, typing.Dict[int, bytes]]
    device_key: DeviceKeyInfo
    document_type: str
    validity_info: ValidityInfo
    time_verification_required: bool

    @classmethod
    def decode(cls, data: bytes) -> "MobileSecurityObject":
        try:
            data = cbor2.loads(data)
        except cbor2.CBORDecodeError as e:
            raise util.EncodingException("Invalid mobile security object") from e

        if not isinstance(data, cbor2.CBORTag):
            raise util.EncodingException("Invalid mobile security object")
        if data.tag != 24:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data.value, bytes):
            raise util.EncodingException("Invalid mobile security object")

        try:
            data = cbor2.loads(data.value)
        except cbor2.CBORDecodeError as e:
            raise util.EncodingException("Invalid mobile security object") from e

        if not isinstance(data, dict):
            raise util.EncodingException("Invalid mobile security object")

        if "1" not in data:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data["1"], str):
            raise util.EncodingException("Invalid mobile security object")

        if "2" not in data:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data["2"], str):
            raise util.EncodingException("Invalid mobile security object")

        if "3" not in data:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data["3"], dict):
            raise util.EncodingException("Invalid mobile security object")
        for k, v in data["3"].items():
            if not isinstance(k, str):
                raise util.EncodingException("Invalid mobile security object")
            if not isinstance(v, dict):
                raise util.EncodingException("Invalid mobile security object")
            for k1, v1 in v.items():
                if not isinstance(k1, int):
                    raise util.EncodingException("Invalid mobile security object")
                if not isinstance(v1, bytes):
                    raise util.EncodingException("Invalid mobile security object")

        if "4" not in data:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data["4"], dict):
            raise util.EncodingException("Invalid mobile security object")

        if "5" not in data:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data["5"], str):
            raise util.EncodingException("Invalid mobile security object")

        if "6" not in data:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data["6"], dict):
            raise util.EncodingException("Invalid mobile security object")

        if "7" not in data:
            raise util.EncodingException("Invalid mobile security object")
        if not isinstance(data["7"], bool):
            raise util.EncodingException("Invalid mobile security object")

        return cls(
            version=data["1"],
            digest_algorithm=data["2"],
            value_digests=data["3"],
            device_key=DeviceKeyInfo.from_dict(data["4"]),
            document_type=data["5"],
            validity_info=ValidityInfo.from_dict(data["6"]),
            time_verification_required=data["7"],
        )

@dataclasses.dataclass
class IssuerSignedItem:
    digest_id: int
    random: bytes
    element_identifier: str
    element_value: typing.Any

    @classmethod
    def decode(cls, data: bytes) -> "IssuerSignedItem":
        try:
            data = cbor2.loads(data)
        except cbor2.CBORDecodeError as e:
            raise util.EncodingException("Invalid issuer signed data") from e

        if not isinstance(data, dict):
            raise util.EncodingException("Invalid issuer signed item")

        if "1" not in data:
            raise util.EncodingException("Invalid issuer signed item")
        if not isinstance(data["1"], int):
            raise util.EncodingException("Invalid issuer signed item")

        if "2" not in data:
            raise util.EncodingException("Invalid issuer signed item")
        if not isinstance(data["2"], bytes):
            raise util.EncodingException("Invalid issuer signed item")

        if "3" not in data:
            raise util.EncodingException("Invalid issuer signed item")
        if not isinstance(data["3"], str):
            raise util.EncodingException("Invalid issuer signed item")
        if "4" not in data:
            raise util.EncodingException("Invalid issuer signed item")

        return cls(
            digest_id=data["1"],
            random=data["2"],
            element_identifier=data["3"],
            element_value=data["4"],
        )