import dataclasses
import typing
import enum
import cbor2
from . import mdl_data_elements, util


class MDLSessionStatus(enum.IntEnum):
    SessionEncryptionError = 10
    CBORDecodingError = 11
    SessionTermination = 20

class MDLResponseStatus(enum.IntEnum):
    Ok = 0
    GeneralError = 10
    CBORDecodingError = 11
    CBORValidationError = 11

@dataclasses.dataclass
class SessionData:
    data: typing.Optional[bytes] = None
    status: typing.Optional[MDLSessionStatus] = None

    def encode(self) -> bytes:
        data = {}
        if self.data:
            data["data"] = self.data
        if self.status:
            data["status"] = self.status.value
        return cbor2.dumps(data)

    @classmethod
    def decode(cls, data: bytes) -> "SessionData":
        try:
            data = cbor2.loads(data)
        except cbor2.CBORDecodeError as e:
            raise util.EncodingException("Invalid session data") from e
        if not isinstance(data, dict):
            raise util.EncodingException("Invalid session data")
        out = cls()
        if "data" in data:
            if not isinstance(data["data"], bytes):
                raise util.EncodingException("Invalid session data")
            out.data = data["data"]
        if "status" in data:
            if not isinstance(data["status"], int):
                raise util.EncodingException("Invalid session status")
            out.status = MDLSessionStatus(data["status"])
        return out

@dataclasses.dataclass
class DocumentRequest:
    document_type: str
    namespaces: typing.Dict[str, typing.Dict[str, bool]]

    def to_dict(self) -> dict:
        return {
            "1": cbor2.CBORTag(24, cbor2.dumps({
                "1": self.namespaces,
                "5": self.document_type,
            }))
        }


@dataclasses.dataclass
class DeviceRequest:
    version: str
    document_requests: typing.List[DocumentRequest]

    def encode(self) -> bytes:
        return cbor2.dumps({
            "1": self.version,
            "2": [r.to_dict() for r in self.document_requests],
        })

@dataclasses.dataclass
class DeviceResponse:
    version: str
    documents: typing.List[mdl_data_elements.Document]
    status: MDLResponseStatus

    @classmethod
    def decode(cls, data: bytes) -> "DeviceResponse":
        try:
            data = cbor2.loads(data)
        except cbor2.CBORDecodeError as e:
            raise util.EncodingException("Invalid device response") from e
        if not isinstance(data, dict):
            raise util.EncodingException("Invalid device response")

        if "1" not in data:
            raise util.EncodingException("Invalid device response")
        if not isinstance(data["1"], str):
            raise util.EncodingException("Invalid device response")

        if "3" not in data:
            raise util.EncodingException("Invalid device response")
        if not isinstance(data["3"], int):
            raise util.EncodingException("Invalid device response")

        if "2" not in data:
            documents = []
        else:
            if not isinstance(data["2"], list):
                raise util.EncodingException("Invalid device response")
            documents = [mdl_data_elements.Document.from_dict(d) for d in data["2"]]

        out = cls(
            version=data["1"],
            documents=documents,
            status=MDLResponseStatus(data["3"]),
        )
        return out