import dataclasses
import enum
import typing
from .. import encoding

@dataclasses.dataclass
class MessageFlags(encoding.BitStruct):
    version: int
    source_node_id_present: bool
    destination_node_id_size: int

    class Meta:
        fields = (
            (2, "destination_node_id_size"),
            (1, "source_node_id_present"),
            (1, None),
            (4, "version"),
        )


class SessionType(enum.Enum):
    Unicast = 0
    Group = 1


@dataclasses.dataclass
class SecurityFlags(encoding.BitStruct):
    privacy: bool
    control: bool
    message_extensions: bool
    session_type: SessionType

    class Meta:
        fields = (
            (1, "privacy"),
            (1, "control"),
            (1, "message_extensions"),
            (3, None),
            (2, "session_type"),
        )


@dataclasses.dataclass
class MatterFrame(encoding.Encodable, encoding.Decodable):
    version: int
    session_id: int
    message_counter: int
    privacy: bool
    control: bool
    session_type: SessionType
    source_node_id: typing.Optional[bytes]
    destination_group_id: typing.Optional[bytes]
    destination_node_id: typing.Optional[bytes]
    message_extensions: typing.Optional[bytes]
    payload: bytes
    authenticated_header: bytes = b""

    @property
    def is_unsecured_session(self):
        return self.session_id == 0 and self.session_type == SessionType.Unicast

    @property
    def is_secure_unicast_session(self):
        return self.session_id != 0 and self.session_type == SessionType.Unicast

    @property
    def is_unicast_session(self):
        return self.session_type == SessionType.Unicast

    @property
    def is_group_session(self):
        return self.session_type == SessionType.Group

    @property
    def security_flags(self) -> bytes:
        return self.authenticated_header[3:4]

    def encode_to_bytes(self) -> bytes:
        out = bytearray()
        out.extend(MessageFlags(
            version=self.version,
            source_node_id_present=self.source_node_id is not None,
            destination_node_id_size=1 if self.destination_node_id is not None else 2 if self.destination_group_id is not None else 0,
        ).encode_to_bytes())
        out.extend(self.session_id.to_bytes(2, "little"))
        out.extend(SecurityFlags(
            privacy=self.privacy,
            control=self.control,
            message_extensions=self.message_extensions is not None,
            session_type=self.session_type,
        ).encode_to_bytes())
        out.extend(self.message_counter.to_bytes(4, "little"))
        if self.source_node_id is not None:
            out.extend(self.source_node_id[0:8])
        if self.destination_node_id is not None:
            out.extend(self.destination_node_id[0:8])
        elif self.destination_group_id is not None:
            out.extend(self.destination_group_id[0:2])
        if self.message_extensions is not None:
            out.extend(len(self.message_extensions).to_bytes(2, "little"))
            out.extend(self.message_extensions)
        out.extend(self.payload)
        return bytes(out)

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "MatterFrame":
        if len(data) < 8:
            raise ValueError("Not enough data")

        message_flags = MessageFlags.decode_from_bytes(data[0:1])
        session_id = int.from_bytes(data[1:3], "little")
        security_flags = SecurityFlags.decode_from_bytes(data[3:4])
        message_counter = int.from_bytes(data[4:8], "little")
        i = 8

        if message_flags.source_node_id_present:
            source_node_id = data[i:i + 8]
            i += 8
        else:
            source_node_id = None
        if message_flags.destination_node_id_size == 0:
            destination_node_id = None
            destination_group_id = None
        elif message_flags.destination_node_id_size == 1:
            destination_node_id = None
            destination_group_id = data[i:i + 2]
            i += 2
        elif message_flags.destination_node_id_size == 2:
            destination_node_id = data[i:i + 8]
            destination_group_id = None
            i += 8
        else:
            raise ValueError(f"Unsupported destination node ID size")

        if security_flags.message_extensions:
            message_extensions_length = int.from_bytes(data[i:i + 2], "little")
            message_extensions = data[i + 2:i + message_extensions_length + 2]
            i += message_extensions_length + 2
        else:
            message_extensions = None

        return cls(
            version=message_flags.version,
            session_id=session_id,
            message_counter=message_counter,
            privacy=security_flags.privacy,
            control=security_flags.control,
            session_type=security_flags.session_type,
            source_node_id=source_node_id,
            destination_node_id=destination_node_id,
            destination_group_id=destination_group_id,
            message_extensions=message_extensions,
            authenticated_header=data[:i],
            payload=data[i:],
        )


@dataclasses.dataclass
class ExchangeFlags(encoding.BitMask):
    initiator: bool
    acknowledgement: bool
    reliability: bool
    secured_extensions: bool
    vendor: bool

    class Meta:
        size = 1
        fields = (
            (0, "initiator"),
            (1, "acknowledgement"),
            (2, "reliability"),
            (3, "secured_extensions"),
            (4, "vendor"),
        )


@dataclasses.dataclass
class ProtocolMessage(encoding.Encodable, encoding.Decodable):
    initiator: bool
    reliability: bool
    exchange_id: int
    protocol_vendor_id: int
    protocol_id: int
    protocol_opcode: int
    acknowledged_message_counter: typing.Optional[int]
    secured_message_extensions: typing.Optional[bytes]
    payload: bytes

    def encode_to_bytes(self) -> bytes:
        out = bytearray()
        out.extend(ExchangeFlags(
            initiator=self.initiator,
            reliability=self.reliability,
            acknowledgement=self.acknowledged_message_counter is not None,
            secured_extensions=self.secured_message_extensions is not None,
            vendor=self.protocol_vendor_id != 0,
        ).encode_to_bytes())
        out.append(self.protocol_opcode)
        out.extend(self.exchange_id.to_bytes(2, "little"))
        if self.protocol_vendor_id != 0:
            out.extend(self.protocol_vendor_id.to_bytes(2, "little"))
        out.extend(self.protocol_id.to_bytes(2, "little"))
        if self.acknowledged_message_counter is not None:
            out.extend(self.acknowledged_message_counter.to_bytes(4, "little"))
        if self.secured_message_extensions is not None:
            out.extend(len(self.secured_message_extensions).to_bytes(2, "little"))
            out.extend(self.secured_message_extensions)
        out.extend(self.payload)
        return bytes(out)

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "ProtocolMessage":
        exchange_flags = ExchangeFlags.decode_from_bytes(data[0:1])
        protocol_opcode = data[1]
        exchange_id = int.from_bytes(data[2:4], "little")
        i = 4

        if exchange_flags.vendor:
            protocol_vendor_id = int.from_bytes(data[i:i + 2], "little")
            i += 2
        else:
            protocol_vendor_id = 0

        protocol_id = int.from_bytes(data[i:i + 2], "little")
        i += 2

        if exchange_flags.acknowledgement:
            acknowledged_message_counter = int.from_bytes(data[i:i + 4], "little")
            i += 4
        else:
            acknowledged_message_counter = None

        if exchange_flags.secured_extensions:
            secured_message_extensions_length = int.from_bytes(data[i:i + 2], "little")
            secured_message_extensions = data[i + 2:i + secured_message_extensions_length + 2]
            i += secured_message_extensions_length + 2
        else:
            secured_message_extensions = None

        payload = data[i:]

        return cls(
            initiator=exchange_flags.initiator,
            reliability=exchange_flags.reliability,
            exchange_id=exchange_id,
            protocol_vendor_id=protocol_vendor_id,
            protocol_id=protocol_id,
            protocol_opcode=protocol_opcode,
            acknowledged_message_counter=acknowledged_message_counter,
            secured_message_extensions=secured_message_extensions,
            payload=payload,
        )

class GeneralCode(enum.IntEnum):
    SUCCESS = 0 # Operation completed successfully.
    FAILURE = 1 # Generic failure, additional details may be included in the protocol specific status.
    BAD_PRECONDITION = 2 # Operation was rejected by the system because the system is in an invalid state.
    OUT_OF_RANGE = 3 # A value was out of a required range.
    BAD_REQUEST = 4 # A request was unrecognized or malformed.
    UNSUPPORTED = 5 # An unrecognized or unsupported request was received.
    UNEXPECTED = 6 # A request was not expected at this time.
    RESOURCE_EXHAUSTED = 7 # Insufficient resources to process the given request.
    BUSY = 8 # Device is busy and cannot handle this request at this time.
    TIMEOUT = 9 # A timeout occurred.
    CONTINUE = 10 # Context-specific signal to proceed.
    ABORTED = 11 #  Failure, may be due to a concurrency error.
    INVALID_ARGUMENT = 12 # An invalid/unsupported argument was provided.
    NOT_FOUND = 13 # Some requested entity was not found.
    ALREADY_EXISTS = 14 # The sender attempted to create something that already exists.
    PERMISSION_DENIED = 15 # The sender does not have sufficient permissions to execute the requested operations.
    DATA_LOSS = 16 # Unrecoverable data loss or corruption has occurred.
    MESSAGE_TOO_LARGE = 17 # Message size is larger than the recipient can handle.

@dataclasses.dataclass
class StatusReport(encoding.Encodable, encoding.Decodable):
    general_code: GeneralCode
    protocol_vendor_id: int
    protocol_id: int
    protocol_code: int
    protocol_data: bytes

    def encode_to_bytes(self) -> bytes:
        out = bytearray()
        out.extend(self.general_code.value.to_bytes(2, "little"))
        out.extend(self.protocol_vendor_id.to_bytes(2, "little"))
        out.extend(self.protocol_id.to_bytes(2, "little"))
        out.extend(self.protocol_code.to_bytes(2, "little"))
        out.extend(self.protocol_data)
        return bytes(out)

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "StatusReport":
        if len(data) < 8:
            raise ValueError("Not enough data")

        return cls(
            general_code=GeneralCode(int.from_bytes(data[0:2], "little")),
            protocol_vendor_id=int.from_bytes(data[2:4], "little"),
            protocol_id=int.from_bytes(data[4:6], "little"),
            protocol_code=int.from_bytes(data[6:8], "little"),
            protocol_data=data[8:],
        )