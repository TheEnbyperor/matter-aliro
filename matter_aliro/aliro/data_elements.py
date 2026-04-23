import dataclasses
import datetime
import enum
import typing
import ber_tlv.tlv
import cryptography.exceptions
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.utils
from . import util

class AuthenticationPolicy(enum.IntEnum):
    UserDeviceSetting = 0x01
    UserDeviceSettingSecureAction = 0x02
    ForceUserAuthentication = 0x03

class AccessCredentialKeyType(enum.Enum):
    KeySlot = enum.auto()
    PublicKey = enum.auto()

class ReaderStatus(enum.IntEnum):
    AccessCredentialNotFound = 0x0001
    AccessCredentialExpired = 0x0002
    AccessCredentialNotTrusted = 0x0003
    InvalidUserDeviceSignature = 0x0004
    InvalidDataFormat = 0x0006
    InvalidDataContent = 0x0007
    StatusWordError = 0x0020
    NoKeySlotPresent = 0x0021
    NoPublicKeyPresent = 0x0022
    NoUserDeviceSignaturePresent = 0x0023
    InvalidAccessRights = 0x0025
    HardwareIssue = 0x0026
    ReaderSecure = 0x0100
    ReaderUnsecure = 0x0101
    ReaderJammed = 0x0102
    ReaderSecureStarted = 0x0180
    ReaderUnsecureStarted = 0x0181
    ReaderUnknown = 0x0182

@dataclasses.dataclass
class SignallingBitmap:
    access_document_retrievable: bool
    revocation_document_retrievable: bool
    step_up_select_required: bool
    mailbox_has_data: bool
    mailbox_read_supported: bool
    mailbox_write_supported: bool
    credential_issuer_backend_supported: bool
    bound_application_supported: bool
    update_document_supported: bool
    mailbox_during_step_up_supported: bool
    notify_supported: bool
    update_document_during_step_up_supported: bool

    @classmethod
    def from_int(cls, value: int) -> "SignallingBitmap":
        return cls(
            access_document_retrievable=bool(value & 0b0000_0000_0000_0001),
            revocation_document_retrievable=bool(value & 0b0000_0000_0000_0010),
            step_up_select_required=bool(value & 0b0000_0000_0000_0100),
            mailbox_has_data=bool(value & 0b0000_0000_0000_1000),
            mailbox_read_supported=bool(value & 0b0000_0000_0001_0000),
            mailbox_write_supported=bool(value & 0b0000_0000_0010_0000),
            credential_issuer_backend_supported=bool(value & 0b0000_0000_0100_0000),
            bound_application_supported=bool(value & 0b0000_0000_1000_0000),
            update_document_supported=bool(value & 0b0000_0010_0000_0000),
            mailbox_during_step_up_supported=bool(value & 0b0000_0100_0000_0000),
            notify_supported=bool(value & 0b0000_1000_0000_0000),
            update_document_during_step_up_supported=bool(value & 0b0001_0000_0000_0000),
        )

@dataclasses.dataclass
class Auth1Authentication:
    reader_group_identifier: bytes
    reader_sub_group_identifier: bytes
    user_device_ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    reader_ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    transaction_identifier: bytes

    def _tbs(self, usage: bytes) -> bytes:
        return ber_tlv.tlv.Tlv.build({
            0x4D: self.reader_group_identifier[0:16] + self.reader_sub_group_identifier[0:16],
            0x86: self.user_device_ephemeral_public_key.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.X962,
                cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
            )[1:],
            0x87: self.reader_ephemeral_public_key.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.X962,
                cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
            )[1:],
            0x4C: self.transaction_identifier[0:16],
            0x93: usage
        })

    def sign(self, pk: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey) -> bytes:
        tbs = self._tbs(b"\x41\x5D\x95\x69")
        sig = pk.sign(tbs, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
            cryptography.hazmat.primitives.hashes.SHA256(),
        ))
        r, s = cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature(sig)
        return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

    def verify(self, pub_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey, signature: bytes) -> bool:
        tbs = self._tbs(b"\x4E\x88\x7B\x4C")
        try:
            pub_key.verify(signature, tbs, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA256(),
            ))
            return True
        except cryptography.exceptions.InvalidSignature:
            return False



@dataclasses.dataclass
class CryptogramPayload:
    signalling_bitmap: SignallingBitmap
    credential_signed_timestamp: typing.Optional[datetime.datetime]
    revocation_signed_timestamp: typing.Optional[datetime.datetime]

    @classmethod
    def decode(cls, data: bytes) -> "CryptogramPayload":
        try:
            data = ber_tlv.tlv.Tlv.parse(data, False)
        except (ber_tlv.tlv.BadLength, ber_tlv.tlv.BadTag, ber_tlv.tlv.BadParameter, ber_tlv.tlv.UnexpectedEnd) as e:
            raise util.EncodingException("Invalid TLV") from e

        signalling_bitmap = next(filter(lambda d: d[0] == 0x5E, data), None)
        if not signalling_bitmap:
            raise util.EncodingException("Signalling bitmap is required")
        if len(signalling_bitmap[1]) != 2:
            raise util.EncodingException("Invalid signalling bitmap")
        signalling_bitmap = int.from_bytes(signalling_bitmap[1], "big")

        credential_signed_timestamp = next(filter(lambda d: d[0] == 0x91, data), None)
        if not credential_signed_timestamp:
            raise util.EncodingException("Credential signed timestamp is required")
        if len(credential_signed_timestamp[1]) != 20:
            raise util.EncodingException("Invalid credential signed timestamp")
        credential_signed_timestamp = credential_signed_timestamp[1]
        revocation_signed_timestamp = next(filter(lambda d: d[0] == 0x92, data), None)
        if not revocation_signed_timestamp:
            raise util.EncodingException("Revocation signed timestamp is required")
        if len(revocation_signed_timestamp[1]) != 20:
            raise util.EncodingException("Invalid revocation signed timestamp")
        revocation_signed_timestamp = revocation_signed_timestamp[1]

        if credential_signed_timestamp != bytes(20):
            credential_signed_timestamp = credential_signed_timestamp.decode("ascii")
            credential_signed_timestamp = datetime.datetime.fromisoformat(credential_signed_timestamp)
        else:
            credential_signed_timestamp = None

        if revocation_signed_timestamp != bytes(20):
            revocation_signed_timestamp = revocation_signed_timestamp.decode("ascii")
            revocation_signed_timestamp = datetime.datetime.fromisoformat(revocation_signed_timestamp)

        return cls(
            signalling_bitmap=SignallingBitmap.from_int(signalling_bitmap),
            credential_signed_timestamp=credential_signed_timestamp,
            revocation_signed_timestamp=revocation_signed_timestamp,
        )