import base64
import typing
import enum
import secrets
import nfc
import nfc.tag.tt4
import time
import ber_tlv.tlv
import dataclasses
import datetime
import cryptography.exceptions
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.kdf.x963kdf
import cryptography.hazmat.primitives.kdf.hkdf
import cryptography.hazmat.primitives.ciphers.aead
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.utils
import broadcast_frame_contactless_frontend

class RequestAPDU:
    instruction_class: int
    instruction: int
    p1: int
    p2: int
    data: bytes
    expected_response_length: int

    def __init__(
            self, instruction_class: int, instruction: int, p1: int, p2: int,
            data: bytes, expected_response_length: int
    ):
        self.instruction_class = instruction_class
        self.instruction = instruction
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expected_response_length = expected_response_length

    def __str__(self):
        return (f"RequestAPDU(class={self.instruction_class:02x}, "
                f"instruction={self.instruction:02x}, "
                f"p1={self.p1:02x}, p2={self.p2:02x}, "
                f"data={self.data.hex().upper()}), "
                f"expected_response_length={self.expected_response_length})")

    def __repr__(self):
        return str(self)

    def encode(self):
        data_len = len(self.data)

        if self.expected_response_length == 0 and data_len == 0:
            raise ValueError("Expected response length cannot be 0 with no command data")

        out = bytearray([
            self.instruction_class,
            self.instruction,
            self.p1,
            self.p2,
        ])

        if data_len == 0:
            pass
        elif data_len < 256:
            out.append(data_len)
        elif data_len < t:
            out.append(0)
            out.extend(data_len.to_bytes(2, "big"))
        else:
            raise ValueError("Data length too long")
        out.extend(self.data)

        if self.expected_response_length == 0:
            pass
        else:
            if data_len >= 256:
                if self.expected_response_length == 65536:
                    out.append(0)
                    out.append(0)
                elif self.expected_response_length < 65536:
                    out.extend(self.expected_response_length.to_bytes(2, "big"))
                else:
                    raise ValueError("Invalid expected response length")
            else:
                if self.expected_response_length == 256:
                    out.append(0)
                elif self.expected_response_length == 65536:
                    out.append(0)
                    out.append(0)
                    out.append(0)
                elif self.expected_response_length < 256:
                    out.append(self.expected_response_length)
                elif self.expected_response_length < 65536:
                    out.append(0)
                    out.extend(self.expected_response_length.to_bytes(2, "big"))
                else:
                    raise ValueError("Invalid expected response length")
        return bytes(out)


class ResponseAPDU:
    sw1: int
    sw2: int
    data: bytes

    def __init__(self, sw1: int, sw2: int, data: bytes):
        self.sw1 = sw1
        self.sw2 = sw2
        self.data = data

    @classmethod
    def decode(cls, data: bytes):
        return cls(
            data=data[:-2],
            sw1=data[-2],
            sw2=data[-1],
        )

    def __str__(self):
        return (f"ResponseAPDU(data={self.data.hex().upper()}, "
                f"sw1={self.sw1:02x}, sw2={self.sw2:02x})")

    def __repr__(self):
        return str(self)

    def is_success(self):
        return self.sw1 == 0x90 and self.sw2 == 0x00


class Terminal:
    def __init__(self, device: nfc.tag.tt4.Type4Tag):
        self.device = device

    def transmit(self, request: RequestAPDU) -> ResponseAPDU:
        return ResponseAPDU.decode(self.device.transceive(request.encode()))

@dataclasses.dataclass
class PersistentKey:
    key: bytes
    authentication_credential_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey

@dataclasses.dataclass
class ReaderConfig:
    signing_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    group_identifier: bytes
    sub_group_identifier: bytes
    persistent_keys: typing.List[PersistentKey]


@dataclasses.dataclass
class UserDeviceDescriptor:
    vendor_id: int
    product_id: bytes
    firmware_version: bytes


@dataclasses.dataclass
class SelectResponse:
    application_type: int
    expedited_phase_supported_protocol_versions: typing.List[int]
    max_command_apdu: typing.Optional[int]
    max_response_apdu: typing.Optional[int]
    user_device_descriptor: typing.Optional[UserDeviceDescriptor]
    fci_proprietary_bytes: bytes

    @classmethod
    def decode(cls, data: bytes, target_aid: bytes) -> "SelectResponse":
        data = ber_tlv.tlv.Tlv.parse(data, False)
        fci = next(filter(lambda d: d[0] == 0x6F, data), None)
        udd = next(filter(lambda d: d[0] == 0xB7, data), None)

        if not fci:
            raise RuntimeError("SELECT response missing FCI")

        fci = ber_tlv.tlv.Tlv.parse(fci[1], False)
        udd = ber_tlv.tlv.Tlv.parse(udd[1], True) if udd else None

        aid = next(filter(lambda d: d[0] == 0x84, fci), None)
        if not aid:
            raise RuntimeError("SELECT response missing AID")
        if aid[1] != target_aid:
            raise RuntimeError("SELECT response AID mismatch")

        fci_proprietary = next(filter(lambda d: d[0] == 0xA5, fci), None)
        if not fci_proprietary:
            raise RuntimeError("SELECT response missing FCI proprietary data")
        fci_proprietary_bytes = ber_tlv.tlv.Tlv.build({0xA5: fci_proprietary[1]})
        fci_proprietary = ber_tlv.tlv.Tlv.parse(fci_proprietary[1], True)

        application_type = next(filter(lambda d: d[0] == 0x80, fci_proprietary), None)
        if not application_type:
            raise RuntimeError("SELECT response missing application type")
        application_type = application_type[1]
        if len(application_type) != 2:
            raise RuntimeError("Invalid Aliro application type")
        application_type = int.from_bytes(application_type, "big")

        expedited_phase_supported_protocol_versions = next(filter(lambda d: d[0] == 0x5C, fci_proprietary), None)
        if expedited_phase_supported_protocol_versions:
            if len(expedited_phase_supported_protocol_versions[1]) % 2 != 0:
                raise RuntimeError("Invalid Expedited Phase Supported Protocol Version")
            expedited_phase_supported_protocol_versions = [
                int.from_bytes(expedited_phase_supported_protocol_versions[1][i:i + 2], "big")
                for i in range(0, len(expedited_phase_supported_protocol_versions[1]), 2)
            ]
        else:
            expedited_phase_supported_protocol_versions = []

        extended_length_information = next(filter(lambda d: d[0] == 0x7F66, fci_proprietary), None)
        if extended_length_information:
            if len(extended_length_information[1]) != 2:
                raise RuntimeError("Invalid Extended Length Information")
            max_command_apdu = extended_length_information[1][0]
            max_response_apdu = extended_length_information[1][1]
            if max_command_apdu[0] != 0x02:
                raise RuntimeError("Invalid Extended Length Information")
            if max_response_apdu[0] != 0x02:
                raise RuntimeError("Invalid Extended Length Information")
            max_command_apdu = int.from_bytes(max_command_apdu[1], "big")
            max_response_apdu = int.from_bytes(max_response_apdu[1], "big")
        else:
            max_command_apdu = None
            max_response_apdu = None

        if udd:
            vendor_id = next(filter(lambda d: d[0] == 0x04, udd), None)
            if not vendor_id:
                raise RuntimeError("SELECT response missing UDD Vendor ID")
            vendor_id = int.from_bytes(vendor_id[1], "big")
            product_id = next(filter(lambda d: d[0] == 0x80, udd), None)
            if not product_id:
                raise RuntimeError("SELECT response missing UDD Product ID")
            firmware_version = next(filter(lambda d: d[0] == 0x81, udd), None)
            if not firmware_version:
                raise RuntimeError("SELECT response missing UDD Firmware Version")
            udd = UserDeviceDescriptor(
                vendor_id=int.from_bytes(vendor_id[1], "big"),
                product_id=product_id[1],
                firmware_version=firmware_version[1],
            )

        return cls(
            application_type=application_type,
            expedited_phase_supported_protocol_versions=expedited_phase_supported_protocol_versions,
            max_command_apdu=max_command_apdu,
            max_response_apdu=max_response_apdu,
            user_device_descriptor=udd,
            fci_proprietary_bytes=fci_proprietary_bytes,
        )


class AuthenticationPolicy(enum.IntEnum):
    UserDeviceSetting = 0x01
    UserDeviceSettingSecureAction = 0x02
    ForceUserAuthentication = 0x03


@dataclasses.dataclass
class Auth0Request:
    fast_request: bool
    authentication_policy: AuthenticationPolicy
    expedited_phase_protocol_version: int
    reader_ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    transaction_identifier: bytes
    reader_group_identifier: bytes
    reader_sub_group_identifier: bytes

    @property
    def command_parameters(self) -> bytes:
        return bytes([1 if self.fast_request else 0])

    @property
    def authentication_policy_bytes(self) -> bytes:
        return bytes([self.authentication_policy.value])

    def encode(self) -> bytes:
        return ber_tlv.tlv.Tlv.build({
            0x41: self.command_parameters,
            0x42: self.authentication_policy_bytes,
            0x5C: self.expedited_phase_protocol_version.to_bytes(2, "big"),
            0x87: self.reader_ephemeral_public_key.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.X962,
                cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint
            ),
            0x4C: self.transaction_identifier[0:16],
            0x4D: self.reader_group_identifier[0:16] + self.reader_sub_group_identifier[0:16],
        })


@dataclasses.dataclass
class Auth0Response:
    user_device_ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    cryptogram: typing.Optional[bytes]
    vendor_extension: typing.Optional[bytes]

    @classmethod
    def decode(cls, data: bytes) -> "Auth0Response":
        data = ber_tlv.tlv.Tlv.parse(data, False)
        ue_pub_k = next(filter(lambda d: d[0] == 0x86, data), None)
        if not ue_pub_k:
            raise RuntimeError("SELECT response missing User Device Ephemeral Public Key")
        if len(ue_pub_k[1]) != 65:
            raise RuntimeError("Invalid User Device Ephemeral Public Key")

        ue_pub_k = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
            ue_pub_k[1]
        )

        cryptogram = next(filter(lambda d: d[0] == 0x9D, data), None)
        if cryptogram:
            if len(cryptogram[1]) != 64:
                raise RuntimeError("Invalid cryptogram")
            cryptogram = cryptogram[1]

        vendor_extension = next(filter(lambda d: d[0] == 0xB2, data), None)

        return cls(
            user_device_ephemeral_public_key=ue_pub_k,
            cryptogram=cryptogram,
            vendor_extension=ber_tlv.tlv.Tlv.build({0xB2: vendor_extension[1]}) if vendor_extension else None,
        )

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
class CryptogramPayload:
    signalling_bitmap: SignallingBitmap
    credential_signed_timestamp: typing.Optional[datetime.datetime]
    revocation_signed_timestamp: typing.Optional[datetime.datetime]

    @classmethod
    def decode(cls, data: bytes) -> "CryptogramPayload":
        data = ber_tlv.tlv.Tlv.parse(data, False)

        signalling_bitmap = next(filter(lambda d: d[0] == 0x5E, data), None)
        if not signalling_bitmap:
            raise RuntimeError("Signalling bitmap is required")
        if len(signalling_bitmap[1]) != 2:
            raise RuntimeError("Invalid signalling bitmap")
        signalling_bitmap = int.from_bytes(signalling_bitmap[1], "big")

        credential_signed_timestamp = next(filter(lambda d: d[0] == 0x91, data), None)
        if not credential_signed_timestamp:
            raise RuntimeError("Credential signed timestamp is required")
        if len(credential_signed_timestamp[1]) != 20:
            raise RuntimeError("Invalid credential signed timestamp")
        credential_signed_timestamp = credential_signed_timestamp[1]
        revocation_signed_timestamp = next(filter(lambda d: d[0] == 0x92, data), None)
        if not revocation_signed_timestamp:
            raise RuntimeError("Revocation signed timestamp is required")
        if len(revocation_signed_timestamp[1]) != 20:
            raise RuntimeError("Invalid revocation signed timestamp")
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


class AccessCredentialKeyType(enum.Enum):
    KeySlot = enum.auto()
    PublicKey = enum.auto()

@dataclasses.dataclass
class Auth1Request:
    key_type: AccessCredentialKeyType
    reader_signature: bytes

    def encode(self) -> bytes:
        return ber_tlv.tlv.Tlv.build({
            0x41: bytes([1 if self.key_type == AccessCredentialKeyType.PublicKey else 0]),
            0x9E: self.reader_signature,
        })

@dataclasses.dataclass
class Auth1Response:
    key_slot: bytes
    access_credential_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    user_device_signature: bytes
    signalling_bitmap: SignallingBitmap
    mailbox_data_subset: typing.Optional[bytes]
    credential_signed_timestamp: typing.Optional[datetime.datetime]
    revocation_signed_timestamp: typing.Optional[datetime.datetime]

    @classmethod
    def decode(cls, data: bytes) -> "Auth1Response":
        data = ber_tlv.tlv.Tlv.parse(data, False)
        key_slot = next(filter(lambda d: d[0] == 0x4E, data), None)
        access_credential_public_key = next(filter(lambda d: d[0] == 0x5A, data), None)
        if not key_slot and not access_credential_public_key:
            raise RuntimeError("One of key slot or access credential public key is required")

        if key_slot:
            if len(key_slot[1]) != 8:
                raise RuntimeError("Invalid key slot")
            key_slot = key_slot[1]
        if access_credential_public_key:
            if len(access_credential_public_key[1]) != 65:
                raise RuntimeError("Invalid access credential public key")
            access_credential_public_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
                access_credential_public_key[1]
            )

        user_device_signature = next(filter(lambda d: d[0] == 0x9E, data), None)
        if not user_device_signature:
            raise RuntimeError("User device signature is required")
        if len(user_device_signature[1]) != 64:
            raise RuntimeError("Invalid user device signature")
        user_device_signature = cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(
            int.from_bytes(user_device_signature[1][0:32], byteorder="big"),
            int.from_bytes(user_device_signature[1][32:64], byteorder="big"),
        )

        mailbox_data_subset = next(filter(lambda d: d[0] == 0x4B, data), None)
        if mailbox_data_subset:
            mailbox_data_subset = mailbox_data_subset[1]

        signalling_bitmap = next(filter(lambda d: d[0] == 0x5E, data), None)
        if not signalling_bitmap:
            raise RuntimeError("Signalling bitmap is required")
        if len(signalling_bitmap[1]) != 2:
            raise RuntimeError("Invalid signalling bitmap")
        signalling_bitmap = int.from_bytes(signalling_bitmap[1], "big")

        credential_signed_timestamp = next(filter(lambda d: d[0] == 0x91, data), None)
        revocation_signed_timestamp = next(filter(lambda d: d[0] == 0x92, data), None)

        if credential_signed_timestamp:
            if len(credential_signed_timestamp[1]) != 20:
                raise RuntimeError("Invalid credential signed timestamp")
            credential_signed_timestamp = credential_signed_timestamp[1].decode("ascii")
            credential_signed_timestamp = datetime.datetime.fromisoformat(credential_signed_timestamp)
        if revocation_signed_timestamp:
            if len(revocation_signed_timestamp[1]) != 20:
                raise RuntimeError("Invalid revocation signed timestamp")
            revocation_signed_timestamp = revocation_signed_timestamp[1].decode("ascii")
            revocation_signed_timestamp = datetime.datetime.fromisoformat(revocation_signed_timestamp)

        return cls(
            key_slot=key_slot,
            access_credential_public_key=access_credential_public_key,
            user_device_signature=user_device_signature,
            mailbox_data_subset=mailbox_data_subset,
            signalling_bitmap=SignallingBitmap.from_int(signalling_bitmap),
            credential_signed_timestamp=credential_signed_timestamp,
            revocation_signed_timestamp=revocation_signed_timestamp,
        )

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
class ExchangeRequest:
    reader_status: typing.Optional[ReaderStatus]

    def encode(self) -> bytes:
        out = []
        if self.reader_status:
            out.append((0x97, self.reader_status.value.to_bytes(2, "big")))
        return ber_tlv.tlv.Tlv.build(out)

@dataclasses.dataclass
class ExchangeResponse:
    b1: int
    b2: int

    @property
    def is_success(self):
        return self.b1 == 0 and self.b2 == 0

    @classmethod
    def decode(cls, data: bytes) -> "ExchangeResponse":
        if len(data) != 4:
            raise RuntimeError("Invalid exchange response")
        if data[0] != 0 or data[1] != 2:
            raise RuntimeError("Invalid exchange response")
        return cls(
            b1=data[2],
            b2=data[3],
        )

class SecureChannel:
    device_gcm: cryptography.hazmat.primitives.ciphers.aead.AESGCM
    reader_gcm: cryptography.hazmat.primitives.ciphers.aead.AESGCM
    device_counter: int
    reader_counter: int

    def __init__(self, sk_device: bytes, sk_reader: bytes):
        self.device_gcm = cryptography.hazmat.primitives.ciphers.aead.AESGCM(sk_device)
        self.reader_gcm = cryptography.hazmat.primitives.ciphers.aead.AESGCM(sk_reader)
        self.device_counter = 1
        self.reader_counter = 1

    def encrypt_command(self, data: bytes) -> bytes:
        nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00" + self.reader_counter.to_bytes(4, "big")
        self.reader_counter += 1
        return self.reader_gcm.encrypt(nonce, data, None)

    def decrypt_response(self, data: bytes) -> typing.Optional[bytes]:
        nonce = b"\x00\x00\x00\x00\x00\x00\x00\x01" + self.device_counter.to_bytes(4, "big")
        self.device_counter += 1
        try:
            return self.device_gcm.decrypt(nonce, data, None)
        except cryptography.exceptions.InvalidTag:
            return None


class ReaderTransaction:
    EXPEDITED_AID = bytes.fromhex("A000000909ACCE5501")
    STEP_UP_AID = bytes.fromhex("A000000909ACCE5502")

    def __init__(self, device: nfc.tag.tt4.Type4Tag, config: ReaderConfig):
        self.target = Terminal(device)
        self.config = config

    def _salt_base(
            self,
            mode: bytes,
            transaction_identifier: bytes,
            protocol_version: int,
            ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
            select_resp: SelectResponse,
            auth0_req: Auth0Request,
    ) -> bytearray:
        salt = bytearray()
        salt.extend(self.config.signing_key.public_key().public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.X962,
            cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
        )[1:])
        salt.extend(mode)
        salt.extend(self.config.group_identifier[0:16])
        salt.extend(self.config.sub_group_identifier[0:16])
        salt.append(0x5E)  # NFC
        salt.extend(ber_tlv.tlv.Tlv.build({0x5C: protocol_version.to_bytes(2, "big")}))
        salt.extend(ephemeral_public_key.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.X962,
            cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
        )[1:])
        salt.extend(transaction_identifier)
        salt.extend(auth0_req.command_parameters)
        salt.extend(auth0_req.authentication_policy_bytes)
        salt.extend(select_resp.fci_proprietary_bytes)
        return salt

    def build_salt_volatile(
            self,
            transaction_identifier: bytes,
            protocol_version: int,
            ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
            select_resp: SelectResponse,
            auth0_req: Auth0Request,
    ) -> bytes:
        return bytes(self._salt_base(
            mode=b"Volatile****",
            transaction_identifier=transaction_identifier,
            protocol_version=protocol_version,
            ephemeral_public_key=ephemeral_public_key,
            select_resp=select_resp,
            auth0_req=auth0_req,
        ))

    def build_salt_persistent(
            self,
            transaction_identifier: bytes,
            protocol_version: int,
            ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
            select_resp: SelectResponse,
            auth0_req: Auth0Request,
            access_credential_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
    ) -> bytes:
        salt_persistent = self._salt_base(
            mode=b"Persistent**",
            transaction_identifier=transaction_identifier,
            protocol_version=protocol_version,
            ephemeral_public_key=ephemeral_public_key,
            select_resp=select_resp,
            auth0_req=auth0_req,
        )
        salt_persistent.extend(access_credential_public_key.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.X962,
            cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
        )[1:])
        return bytes(salt_persistent)

    def build_salt_fast(
            self,
            transaction_identifier: bytes,
            protocol_version: int,
            ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
            select_resp: SelectResponse,
            auth0_req: Auth0Request,
            access_credential_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
    ) -> bytes:
        salt_fast = self._salt_base(
            mode=b"VolatileFast",
            transaction_identifier=transaction_identifier,
            protocol_version=protocol_version,
            ephemeral_public_key=ephemeral_public_key,
            select_resp=select_resp,
            auth0_req=auth0_req,
        )
        salt_fast.extend(access_credential_public_key.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.X962,
            cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
        )[1:])
        return bytes(salt_fast)

    @staticmethod
    def build_info(auth0_resp: Auth0Response) -> bytes:
        info = bytearray()
        info.extend(auth0_resp.user_device_ephemeral_public_key.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.X962,
            cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
        )[1:])
        if auth0_resp.vendor_extension:
            info.extend(auth0_resp.vendor_extension)
        return bytes(info)

    def select(self, target_aid: bytes) -> SelectResponse:
        resp = self.target.transmit(RequestAPDU(
            instruction_class=0x00,
            instruction=0xA4,
            p1=0x04, p2=0x00,
            data=target_aid,
            expected_response_length=256,
        ))
        if not resp.is_success():
            raise RuntimeError("SELECT failed")
        return SelectResponse.decode(resp.data, target_aid)

    def control_flow(self, s1: int, s2: int) -> None:
        resp = self.target.transmit(RequestAPDU(
            instruction_class=0x80,
            instruction=0x3C,
            p1=0x00, p2=0x00,
            data=ber_tlv.tlv.Tlv.build({
                0x41: bytes([s1]),
                0x42: bytes([s2]),
            }),
            expected_response_length=256,
        ))
        if not resp.is_success():
            raise RuntimeError("CONTROL FLOW failed")

    def auth0(self, req: Auth0Request) -> Auth0Response:
        resp = self.target.transmit(RequestAPDU(
            instruction_class=0x80,
            instruction=0x80,
            p1=0x00, p2=0x00,
            data=req.encode(),
            expected_response_length=256,
        ))
        if not resp.is_success():
            raise RuntimeError("AUTH0 failed")
        return Auth0Response.decode(resp.data)

    def auth1(self, req: Auth1Request, secure_channel: SecureChannel) -> Auth1Response:
        resp = self.target.transmit(RequestAPDU(
            instruction_class=0x80,
            instruction=0x81,
            p1=0x00, p2=0x00,
            data=req.encode(),
            expected_response_length=256,
        ))
        if not resp.is_success():
            raise RuntimeError("AUTH1 failed")
        resp = secure_channel.decrypt_response(resp.data)
        if not resp:
            raise RuntimeError("Secure channel failed")
        return Auth1Response.decode(resp)

    def exchange(self, req: ExchangeRequest, secure_channel: SecureChannel) -> ExchangeResponse:
        resp = self.target.transmit(RequestAPDU(
            instruction_class=0x80,
            instruction=0xC9,
            p1=0x00, p2=0x00,
            data=secure_channel.encrypt_command(req.encode()),
            expected_response_length=256,
        ))
        if not resp.is_success():
            raise RuntimeError("EXCHANGE failed")
        resp = secure_channel.decrypt_response(resp.data)
        if not resp:
            raise RuntimeError("Secure channel failed")
        return ExchangeResponse.decode(resp)

    def test_cryptogram(
            self,
            transaction_identifier: bytes,
            protocol_version: int,
            ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
            select_resp: SelectResponse,
            auth0_req: Auth0Request,
            auth0_resp: Auth0Response,
    ) -> typing.Optional[typing.Tuple[CryptogramPayload, bytes, bytes]]:
        for persistent_key in self.config.persistent_keys:
            hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
                algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                length=160,
                salt=self.build_salt_fast(
                    transaction_identifier=transaction_identifier,
                    protocol_version=protocol_version,
                    ephemeral_public_key=ephemeral_public_key,
                    select_resp=select_resp,
                    auth0_req=auth0_req,
                    access_credential_public_key=persistent_key.authentication_credential_public_key
                ),
                info=self.build_info(auth0_resp)
            )
            derived_keys_fast = hkdf.derive(persistent_key.key)
            cryptogram_sk = derived_keys_fast[0:32]
            expedited_sk_reader = derived_keys_fast[32:64]
            expedited_sk_device = derived_keys_fast[64:96]

            gcm = cryptography.hazmat.primitives.ciphers.aead.AESGCM(cryptogram_sk)
            iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            try:
                data = gcm.decrypt(iv, auth0_resp.cryptogram, None)
                return CryptogramPayload.decode(data), expedited_sk_reader, expedited_sk_device
            except cryptography.exceptions.InvalidTag:
                pass

    def run(self):
        protocol_version = 0x0100

        select_resp = self.select(self.EXPEDITED_AID)
        if select_resp.application_type != 0:
            self.control_flow(0x00, 0x27)
            raise RuntimeError("Application Type unsupported")
        if protocol_version not in select_resp.expedited_phase_supported_protocol_versions:
            self.control_flow(0x00, 0x27)
            raise RuntimeError("No supported expedited-phase protocol version")

        ephemeral_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
        )
        transaction_identifier = secrets.token_bytes(16)
        xkdf = cryptography.hazmat.primitives.kdf.x963kdf.X963KDF(
            algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
            length=32,
            sharedinfo=transaction_identifier
        )

        auth0_req = Auth0Request(
            fast_request=True,
            authentication_policy=AuthenticationPolicy.UserDeviceSetting,
            expedited_phase_protocol_version=protocol_version,
            reader_ephemeral_public_key=ephemeral_key.public_key(),
            transaction_identifier=transaction_identifier,
            reader_group_identifier=self.config.group_identifier,
            reader_sub_group_identifier=self.config.sub_group_identifier,
        )
        auth0_resp = self.auth0(auth0_req)

        if not auth0_resp.cryptogram:
            raise RuntimeError("Cryptogram not present")

        if fast := self.test_cryptogram(
            transaction_identifier=transaction_identifier,
            protocol_version=protocol_version,
            ephemeral_public_key=ephemeral_key.public_key(),
            select_resp=select_resp,
            auth0_req=auth0_req,
            auth0_resp=auth0_resp,
        ):
            cryptogram_response = fast[0]
            secure_channel = SecureChannel(
                sk_reader=fast[1],
                sk_device=fast[2]
            )

            print("Aliro fast complete")

        else:
            hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
                algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                length=160,
                salt=self.build_salt_volatile(
                    transaction_identifier=transaction_identifier,
                    protocol_version=protocol_version,
                    ephemeral_public_key=ephemeral_key.public_key(),
                    select_resp=select_resp,
                    auth0_req=auth0_req,
                ),
                info=self.build_info(auth0_resp)
            )

            shared_secret = ephemeral_key.exchange(
                cryptography.hazmat.primitives.asymmetric.ec.ECDH(),
                auth0_resp.user_device_ephemeral_public_key
            )
            kdh = xkdf.derive(shared_secret)
            derived_keys_volatile = hkdf.derive(kdh)

            secure_channel = SecureChannel(
                sk_reader=derived_keys_volatile[0:32],
                sk_device=derived_keys_volatile[32:64]
            )
            step_up_sk = derived_keys_volatile[64:96]

            auth1_authentication = Auth1Authentication(
                reader_group_identifier=self.config.group_identifier,
                reader_sub_group_identifier=self.config.sub_group_identifier,
                user_device_ephemeral_public_key=auth0_resp.user_device_ephemeral_public_key,
                reader_ephemeral_public_key=ephemeral_key.public_key(),
                transaction_identifier=transaction_identifier,
            )
            auth1_signature = auth1_authentication.sign(self.config.signing_key)
            auth1_resp = self.auth1(Auth1Request(
                key_type=AccessCredentialKeyType.PublicKey,
                reader_signature=auth1_signature,
            ), secure_channel)

            if not auth1_authentication.verify(auth1_resp.access_credential_public_key, auth1_resp.user_device_signature):
                raise RuntimeError("User device signature verification failed")

            persistent_hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
                algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                length=32,
                salt=self.build_salt_persistent(
                    transaction_identifier=transaction_identifier,
                    protocol_version=protocol_version,
                    ephemeral_public_key=ephemeral_key.public_key(),
                    select_resp=select_resp,
                    auth0_req=auth0_req,
                    access_credential_public_key=auth1_resp.access_credential_public_key,
                ),
                info=self.build_info(auth0_resp)
            )
            derived_key_persistent = persistent_hkdf.derive(kdh)
            self.config.persistent_keys.append(PersistentKey(
                key=derived_key_persistent,
                authentication_credential_public_key=auth1_resp.access_credential_public_key,
            ))

            print("Aliro complete")

        exc_resp = self.exchange(ExchangeRequest(
            reader_status=ReaderStatus.ReaderSecure
        ), secure_channel)
        if not exc_resp.is_success:
            print("Reader status notify failed")

@dataclasses.dataclass
class ECPv2:
    terminal_type: int
    terminal_subtype: int
    flag_1: bool
    flag_2: bool
    flag_3: bool
    flag_4: bool
    payload: bytes

    def encode(self) -> bytes:
        terminal_info = (int(self.flag_1) << 7) + (int(self.flag_2) << 6) + \
                        (int(self.flag_3) << 5) + (int(self.flag_4) << 4) + len(self.payload)
        return bytes([0x6A, 0x02, terminal_info, self.terminal_type, self.terminal_subtype]) + self.payload

    @classmethod
    def aliro(cls, identifier: bytes, express: bool = True):
        return cls(
            terminal_type=0x02, # ACCESS,
            terminal_subtype=0x06, # HomeKey,
            flag_1=True,
            flag_2=express,
            flag_3=False,
            flag_4=False,
            payload=b"\x20\x42\x20" + identifier[0:8],
        )

config = ReaderConfig(
    signing_key=cryptography.hazmat.primitives.asymmetric.ec.derive_private_key(
        int.from_bytes(base64.b64decode("E73cCu6HsWarIQoU+MdhgojLiQkSHzhEHXIe5DL0txk="), "big"),
        cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
    ),
    group_identifier=base64.b64decode("JQywTj4OqzpUNLyOfhCtBg=="),
    sub_group_identifier=base64.b64decode("YF1M9dv6xVbjzPKzy6bzhg=="),
    persistent_keys=[]
)

def run_aliro(tag: nfc.tag.tt4.Type4Tag):
    transaction = ReaderTransaction(tag, config)
    print("Running Aliro")
    transaction.run()


def main():
    with broadcast_frame_contactless_frontend.BroadcastFrameContactlessFrontend("usb") as clf:
        tries = 0
        ecp = ECPv2.aliro(config.group_identifier).encode()
        while True:
            target = clf.sense(
                nfc.clf.RemoteTarget("106A"),
                nfc.clf.RemoteTarget("106B"),
                broadcast=ecp,
            )
            if not target:
                tries = min(0, tries - 1)
                time.sleep(0.1)
                continue

            if tries > 0:
                time.sleep(0.5)
                continue

            try:
                clf.connect(rdwr={'on-connect': run_aliro})
            except (nfc.tag.tt4.Type4TagCommandError, RuntimeError) as e:
                print(e)
                tries = 3
                time.sleep(1)
                continue

            tries = 3
            time.sleep(5)


if __name__ == '__main__':
    main()
