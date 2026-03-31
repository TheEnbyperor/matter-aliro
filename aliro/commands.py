import dataclasses
import typing
import datetime
import ber_tlv.tlv
import cryptography.exceptions
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.hashes
from . import util, data_elements

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
        try:
            data = ber_tlv.tlv.Tlv.parse(data, False)
        except (ber_tlv.tlv.BadLength, ber_tlv.tlv.BadTag, ber_tlv.tlv.BadParameter, ber_tlv.tlv.UnexpectedEnd) as e:
            raise util.EncodingException("Invalid TLV") from e
        fci = next(filter(lambda d: d[0] == 0x6F, data), None)
        udd = next(filter(lambda d: d[0] == 0xB7, data), None)

        if not fci:
            raise util.EncodingException("SELECT response missing FCI")

        try:
            fci = ber_tlv.tlv.Tlv.parse(fci[1], False)
            udd = ber_tlv.tlv.Tlv.parse(udd[1], True) if udd else None
        except (ber_tlv.tlv.BadLength, ber_tlv.tlv.BadTag, ber_tlv.tlv.BadParameter, ber_tlv.tlv.UnexpectedEnd) as e:
            raise util.EncodingException("Invalid TLV") from e

        aid = next(filter(lambda d: d[0] == 0x84, fci), None)
        if not aid:
            raise util.EncodingException("SELECT response missing AID")
        if aid[1] != target_aid:
            raise util.GeneralException("SELECT response AID mismatch")

        fci_proprietary = next(filter(lambda d: d[0] == 0xA5, fci), None)
        if not fci_proprietary:
            raise util.EncodingException("SELECT response missing FCI proprietary data")
        fci_proprietary_bytes = ber_tlv.tlv.Tlv.build({0xA5: fci_proprietary[1]})
        try:
            fci_proprietary = ber_tlv.tlv.Tlv.parse(fci_proprietary[1], True)
        except (ber_tlv.tlv.BadLength, ber_tlv.tlv.BadTag, ber_tlv.tlv.BadParameter, ber_tlv.tlv.UnexpectedEnd) as e:
            raise util.EncodingException("Invalid TLV") from e

        application_type = next(filter(lambda d: d[0] == 0x80, fci_proprietary), None)
        if not application_type:
            raise util.EncodingException("SELECT response missing application type")
        application_type = application_type[1]
        if len(application_type) != 2:
            raise util.EncodingException("Invalid Aliro application type")
        application_type = int.from_bytes(application_type, "big")

        expedited_phase_supported_protocol_versions = next(filter(lambda d: d[0] == 0x5C, fci_proprietary), None)
        if expedited_phase_supported_protocol_versions:
            if len(expedited_phase_supported_protocol_versions[1]) % 2 != 0:
                raise util.EncodingException("Invalid Expedited Phase Supported Protocol Version")
            expedited_phase_supported_protocol_versions = [
                int.from_bytes(expedited_phase_supported_protocol_versions[1][i:i + 2], "big")
                for i in range(0, len(expedited_phase_supported_protocol_versions[1]), 2)
            ]
        else:
            expedited_phase_supported_protocol_versions = []

        extended_length_information = next(filter(lambda d: d[0] == 0x7F66, fci_proprietary), None)
        if extended_length_information:
            if len(extended_length_information[1]) != 2:
                raise util.EncodingException("Invalid Extended Length Information")
            max_command_apdu = extended_length_information[1][0]
            max_response_apdu = extended_length_information[1][1]
            if max_command_apdu[0] != 0x02:
                raise util.EncodingException("Invalid Extended Length Information")
            if max_response_apdu[0] != 0x02:
                raise util.EncodingException("Invalid Extended Length Information")
            max_command_apdu = int.from_bytes(max_command_apdu[1], "big")
            max_response_apdu = int.from_bytes(max_response_apdu[1], "big")
        else:
            max_command_apdu = None
            max_response_apdu = None

        if udd:
            vendor_id = next(filter(lambda d: d[0] == 0x04, udd), None)
            if not vendor_id:
                raise util.EncodingException("SELECT response missing UDD Vendor ID")
            vendor_id = int.from_bytes(vendor_id[1], "big")
            product_id = next(filter(lambda d: d[0] == 0x80, udd), None)
            if not product_id:
                raise util.EncodingException("SELECT response missing UDD Product ID")
            firmware_version = next(filter(lambda d: d[0] == 0x81, udd), None)
            if not firmware_version:
                raise util.EncodingException("SELECT response missing UDD Firmware Version")
            udd = UserDeviceDescriptor(
                vendor_id=vendor_id,
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

@dataclasses.dataclass
class Auth0Request:
    fast_request: bool
    authentication_policy: data_elements.AuthenticationPolicy
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
        try:
            data = ber_tlv.tlv.Tlv.parse(data, False)
        except (ber_tlv.tlv.BadLength, ber_tlv.tlv.BadTag, ber_tlv.tlv.BadParameter, ber_tlv.tlv.UnexpectedEnd) as e:
            raise util.EncodingException("Invalid TLV") from e
        ue_pub_k = next(filter(lambda d: d[0] == 0x86, data), None)
        if not ue_pub_k:
            raise util.EncodingException("SELECT response missing User Device Ephemeral Public Key")
        if len(ue_pub_k[1]) != 65:
            raise util.EncodingException("Invalid User Device Ephemeral Public Key")

        ue_pub_k = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
            ue_pub_k[1]
        )

        cryptogram = next(filter(lambda d: d[0] == 0x9D, data), None)
        if cryptogram:
            if len(cryptogram[1]) != 64:
                raise util.EncodingException("Invalid cryptogram length")
            cryptogram = cryptogram[1]

        vendor_extension = next(filter(lambda d: d[0] == 0xB2, data), None)

        return cls(
            user_device_ephemeral_public_key=ue_pub_k,
            cryptogram=cryptogram,
            vendor_extension=ber_tlv.tlv.Tlv.build({0xB2: vendor_extension[1]}) if vendor_extension else None,
        )

@dataclasses.dataclass
class Auth1Request:
    key_type: data_elements.AccessCredentialKeyType
    reader_signature: bytes

    def encode(self) -> bytes:
        return ber_tlv.tlv.Tlv.build({
            0x41: bytes([1 if self.key_type == data_elements.AccessCredentialKeyType.PublicKey else 0]),
            0x9E: self.reader_signature,
        })

@dataclasses.dataclass
class Auth1Response:
    key_slot: bytes
    access_credential_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    user_device_signature: bytes
    signalling_bitmap: data_elements.SignallingBitmap
    mailbox_data_subset: typing.Optional[bytes]
    credential_signed_timestamp: typing.Optional[datetime.datetime]
    revocation_signed_timestamp: typing.Optional[datetime.datetime]

    @classmethod
    def decode(cls, data: bytes) -> "Auth1Response":
        try:
            data = ber_tlv.tlv.Tlv.parse(data, False)
        except (ber_tlv.tlv.BadLength, ber_tlv.tlv.BadTag, ber_tlv.tlv.BadParameter, ber_tlv.tlv.UnexpectedEnd) as e:
            raise util.EncodingException("Invalid TLV") from e
        key_slot = next(filter(lambda d: d[0] == 0x4E, data), None)
        access_credential_public_key = next(filter(lambda d: d[0] == 0x5A, data), None)
        if not key_slot and not access_credential_public_key:
            raise util.EncodingException("One of key slot or access credential public key is required")

        if key_slot:
            if len(key_slot[1]) != 8:
                raise util.EncodingException("Invalid key slot length")
            key_slot = key_slot[1]
        if access_credential_public_key:
            if len(access_credential_public_key[1]) != 65:
                raise util.EncodingException("Invalid access credential public key length")
            access_credential_public_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
                access_credential_public_key[1]
            )

        user_device_signature = next(filter(lambda d: d[0] == 0x9E, data), None)
        if not user_device_signature:
            raise util.EncodingException("User device signature is required")
        if len(user_device_signature[1]) != 64:
            raise util.EncodingException("Invalid user device signature length")
        user_device_signature = cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(
            int.from_bytes(user_device_signature[1][0:32], byteorder="big"),
            int.from_bytes(user_device_signature[1][32:64], byteorder="big"),
        )

        mailbox_data_subset = next(filter(lambda d: d[0] == 0x4B, data), None)
        if mailbox_data_subset:
            mailbox_data_subset = mailbox_data_subset[1]

        signalling_bitmap = next(filter(lambda d: d[0] == 0x5E, data), None)
        if not signalling_bitmap:
            raise util.EncodingException("Signalling bitmap is required")
        if len(signalling_bitmap[1]) != 2:
            raise util.EncodingException("Invalid signalling bitmap length")
        signalling_bitmap = int.from_bytes(signalling_bitmap[1], "big")

        credential_signed_timestamp = next(filter(lambda d: d[0] == 0x91, data), None)
        revocation_signed_timestamp = next(filter(lambda d: d[0] == 0x92, data), None)

        if credential_signed_timestamp:
            if len(credential_signed_timestamp[1]) != 20:
                raise util.EncodingException("Invalid credential signed timestamp length")
            credential_signed_timestamp = credential_signed_timestamp[1].decode("ascii")
            credential_signed_timestamp = datetime.datetime.fromisoformat(credential_signed_timestamp)
        if revocation_signed_timestamp:
            if len(revocation_signed_timestamp[1]) != 20:
                raise util.EncodingException("Invalid revocation signed timestamp length")
            revocation_signed_timestamp = revocation_signed_timestamp[1].decode("ascii")
            revocation_signed_timestamp = datetime.datetime.fromisoformat(revocation_signed_timestamp)

        return cls(
            key_slot=key_slot,
            access_credential_public_key=access_credential_public_key,
            user_device_signature=user_device_signature,
            mailbox_data_subset=mailbox_data_subset,
            signalling_bitmap=data_elements.SignallingBitmap.from_int(signalling_bitmap),
            credential_signed_timestamp=credential_signed_timestamp,
            revocation_signed_timestamp=revocation_signed_timestamp,
        )

@dataclasses.dataclass
class ExchangeRequest:
    reader_status: typing.Optional[data_elements.ReaderStatus]

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
            raise util.EncodingException("Invalid exchange response")
        if data[0] != 0 or data[1] != 2:
            raise util.EncodingException("Invalid exchange response")
        return cls(
            b1=data[2],
            b2=data[3],
        )