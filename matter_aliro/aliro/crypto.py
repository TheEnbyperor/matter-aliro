import dataclasses
import typing
import cryptography.exceptions
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.ciphers.aead
import cryptography.hazmat.primitives.asymmetric.ec
import ber_tlv.tlv
from . import commands

@dataclasses.dataclass
class SaltInput:
    reader_signing_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    reader_group_identifier: bytes
    reader_sub_group_identifier: bytes
    transaction_identifier: bytes
    protocol_version: int
    reader_ephemeral_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    select_resp: commands.SelectResponse
    auth0_req: commands.Auth0Request

def _kdf_salt_base(data: SaltInput, mode: bytes) -> bytearray:
    salt = bytearray()
    salt.extend(data.reader_signing_public_key.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.X962,
        cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
    )[1:])
    salt.extend(mode)
    salt.extend(data.reader_group_identifier[0:16])
    salt.extend(data.reader_sub_group_identifier[0:16])
    salt.append(0x5E)  # NFC
    salt.extend(ber_tlv.tlv.Tlv.build({0x5C: data.protocol_version.to_bytes(2, "big")}))
    salt.extend(data.reader_ephemeral_public_key.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.X962,
        cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
    )[1:])
    salt.extend(data.transaction_identifier)
    salt.extend(data.auth0_req.command_parameters)
    salt.extend(data.auth0_req.authentication_policy_bytes)
    salt.extend(data.select_resp.fci_proprietary_bytes)
    return salt

def kdf_salt_volatile(data: SaltInput) -> bytes:
    return bytes(_kdf_salt_base(data=data, mode=b"Volatile****"))

def kdf_salt_persistent(
        data: SaltInput,
        access_credential_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
) -> bytes:
    salt_persistent = _kdf_salt_base(data=data, mode=b"Persistent**")
    salt_persistent.extend(access_credential_public_key.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.X962,
        cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
    )[1:])
    return bytes(salt_persistent)

def kdf_salt_fast(
        data: SaltInput,
        access_credential_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
) -> bytes:
    salt_fast = _kdf_salt_base(data=data, mode=b"VolatileFast")
    salt_fast.extend(access_credential_public_key.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.X962,
        cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
    )[1:])
    return bytes(salt_fast)

def kdf_info(auth0_resp: commands.Auth0Response) -> bytes:
    info = bytearray()
    info.extend(auth0_resp.user_device_ephemeral_public_key.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.X962,
        cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint
    )[1:])
    if auth0_resp.vendor_extension:
        info.extend(auth0_resp.vendor_extension)
    return bytes(info)

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