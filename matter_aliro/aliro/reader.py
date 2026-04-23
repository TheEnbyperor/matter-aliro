import secrets
import dataclasses
import typing
import cryptography.exceptions
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.ciphers.aead
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.kdf.hkdf
import cryptography.hazmat.primitives.kdf.x963kdf
from . import iso7816, command_handlers, data_elements, commands, crypto, util, mdl_reader

EXPEDITED_AID = bytes.fromhex("A000000909ACCE5501")
STEP_UP_AID = bytes.fromhex("A000000909ACCE5502")

@dataclasses.dataclass
class PersistentKey:
    public_key: util.PublicKey
    persistent_key: bytes

@dataclasses.dataclass
class ExpeditedSuccess:
    device_public_key: util.PublicKey
    secure_channel: crypto.SecureChannel
    new_persistent_key: typing.Optional[bytes]

async def notify_status(target: iso7816.Terminal, status: data_elements.ReaderStatus, secure_channel: crypto.SecureChannel):
    exc_resp = await command_handlers.exchange(target, commands.ExchangeRequest(
        reader_status=status,
    ), secure_channel)
    if not exc_resp.is_success:
        util.GeneralException("Reader status notify failed")

def _test_cryptogram(
        salt_input: crypto.SaltInput,
        kdf_info: bytes,
        cryptogram: bytes,
        persistent_key: PersistentKey,
) -> typing.Optional[typing.Tuple[data_elements.CryptogramPayload, crypto.SecureChannel]]:
    public_key = persistent_key.public_key.public_key()
    hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=160,
        salt=crypto.kdf_salt_fast(salt_input, public_key),
        info=kdf_info,
    )
    derived_keys_fast = hkdf.derive(persistent_key.persistent_key)
    cryptogram_sk = derived_keys_fast[0:32]
    expedited_sk_reader = derived_keys_fast[32:64]
    expedited_sk_device = derived_keys_fast[64:96]

    gcm = cryptography.hazmat.primitives.ciphers.aead.AESGCM(cryptogram_sk)
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    try:
        data = gcm.decrypt(iv, cryptogram, None)
        return data_elements.CryptogramPayload.decode(data), crypto.SecureChannel(
            sk_reader=expedited_sk_reader,
            sk_device=expedited_sk_device,
        )
    except cryptography.exceptions.InvalidTag:
        pass
    return None

async def run_aliro(
        target: iso7816.Terminal,
        reader_signing_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey,
        reader_group_identifier: bytes,
        reader_sub_group_identifier: bytes,
        authentication_policy: data_elements.AuthenticationPolicy,
        requested_access_elements: typing.List[str],
        known_access_keys: typing.List[util.PublicKey],
        trusted_issuer_keys: typing.List[util.PublicKey],
        persistent_keys: typing.List[PersistentKey] = None,
) -> typing.Optional[typing.Union[ExpeditedSuccess, mdl_reader.StepUpSuccess]]:
    if persistent_keys is None:
        persistent_keys = []

    protocol_version = 0x0100

    select_resp = await command_handlers.select(target, EXPEDITED_AID)
    if select_resp.application_type != 0:
        await command_handlers.control_flow(target, 0x00, 0x27)
        raise util.GeneralException("Application Type unsupported")
    if protocol_version not in select_resp.expedited_phase_supported_protocol_versions:
        await command_handlers.control_flow(target, 0x00, 0x27)
        raise util.GeneralException("No supported expedited-phase protocol version")

    reader_ephemeral_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
    )
    transaction_identifier = secrets.token_bytes(16)
    x_kdf = cryptography.hazmat.primitives.kdf.x963kdf.X963KDF(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=32,
        sharedinfo=transaction_identifier
    )

    auth0_req = commands.Auth0Request(
        fast_request=True,
        authentication_policy=authentication_policy,
        expedited_phase_protocol_version=protocol_version,
        reader_ephemeral_public_key=reader_ephemeral_key.public_key(),
        transaction_identifier=transaction_identifier,
        reader_group_identifier=reader_group_identifier,
        reader_sub_group_identifier=reader_sub_group_identifier,
    )
    try:
        auth0_resp = await command_handlers.auth0(target, auth0_req)
    except util.GeneralException as e:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise e

    if not auth0_resp.cryptogram:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.EncodingException("Cryptogram not present")

    salt_input = crypto.SaltInput(
        reader_signing_public_key=reader_signing_key.public_key(),
        reader_ephemeral_public_key=reader_ephemeral_key.public_key(),
        reader_group_identifier=reader_group_identifier,
        reader_sub_group_identifier=reader_sub_group_identifier,
        transaction_identifier=transaction_identifier,
        protocol_version=protocol_version,
        select_resp=select_resp,
        auth0_req=auth0_req,
    )
    kdf_info = crypto.kdf_info(auth0_resp)

    for pk in persistent_keys:
        if fast := _test_cryptogram(salt_input, kdf_info, auth0_resp.cryptogram, pk):
            return ExpeditedSuccess(
                device_public_key=pk.public_key,
                secure_channel=fast[1],
                new_persistent_key=None,
            )

    auth1_authentication = data_elements.Auth1Authentication(
        reader_group_identifier=reader_group_identifier,
        reader_sub_group_identifier=reader_sub_group_identifier,
        user_device_ephemeral_public_key=auth0_resp.user_device_ephemeral_public_key,
        reader_ephemeral_public_key=reader_ephemeral_key.public_key(),
        transaction_identifier=transaction_identifier,
    )
    auth1_signature = auth1_authentication.sign(reader_signing_key)

    hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=160,
        salt=crypto.kdf_salt_volatile(salt_input),
        info=kdf_info,
    )

    shared_secret = reader_ephemeral_key.exchange(
        cryptography.hazmat.primitives.asymmetric.ec.ECDH(),
        auth0_resp.user_device_ephemeral_public_key
    )
    kdh = x_kdf.derive(shared_secret)
    derived_keys_volatile = hkdf.derive(kdh)
    secure_channel = crypto.SecureChannel(
        sk_reader=derived_keys_volatile[0:32],
        sk_device=derived_keys_volatile[32:64]
    )
    step_up_sk = derived_keys_volatile[64:96]

    try:
        auth1_resp = await command_handlers.auth1(target, commands.Auth1Request(
            key_type=data_elements.AccessCredentialKeyType.KeySlot,
            reader_signature=auth1_signature,
        ), secure_channel)
    except RuntimeError as e:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise e

    for k in known_access_keys:
        if k.aliro_key_slot() != auth1_resp.key_slot:
            continue

        pk = k.public_key()
        if auth1_authentication.verify(pk, auth1_resp.user_device_signature):
            persistent_hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
                algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                length=32,
                salt=crypto.kdf_salt_persistent(salt_input, pk),
                info=kdf_info,
            )
            derived_key_persistent = persistent_hkdf.derive(kdh)
            return ExpeditedSuccess(
                device_public_key=k,
                secure_channel=secure_channel,
                new_persistent_key=derived_key_persistent
            )

    if auth1_resp.signalling_bitmap.access_document_retrievable:
        if auth1_resp.signalling_bitmap.step_up_select_required:
            step_up_select_resp = await command_handlers.select(target, STEP_UP_AID)
            if step_up_select_resp.application_type != 0:
                await command_handlers.control_flow(target, 0x00, 0x27)
                raise util.GeneralException("Application Type unsupported")

        return await mdl_reader.run_step_up(
            target=target,
            trusted_issuer_keys=trusted_issuer_keys,
            step_up_sk=step_up_sk,
            revocation_available=auth1_resp.signalling_bitmap.revocation_document_retrievable,
            requested_access_elements=requested_access_elements,
            kdh=kdh,
            salt_input=salt_input,
            kdf_info=kdf_info,
        )
    else:
        return None
