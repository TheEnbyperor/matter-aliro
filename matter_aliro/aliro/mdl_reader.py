import typing
import hashlib
import datetime
import ber_tlv.tlv
import cbor2
import dataclasses
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.kdf.hkdf
import cryptography.hazmat.primitives.asymmetric.ec
from . import crypto, mdl_commands, mdl_data_elements, iso7816, util, command_handlers


@dataclasses.dataclass
class StepUpSuccess:
    issuer_public_key: util.PublicKey
    secure_channel: crypto.SecureChannel
    new_persistent_key: typing.Optional[bytes]
    validity_info: mdl_data_elements.ValidityInfo
    device_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    access_elements: typing.Dict[str, typing.Any]
    revocation_elements: typing.Dict[str, typing.Any]

async def _mdl_envelope(
        target: iso7816.Terminal,
        secure_channel: crypto.SecureChannel,
        req: typing.Optional[bytes] = None,
        status: typing.Optional[mdl_commands.MDLSessionStatus] = None
) -> typing.Tuple[typing.Optional[bytes], typing.Optional[mdl_commands.MDLSessionStatus]]:
    req = mdl_commands.SessionData(
        data=secure_channel.encrypt_command(req) if req else None,
        status=status,
    )
    resp = await target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x00,
        instruction=0xC3,
        p1=0x00, p2=0x00,
        data=ber_tlv.tlv.Tlv.build({
            0x53: req.encode(),
        }),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise util.ISO7816Exception("ENVELOPE failed", resp.sw1, resp.sw2)
    try:
        resp = ber_tlv.tlv.Tlv.parse(resp.data, True)
    except (ber_tlv.tlv.BadLength, ber_tlv.tlv.BadTag, ber_tlv.tlv.BadParameter, ber_tlv.tlv.UnexpectedEnd) as e:
        raise util.EncodingException("Invalid TLV") from e
    resp_data = next(filter(lambda d: d[0] == 0x53, resp), None)
    if not resp_data:
        raise util.EncodingException("Invalid ENVELOPE response")
    resp = mdl_commands.SessionData.decode(resp_data[1])
    if resp.status == mdl_commands.MDLSessionStatus.SessionEncryptionError:
        raise util.GeneralException("ENVELOPE encryption error")
    if resp.status == mdl_commands.MDLSessionStatus.CBORDecodingError:
        raise util.GeneralException("ENVELOPE CBOR error")
    if resp.data:
        resp_data = secure_channel.decrypt_response(resp.data)
    else:
        resp_data = None
    return resp_data, resp.status


async def _device_request(target: iso7816.Terminal, req: mdl_commands.DeviceRequest,
                    secure_channel: crypto.SecureChannel) -> mdl_commands.DeviceResponse:
    resp, status = await _mdl_envelope(target, secure_channel, req.encode())
    if status:
        raise util.GeneralException("mDL device request failed")
    return mdl_commands.DeviceResponse.decode(resp)


async def run_step_up(
        target: iso7816.Terminal,
        trusted_issuer_keys: typing.List[util.PublicKey],
        step_up_sk: bytes,
        revocation_available: bool,
        requested_access_elements: typing.List[str],
        kdh: bytes,
        salt_input: crypto.SaltInput,
        kdf_info: bytes,
) -> typing.Optional[StepUpSuccess]:
    step_up_reader_hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"SKReader"
    )
    step_up_device_hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"SKDevice"
    )
    step_up_secure_channel = crypto.SecureChannel(
        sk_reader=step_up_reader_hkdf.derive(step_up_sk),
        sk_device=step_up_device_hkdf.derive(step_up_sk),
    )

    document_types = [mdl_commands.DocumentRequest(
        document_type="aliro-a",
        namespaces={
            "aliro-a": {
                e: True for e in requested_access_elements
            }
        },
    )]

    if revocation_available:
        document_types.append(mdl_commands.DocumentRequest(
            document_type="aliro-r",
            namespaces={
                "aliro-r": {
                    e: True for e in requested_access_elements
                }
            }
        ))

    device_resp = await _device_request(target, mdl_commands.DeviceRequest(
        version="1.0",
        document_requests=document_types,
    ), step_up_secure_channel)

    if device_resp.version != "1.0":
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.GeneralException("mDL Version unsupported")

    access_document: typing.Optional[mdl_data_elements.Document] = next(filter(lambda d: d.document_type == "aliro-a", device_resp.documents), None)
    if not access_document:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.GeneralException("No access document presented")

    if access_document.issuer_auth.protected_headers.critical:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.GeneralException("Critical protected headers not supported")
    if access_document.issuer_auth.unprotected_headers.critical:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.GeneralException("Critical unprotected headers not supported")

    issuer = None
    for i in trusted_issuer_keys:
        if access_document.issuer_auth.unprotected_headers.key_id != i.aliro_key_identifier():
            continue

        if access_document.issuer_auth.verify(i.public_key()):
            issuer = i
            break

    if not issuer:
        await command_handlers.control_flow(target, 0x00, 0x00)
        return None

    mso = mdl_data_elements.MobileSecurityObject.decode(access_document.issuer_auth.payload)

    if mso.document_type != access_document.document_type:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.GeneralException("Document type mis-match")

    now = datetime.datetime.now(datetime.UTC)
    if not mso.validity_info.valid_from <= now <= mso.validity_info.valid_to:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.GeneralException("Expired validity info")

    if mso.digest_algorithm == "SHA-256":
        hash_alg = hashlib.sha256
    elif mso.digest_algorithm == "SHA-384":
        hash_alg = hashlib.sha384
    elif mso.digest_algorithm == "SHA-512":
        hash_alg = hashlib.sha512
    else:
        await command_handlers.control_flow(target, 0x00, 0x00)
        raise util.GeneralException("Invalid digest algorithm")

    access_elements = {
        "aliro-a": {},
        "aliro-r": {},
    }
    for ns, elements in access_document.namespaces.items():
        for element_bytes in elements:
            element_digest = hash_alg(cbor2.dumps(cbor2.CBORTag(24, element_bytes))).digest()
            element = mdl_data_elements.IssuerSignedItem.decode(element_bytes)

            signed_digest = mso.value_digests.get(ns, {}).get(element.digest_id)
            if signed_digest != element_digest:
                await command_handlers.control_flow(target, 0x00, 0x00)
                raise util.CryptoException("Invalid element digest")

            if ns in access_elements:
                access_elements[ns][element.element_identifier] = element.element_value

    persistent_hkdf = cryptography.hazmat.primitives.kdf.hkdf.HKDF(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=32,
        salt=crypto.kdf_salt_persistent(salt_input, mso.device_key.device_key),
        info=kdf_info,
    )
    derived_key_persistent = persistent_hkdf.derive(kdh)

    return StepUpSuccess(
        issuer_public_key=issuer,
        secure_channel=step_up_secure_channel,
        new_persistent_key=derived_key_persistent,
        validity_info=mso.validity_info,
        device_public_key=mso.device_key.device_key,
        access_elements=access_elements["aliro-a"],
        revocation_elements=access_elements["aliro-r"],
    )