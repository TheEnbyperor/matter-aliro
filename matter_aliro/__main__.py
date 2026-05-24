import base64
import logging
import pathlib
import qrcode
import asyncio
import aiocoap.resource
import cryptography.x509
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
import zeroconf
import socket
import typing
from .matter.encoding import protocol_messages
from .aliro import util as aliro_util
from .aliro import reader, data_elements
from . import device, matter, coap
from .coap import views

DEVICES: typing.List[device.DoorLockDevice] = []

class PublicKey(aliro_util.PublicKey):
    def __init__(
            self,
            key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
            aliro_key_slot: bytes,
            aliro_key_identifier: bytes,
            user_id: int,
            credential_type: protocol_messages.CredentialTypeEnum,
            credential_id: int
    ):
        self.key = key
        self.key_slot = aliro_key_slot
        self.key_identifier = aliro_key_identifier
        self.user_id = user_id
        self.credential_type = credential_type
        self.credential_id = credential_id

    def public_key(self) -> cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey:
        return self.key

    def aliro_key_slot(self) -> bytes:
        return self.key_slot

    def aliro_key_identifier(self) -> bytes:
        return self.key_identifier

    def __repr__(self):
        return f"PublicKey(user_id={self.user_id}, credential_type={self.credential_type}, credential_id={self.credential_id})"

def config_handler(did: bytes):
    for d in DEVICES:
        if did in d.readers:
            if d.aliro_reader_config:
                return {
                    "ecp": d.aliro_reader_config.ecp_broadcast
                }
            else:
                return {}
    logging.warning(f"Unknown device: {base64.b64encode(did).decode('ascii')}")
    return {}

async def nfc_handler(did: bytes, target: views.Target):
    for d in DEVICES:
        if did in d.readers:
            break
    else:
        logging.warning(f"Unknown device: {base64.b64encode(did).decode('ascii')}")
        return

    if not d.aliro_reader_config:
        logging.warning(f"Device {d.unique_id} not configured for Aliro")
        return

    logging.info(f"New target {target} on device {d.unique_id}, running Aliro")

    known_access_keys = []
    known_issuer_keys = []

    for cid, credential in d.credentials[protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey].items():
        known_issuer_keys.append(PublicKey(
            key=credential.data,
            aliro_key_slot=b"",
            aliro_key_identifier=credential.aliro_discriminator,
            user_id=credential.user_index,
            credential_type=protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey,
            credential_id=cid
        ))
    for cid, credential in d.credentials[protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey].items():
        known_access_keys.append(PublicKey(
            key=credential.data,
            aliro_key_slot=credential.aliro_discriminator,
            aliro_key_identifier=b"",
            user_id=credential.user_index,
            credential_type=protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey,
            credential_id=cid
        ))
    for cid, credential in d.credentials[protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey].items():
        known_access_keys.append(PublicKey(
            key=credential.data,
            aliro_key_slot=credential.aliro_discriminator,
            aliro_key_identifier=b"",
            user_id=credential.user_index,
            credential_type=protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey,
            credential_id=cid
        ))

    if resp := await reader.run_aliro(
            target=target,
            reader_signing_key=d.aliro_reader_config.signing_key,
            reader_group_identifier=d.aliro_reader_config.group_identifier,
            reader_sub_group_identifier=d.aliro_reader_config.sub_group_identifier,
            authentication_policy=data_elements.AuthenticationPolicy.UserDeviceSetting if d.locked else \
                data_elements.AuthenticationPolicy.UserDeviceSettingSecureAction,
            requested_access_elements=["matter1"],
            known_access_keys=known_access_keys,
            trusted_issuer_keys=known_issuer_keys,
            persistent_keys=[]
    ):
        if d.locked:
            print("UNLOCK DOOR")
            d.locked = False
            d.save_state()
            d.lock_cluster.increment_data_version()
            d.lock_cluster.attributes_changed([d.lock_cluster.lock_state])
            await reader.notify_status(target, data_elements.ReaderStatus.ReaderUnsecure, resp.secure_channel)
        else:
            print("LOCK DOOR")
            d.locked = True
            d.save_state()
            d.lock_cluster.increment_data_version()
            d.lock_cluster.attributes_changed([d.lock_cluster.lock_state])
            await reader.notify_status(target, data_elements.ReaderStatus.ReaderSecure, resp.secure_channel)

async def main():
    state_dir = pathlib.Path("/data/state")
    if not state_dir.is_dir():
        state_dir.mkdir()

    root = aiocoap.resource.Site()
    root.add_resource(["whoami"], views.WhoAmI())
    root.add_resource(["config"], views.DeviceConfig(config_handler))
    root.add_resource(["interact"], views.Interact(nfc_handler))
    root.add_resource([".well-known", "core"], aiocoap.resource.WKCResource(root.get_resources_as_linkheader))

    address = "::"
    matter_port = 5451
    coaps_port = 5684
    coap.CoAPServer(root, coap.CoAPDTLS, (address, coaps_port))
    logging.info(f"CoAP listening on {address} port {coaps_port}")

    matter_device = matter.Device(matter.DeviceMeta(
        vendor_id=0xFFF1,
        vendor_name="Q Misell",
        product_id=0x8000,
        product_name="Aliro Lock",
        primary_device_type=0x000A,
        device_name="Aliro Lock",
    ), state_dir, matter_port=matter_port, coaps_port=coaps_port)

    with open("pai-cert.pem", "rb") as f:
        matter_device.state.set_pai_cert(cryptography.x509.load_pem_x509_certificate(f.read()))
    with open("dac-cert.pem", "rb") as f:
        matter_device.state.set_dac_cert(cryptography.x509.load_pem_x509_certificate(f.read()))
    with open("dac-priv.pem", "rb") as f:
        matter_device.state.set_dac_key(cryptography.hazmat.primitives.serialization.load_pem_private_key(f.read(), None))

    lock = device.DoorLockDevice("door-lock", matter_device.state)
    matter_device.add_endpoint(lock)
    DEVICES.append(lock)

    if not matter_device.state.is_commissioned:
        print("Matter commissioning required")
        qr = qrcode.QRCode()
        qr.add_data(matter_device.state.qr_discovery_string)
        qr.print_ascii()
        print("Manual pairing code:", matter_device.state.manual_discovery_string)

    asyncio.create_task(matter_device.start())
    logging.info("Matter running")

    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())