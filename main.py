import logging
import pathlib
import os.path
import threading
import time
import qrcode
import dataclasses
import cluster
import typing
import base64
import matter.interaction_model
import aliro.util
import aliro.reader
import aliro.iso7816
import aliro.data_elements
import cryptography.x509
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
import nfc
import nfc.tag
import nfc.tag.tt4
import broadcast_frame_contactless_frontend
from matter.encoding import protocol_messages


@dataclasses.dataclass
class LockUser:
    name: str
    unique_id: int
    user_status: protocol_messages.UserStatusEnum
    user_type: protocol_messages.UserTypeEnum
    credential_rule: protocol_messages.CredentialRuleEnum
    creator_fabric_index: int
    last_modified_fabric_index: int


@dataclasses.dataclass
class LockCredential:
    user_index: int
    data: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    creator_fabric_index: int
    last_modified_fabric_index: int
    aliro_discriminator: bytes
    persistent_key: typing.Optional[bytes]


@dataclasses.dataclass
class AliroReaderConfig:
    signing_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    group_identifier: bytes
    sub_group_identifier: bytes
    ecp_broadcast: bytes


class DoorLockDevice(matter.interaction_model.Endpoint):
    DEVICE_TYPES = {matter.interaction_model.DeviceType(id=0x000A, revision=3)}

    def __init__(self, unique_id: str, state: matter.device.DeviceState):
        super().__init__(unique_id)

        self._state = state
        self.locked = False
        self.users: typing.Dict[int, LockUser] = {}
        self.credentials: typing.Dict[protocol_messages.CredentialTypeEnum, typing.Dict[int, LockCredential]] = {}
        self.aliro_reader_config: typing.Optional[AliroReaderConfig] = None
        self.load_state()

        self.lock_cluster = cluster.DoorLockCluster(self)
        self.add_server(self.lock_cluster)

    def load_state(self):
        if state := self._state.load_custom_state("door_lock"):
            self.locked = bool(state["locked"])
            for user in state["users"]:
                self.users[int(user["id"])] = LockUser(
                    name=str(user["user"]["name"]),
                    unique_id=int(user["user"]["unique_id"]),
                    user_status=protocol_messages.UserStatusEnum(int(user["user"]["status"])),
                    user_type=protocol_messages.UserTypeEnum(int(user["user"]["type"])),
                    credential_rule=protocol_messages.CredentialRuleEnum(int(user["user"]["credential_rule"])),
                    creator_fabric_index=int(user["user"]["creator_fabric_index"]),
                    last_modified_fabric_index=int(user["user"]["last_modified_fabric_index"]),
                )
            for credential_type in state["credentials"]:
                ct = {}
                for credential in credential_type["credentials"]:
                    ct[credential["id"]] = LockCredential(
                        user_index=int(credential["credential"]["user_index"]),
                        data=cryptography.hazmat.primitives.serialization.load_der_public_key(
                            base64.b64decode(credential["credential"]["data"])),
                        creator_fabric_index=int(credential["credential"]["creator_fabric_index"]),
                        last_modified_fabric_index=int(credential["credential"]["last_modified_fabric_index"]),
                        aliro_discriminator=base64.b64decode(credential["credential"]["aliro_discriminator"]),
                        persistent_key=base64.b64decode(credential["credential"]["persistent_key"]) if credential["credential"]["persistent_key"] else None,
                    )
                self.credentials[protocol_messages.CredentialTypeEnum(int(credential_type["type"]))] = ct
            if state["aliro_reader_config"]:
                self.aliro_reader_config = AliroReaderConfig(
                    signing_key=cryptography.hazmat.primitives.serialization.load_der_private_key(
                        base64.b64decode(state["aliro_reader_config"]["signing_key"]), None),
                    group_identifier=base64.b64decode(state["aliro_reader_config"]["group_identifier"]),
                    sub_group_identifier=base64.b64decode(state["aliro_reader_config"]["sub_group_identifier"]),
                    ecp_broadcast=base64.b64decode(state["aliro_reader_config"]["ecp_broadcast"]),
                )
            else:
                self.aliro_reader_config = None
        else:
            self.locked = True
            self.users = {}
            self.credentials = {
                protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey: {},
                protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey: {},
                protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey: {},
            }
            self.aliro_reader_config = None

    def save_state(self):
        self._state.save_custom_state("door_lock", {
            "locked": self.locked,
            "users": [{
                "id": uid,
                "user": {
                    "name": str(user.name),
                    "unique_id": int(user.unique_id),
                    "status": user.user_status.value,
                    "type": user.user_type.value,
                    "credential_rule": user.credential_rule.value,
                    "creator_fabric_index": user.creator_fabric_index,
                    "last_modified_fabric_index": user.last_modified_fabric_index,
                }
            } for uid, user in self.users.items()],
            "credentials": [{
                "type": ct.value,
                "credentials": [{
                    "id": cid,
                    "credential": {
                        "user_index": cred.user_index,
                        "data": base64.b64encode(cred.data.public_bytes(
                            cryptography.hazmat.primitives.serialization.Encoding.DER,
                            cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
                        )).decode("ascii"),
                        "creator_fabric_index": cred.creator_fabric_index,
                        "last_modified_fabric_index": cred.last_modified_fabric_index,
                        "aliro_discriminator": base64.b64encode(cred.aliro_discriminator).decode("ascii"),
                        "persistent_key": base64.b64encode(cred.persistent_key).decode("ascii") if cred.persistent_key else None,
                    }
                } for cid, cred in creds.items()],
            } for ct, creds in self.credentials.items()],
            "aliro_reader_config": {
                "signing_key": base64.b64encode(self.aliro_reader_config.signing_key.private_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.DER,
                    cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
                    cryptography.hazmat.primitives.serialization.NoEncryption(),
                )).decode("ascii"),
                "group_identifier": base64.b64encode(self.aliro_reader_config.group_identifier).decode("ascii"),
                "sub_group_identifier": base64.b64encode(self.aliro_reader_config.sub_group_identifier).decode("ascii"),
                "ecp_broadcast": base64.b64encode(self.aliro_reader_config.ecp_broadcast).decode("ascii"),
            } if self.aliro_reader_config else None
        })


class Terminal(aliro.iso7816.Terminal):
    def __init__(self, device: nfc.tag.tt4.Type4Tag):
        self.device = device

    def transmit(self, request: aliro.iso7816.RequestAPDU) -> aliro.iso7816.ResponseAPDU:
        return aliro.iso7816.ResponseAPDU.decode(self.device.transceive(request.encode()))


class PublicKey(aliro.util.PublicKey):
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


def run_aliro_nfc(tag, device: DoorLockDevice):
    if not device.aliro_reader_config:
        return

    logging.info("Running Aliro")
    target = Terminal(tag)

    known_access_keys = []
    known_issuer_keys = []

    for cid, credential in device.credentials[protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey].items():
        known_issuer_keys.append(PublicKey(
            key=credential.data,
            aliro_key_slot=b"",
            aliro_key_identifier=credential.aliro_discriminator,
            user_id=credential.user_index,
            credential_type=protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey,
            credential_id=cid
        ))
    for cid, credential in device.credentials[protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey].items():
        known_access_keys.append(PublicKey(
            key=credential.data,
            aliro_key_slot=credential.aliro_discriminator,
            aliro_key_identifier=b"",
            user_id=credential.user_index,
            credential_type=protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey,
            credential_id=cid
        ))
    for cid, credential in device.credentials[protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey].items():
        known_access_keys.append(PublicKey(
            key=credential.data,
            aliro_key_slot=credential.aliro_discriminator,
            aliro_key_identifier=b"",
            user_id=credential.user_index,
            credential_type=protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey,
            credential_id=cid
        ))

    if resp := aliro.reader.run_aliro(
            target=target,
            reader_signing_key=device.aliro_reader_config.signing_key,
            reader_group_identifier=device.aliro_reader_config.group_identifier,
            reader_sub_group_identifier=device.aliro_reader_config.sub_group_identifier,
            authentication_policy=aliro.data_elements.AuthenticationPolicy.UserDeviceSetting if device.locked else \
                aliro.data_elements.AuthenticationPolicy.UserDeviceSettingSecureAction,
            requested_access_elements=["matter1"],
            known_access_keys=known_access_keys,
            trusted_issuer_keys=known_issuer_keys,
            persistent_keys=[]
    ):
        if device.locked:
            print("UNLOCK DOOR")
            device.locked = False
            device.save_state()
            device.lock_cluster.increment_data_version()
            device.lock_cluster.attributes_changed([device.lock_cluster.lock_state])
            aliro.reader.notify_status(target, aliro.data_elements.ReaderStatus.ReaderUnsecure, resp.secure_channel)
        else:
            print("LOCK DOOR")
            device.locked = True
            device.save_state()
            device.lock_cluster.increment_data_version()
            device.lock_cluster.attributes_changed([device.lock_cluster.lock_state])
            aliro.reader.notify_status(target, aliro.data_elements.ReaderStatus.ReaderSecure, resp.secure_channel)


def run_nfc(device: DoorLockDevice):
    logging.info("NFC running")
    with broadcast_frame_contactless_frontend.BroadcastFrameContactlessFrontend("usb") as clf:
        tries = 0
        while True:
            target = clf.sense(
                nfc.clf.RemoteTarget("106A"),
                nfc.clf.RemoteTarget("106B"),
                broadcast=device.aliro_reader_config.ecp_broadcast if device.aliro_reader_config else None,
            )
            if not target:
                tries = min(0, tries - 1)
                time.sleep(0.1)
                continue

            if tries > 0:
                time.sleep(0.5)
                continue

            try:
                clf.connect(rdwr={
                    "on-connect": lambda d: run_aliro_nfc(d, device)
                })
            except (nfc.tag.TagCommandError, nfc.clf.Error, aliro.util.GeneralException) as e:
                tries = 3
                time.sleep(1)
                continue

            tries = 3
            time.sleep(5)


def main():
    logging.basicConfig(level=logging.INFO)

    d = matter.Device(matter.DeviceMeta(
        vendor_id=0xFFF1,
        vendor_name="Q Misell",
        product_id=0x8000,
        product_name="Aliro Lock",
        primary_device_type=0x000A,
        device_name="Aliro Lock",
    ), pathlib.Path(os.path.dirname(__file__)) / "state")

    with open("pai-cert.pem", "rb") as f:
        d.state.set_pai_cert(cryptography.x509.load_pem_x509_certificate(f.read()))
    with open("dac-cert.pem", "rb") as f:
        d.state.set_dac_cert(cryptography.x509.load_pem_x509_certificate(f.read()))
    with open("dac-priv.pem", "rb") as f:
        d.state.set_dac_key(cryptography.hazmat.primitives.serialization.load_pem_private_key(f.read(), None))

    lock = DoorLockDevice("door-lock", d.state)
    d.add_endpoint(lock)

    if not d.state.is_commissioned:
        qr = qrcode.QRCode()
        qr.add_data(d.state.qr_discovery_string)
        qr.print_ascii()
        print("QR contents:", d.state.qr_discovery_string)
        print("Manual pairing code:", d.state.manual_discovery_string)

    t = threading.Thread(target=run_nfc, args=(lock,))
    t.start()

    logging.info("Matter running")
    d.start()


if __name__ == "__main__":
    main()
