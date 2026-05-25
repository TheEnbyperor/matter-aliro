import typing
import dataclasses
import base64
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
from .matter import interaction_model, device
from .matter.encoding import protocol_messages
from . import cluster


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

class DoorLockDevice(interaction_model.Endpoint):
    DEVICE_TYPES = {interaction_model.DeviceType(id=0x000A, revision=3)}

    def __init__(self, unique_id: str, state: device.DeviceState):
        super().__init__(unique_id)

        self._state = state
        self.locked = False
        self.users: typing.Dict[int, LockUser] = {}
        self.credentials: typing.Dict[protocol_messages.CredentialTypeEnum, typing.Dict[int, LockCredential]] = {}
        self.aliro_reader_config: typing.Optional[AliroReaderConfig] = None
        self.readers: typing.Set[bytes] = set()
        self.load_state()

        self.lock_cluster = cluster.DoorLockCluster(self)
        self.add_server(self.lock_cluster)

    def add_reader(self, reader_id: bytes):
        self.readers.add(reader_id)

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
            self.save_state()

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
            "readers": [base64.b64encode(r).decode("ascii") for r in self.readers],
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