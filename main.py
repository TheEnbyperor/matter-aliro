import base64
import logging
import pathlib
import os.path
import qrcode
import dataclasses
import cryptography.x509
import cryptography.hazmat.primitives.serialization
import typing
import matter
import matter.interaction_model
import matter.encoding.tlv
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
    data: bytes
    creator_fabric_index: int
    last_modified_fabric_index: int

@dataclasses.dataclass
class AliroReaderConfig:
    signing_key: bytes
    verification_key: bytes
    group_identifier: bytes

class DoorLockDevice(matter.interaction_model.Endpoint):
    DEVICE_TYPES = {matter.interaction_model.DeviceType(id=0x000A, revision=3)}

    def __init__(self, unique_id: str, state: matter.device.DeviceState):
        super().__init__(unique_id)

        self.add_server(DoorLockCluster(state))

class DoorLockStatusCode(matter.interaction_model.StatusCodeType):
    DUPLICATE = 0x02
    OCCUPIED = 0x03

class DoorLockCluster(matter.interaction_model.Cluster):
    cluster_id = 0x0101
    cluster_revision_number = 9
    features = [8, 13] # USR, ALIRO

    lock_state = matter.interaction_model.cluster.Attribute(
        0x0000, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        p_reportable=True, x_nullable=True
    )
    lock_type = matter.interaction_model.cluster.Attribute(
        0x0001, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View
    )
    actuator_enabled = matter.interaction_model.cluster.Attribute(
        0x0002, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View
    )
    number_of_total_users_supported = matter.interaction_model.cluster.Attribute(
        0x0011, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    credential_rules_support = matter.interaction_model.cluster.Attribute(
        0x001B, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    number_of_credentials_supported_per_user = matter.interaction_model.cluster.Attribute(
        0x001C, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    operating_mode = matter.interaction_model.cluster.Attribute(
        0x0025, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        p_reportable=True
    )
    supported_operating_modes = matter.interaction_model.cluster.Attribute(
        0x0026, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    aliro_reader_verification_key = matter.interaction_model.cluster.Attribute(
        0x0080, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.Administer,
        x_nullable=True
    )
    aliro_reader_group_identifier = matter.interaction_model.cluster.Attribute(
        0x0081, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.Administer,
        x_nullable=True
    )
    aliro_reader_group_sub_identifier = matter.interaction_model.cluster.Attribute(
        0x0082, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.Administer,
        x_nullable=True
    )
    aliro_expedited_transaction_supported_protocol_versions = matter.interaction_model.cluster.ListAttribute(
        0x0083, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.Administer,
        f_fixed=True
    )
    number_of_aliro_credential_issuer_keys_supported = matter.interaction_model.cluster.Attribute(
        0x0087, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    number_of_aliro_endpoint_keys_supported = matter.interaction_model.cluster.Attribute(
        0x0088, matter.interaction_model.cluster.RWAccess.Read,
        matter.interaction_model.cluster.Privileges.View,
        f_fixed=True
    )

    lock_door = matter.interaction_model.cluster.Command(
        0x0000, None,
        matter.interaction_model.cluster.Privileges.Operate, t_timed=True
    )
    unlock_door = matter.interaction_model.cluster.Command(
        0x0001, None,
        matter.interaction_model.cluster.Privileges.Operate, t_timed=True
    )
    set_user = matter.interaction_model.cluster.Command(
        0x001A, None,
        matter.interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    get_user = matter.interaction_model.cluster.Command(
        0x001B, 0x001C,
        matter.interaction_model.cluster.Privileges.Administer
    )
    clear_user = matter.interaction_model.cluster.Command(
        0x001D, None,
        matter.interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    set_credential = matter.interaction_model.cluster.Command(
        0x0022, 0x0023,
        matter.interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    get_credential_status = matter.interaction_model.cluster.Command(
        0x0024, 0x0025,
        matter.interaction_model.cluster.Privileges.Administer
    )
    clear_credential = matter.interaction_model.cluster.Command(
        0x0026, None,
        matter.interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    set_aliro_reader_config = matter.interaction_model.cluster.Command(
        0x0028, None,
        matter.interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    clear_aliro_reader_config = matter.interaction_model.cluster.Command(
        0x0029, None,
        matter.interaction_model.cluster.Privileges.Administer, t_timed=True
    )

    door_lock_alarm = matter.interaction_model.cluster.Event(
        0x0000, matter.interaction_model.cluster.EventPriority.INFO,
        matter.interaction_model.cluster.Privileges.View
    )
    lock_operation = matter.interaction_model.cluster.Event(
        0x0002, matter.interaction_model.cluster.EventPriority.CRITICAL,
        matter.interaction_model.cluster.Privileges.View
    )
    lock_operation_error = matter.interaction_model.cluster.Event(
        0x0003, matter.interaction_model.cluster.EventPriority.CRITICAL,
        matter.interaction_model.cluster.Privileges.View
    )
    lock_user_change = matter.interaction_model.cluster.Event(
        0x0004, matter.interaction_model.cluster.EventPriority.INFO,
        matter.interaction_model.cluster.Privileges.View
    )

    def __init__(self, state: matter.device.DeviceState):
        super().__init__()
        self._state = state
        self.locked = False
        self.users: typing.Dict[int, LockUser] = {}
        self.credentials: typing.Dict[protocol_messages.CredentialTypeEnum, typing.Dict[int, LockCredential]] = {}
        self.aliro_reader_config: typing.Optional[AliroReaderConfig] = None
        self.load_state()

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
                        data=base64.b64decode(credential["credential"]["data"]),
                        creator_fabric_index=int(credential["credential"]["creator_fabric_index"]),
                        last_modified_fabric_index=int(credential["credential"]["last_modified_fabric_index"]),
                    )
                self.credentials[protocol_messages.CredentialTypeEnum(int(credential_type["id"]))] = ct
            if state["aliro_reader_config"]:
                self.aliro_reader_config = AliroReaderConfig(
                    signing_key=base64.b64decode(state["aliro_reader_config"]["signing_key"]),
                    verification_key=base64.b64decode(state["aliro_reader_config"]["verification_key"]),
                    group_identifier=base64.b64decode(state["aliro_reader_config"]["group_identifier"]),
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
                        "data": base64.b64encode(cred.data).decode("ascii"),
                        "creator_fabric_index": cred.creator_fabric_index,
                        "last_modified_fabric_index": cred.last_modified_fabric_index,
                    }
                } for cid, cred in creds.items()],
            } for ct, creds in self.credentials.items()],
            "aliro_reader_config": {
                "signing_key": base64.b64encode(self.aliro_reader_config.signing_key).decode("ascii"),
                "verification_key": base64.b64encode(self.aliro_reader_config.verification_key).decode("ascii"),
                "group_identifier": base64.b64encode(self.aliro_reader_config.group_identifier).decode("ascii"),
            } if self.aliro_reader_config else None
        })

    @lock_state.reader
    def read_lock_state(self):
        return protocol_messages.LockStateEnum.Locked.value if self.locked else protocol_messages.LockStateEnum.Unlocked.value

    @lock_type.reader
    def read_lock_type(self):
        return protocol_messages.LockTypeEnum.Other.value

    @actuator_enabled.reader
    def read_actuator_enabled(self):
        return True

    @number_of_total_users_supported.reader
    def read_number_of_total_users_supported(self):
        return 65535

    @credential_rules_support.reader
    def read_credential_rules_supported(self):
        return 0

    @number_of_credentials_supported_per_user.reader
    def read_number_of_credentials_supported_per_user(self):
        return 255

    @operating_mode.reader
    def read_operating_mode(self):
        return 0

    @supported_operating_modes.reader
    def read_supported_operating_modes(self):
        return 0

    @aliro_reader_verification_key.reader
    def read_aliro_reader_verification_key(self):
        if self.aliro_reader_config:
            return self.aliro_reader_config.verification_key
        else:
            return None

    @aliro_reader_group_identifier.reader
    def read_aliro_reader_group_identifier(self):
        if self.aliro_reader_config:
            return self.aliro_reader_config.group_identifier
        else:
            return None

    @aliro_reader_group_sub_identifier.reader
    def read_aliro_reader_group_sub_identifier(self):
        return None

    @aliro_expedited_transaction_supported_protocol_versions.reader
    def read_aliro_expedited_transaction_supported_protocol_versions(self):
        return [b"\x01\x00"] # Version 1

    @number_of_aliro_credential_issuer_keys_supported.reader
    def read_number_of_aliro_credential_issuer_keys_supported(self):
        return 65535

    @number_of_aliro_endpoint_keys_supported.reader
    def read_number_of_aliro_endpoint_keys_supported(self):
        return 65535

    @lock_door.handler
    def handle_lock_door(self, _: None, session: matter.message.SessionContext):
        print("LOCK DOOR")
        self.locked = True
        self.increment_data_version()
        self.attributes_changed([self.lock_state])
        self.report_event(self.lock_operation, protocol_messages.LockOperation(
            lock_operation_type=protocol_messages.LockOperationTypeEnum.Lock.value,
            operation_source=protocol_messages.OperationSourceEnum.Remote.value,
            user_index=matter.encoding.tlv.Null(),
            fabric_index=session.local_fabric_index,
            source_node=session.peer_node_id,
            credentials=matter.encoding.tlv.Null(),
        ))
        self.save_state()
        return matter.interaction_model.StatusCode.SUCCESS

    @unlock_door.handler
    def handle_unlock_door(self, _: None, session: matter.message.SessionContext):
        print("UNLOCK DOOR")
        self.locked = False
        self.increment_data_version()
        self.attributes_changed([self.lock_state])
        self.report_event(self.lock_operation, protocol_messages.LockOperation(
            lock_operation_type=protocol_messages.LockOperationTypeEnum.Unlock.value,
            operation_source=protocol_messages.OperationSourceEnum.Remote.value,
            user_index=matter.encoding.tlv.Null(),
            fabric_index=session.local_fabric_index,
            source_node=session.peer_node_id,
            credentials=matter.encoding.tlv.Null(),
        ))
        self.save_state()
        return matter.interaction_model.StatusCode.SUCCESS

    @set_user.handler
    def handle_set_user(self, req: protocol_messages.SetUserRequest, session: matter.message.SessionContext):
        if req.operation_type == protocol_messages.DataOperationTypeEnum.Add.value:
            if req.user_index in self.users:
                return DoorLockStatusCode.OCCUPIED

            self.users[req.user_index] = LockUser(
                name=req.user_name or "",
                unique_id=req.user_unique_id or 0xFFFFFFFF,
                user_status=protocol_messages.UserStatusEnum(req.user_status or protocol_messages.UserStatusEnum.OccupiedEnabled),
                user_type=protocol_messages.UserTypeEnum(req.user_type or protocol_messages.UserTypeEnum.UnrestrictedUser),
                credential_rule=protocol_messages.CredentialRuleEnum(req.credential_rule or protocol_messages.CredentialRuleEnum.Single),
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
            )
            self.save_state()

            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Add,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))

            return matter.interaction_model.StatusCode.SUCCESS

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Modify.value:
            if req.user_index not in self.users:
                return matter.interaction_model.StatusCode.INVALID_COMMAND

            user = self.users[req.user_index]
            if req.user_name != matter.encoding.tlv.Null() and session.local_fabric_index != user.creator_fabric_index:
                return matter.interaction_model.StatusCode.INVALID_COMMAND
            if req.user_unique_id != matter.encoding.tlv.Null() and session.local_fabric_index != user.creator_fabric_index:
                return matter.interaction_model.StatusCode.INVALID_COMMAND

            if req.user_name != matter.encoding.tlv.Null():
                user.name = req.user_name
            if req.user_unique_id != matter.encoding.tlv.Null():
                user.unique_id = req.user_unique_id
            if req.user_status != matter.encoding.tlv.Null():
                user.user_status = protocol_messages.UserStatusEnum(req.user_status)
            if req.user_type != matter.encoding.tlv.Null():
                user.user_type = protocol_messages.UserTypeEnum(req.user_type)
            if req.credential_rule != matter.encoding.tlv.Null():
                user.credential_rule = protocol_messages.CredentialRuleEnum(req.credential_rule)

            user.last_modified_fabric_index = session.local_fabric_index
            self.save_state()

            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Modify,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))

            return matter.interaction_model.StatusCode.SUCCESS

        else:
            return matter.interaction_model.StatusCode.INVALID_COMMAND

    @get_user.handler
    def handle_get_user(self, req: protocol_messages.GetUserRequest):
        next_occupied = [i for i in self.users.keys() if i > req.user_index]
        if len(next_occupied) == 0:
            next_user_index = matter.encoding.tlv.Null()
        else:
            next_user_index = min(next_occupied)

        if req.user_index in self.users:
            user = self.users[req.user_index]

            user_creds = []
            for ct, creds in self.credentials.items():
                for cid, cred in creds.items():
                    if cred.user_index == req.user_index:
                        user_creds.append(protocol_messages.CredentialStruct(
                            credential_type=ct.value,
                            credential_index=cid
                        ))

            return protocol_messages.GetUserResponse(
                user_index=req.user_index,
                user_status=user.user_status,
                user_name=user.name,
                user_unique_id=user.unique_id,
                user_type=user.user_type,
                credential_rule=user.credential_rule,
                credentials=user_creds,
                creator_fabric_index=user.creator_fabric_index,
                last_modified_fabric_index=user.last_modified_fabric_index,
                next_user_index=next_user_index,
            )
        else:
            return protocol_messages.GetUserResponse(
                user_index=req.user_index,
                user_status=protocol_messages.UserStatusEnum.Available.value,
                user_name=matter.encoding.tlv.Null(),
                user_unique_id=matter.encoding.tlv.Null(),
                user_type=matter.encoding.tlv.Null(),
                credential_rule=matter.encoding.tlv.Null(),
                credentials=matter.encoding.tlv.Null(),
                creator_fabric_index=matter.encoding.tlv.Null(),
                last_modified_fabric_index=matter.encoding.tlv.Null(),
                next_user_index=next_user_index,
            )

    @clear_user.handler
    def handle_clear_user(self, req: protocol_messages.ClearUserRequest, session: matter.message.SessionContext):
        if req.user_index == 0xFFFE:
            self.users = {}
            self.credentials = {
                protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey: {},
                protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey: {},
                protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey: {},
            }
            self.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))
            return matter.interaction_model.StatusCode.SUCCESS
        elif req.user_index in self.users:
            del self.users[req.user_index]
            for ct in self.credentials.values():
                tbd = set()
                for i, c in ct.items():
                    if c.user_index == req.user_index:
                        tbd.add(i)
                for i in tbd:
                    del ct[i]
            self.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))
            return matter.interaction_model.StatusCode.SUCCESS
        else:
            return matter.interaction_model.StatusCode.INVALID_COMMAND

    @staticmethod
    def credential_type_to_data_type(credential_type: protocol_messages.CredentialTypeEnum) -> protocol_messages.LockDataTypeEnum:
        if credential_type == protocol_messages.CredentialTypeEnum.ProgrammingPIN:
            return protocol_messages.LockDataTypeEnum.ProgrammingCode
        elif credential_type == protocol_messages.CredentialTypeEnum.PIN:
            return protocol_messages.LockDataTypeEnum.PIN
        elif credential_type == protocol_messages.CredentialTypeEnum.RFID:
            return protocol_messages.LockDataTypeEnum.RFID
        elif credential_type == protocol_messages.CredentialTypeEnum.Fingerprint:
            return protocol_messages.LockDataTypeEnum.Fingerprint
        elif credential_type == protocol_messages.CredentialTypeEnum.FingerVein:
            return protocol_messages.LockDataTypeEnum.FingerVein
        elif credential_type == protocol_messages.CredentialTypeEnum.Face:
            return protocol_messages.LockDataTypeEnum.Face
        elif credential_type == protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey:
            return protocol_messages.LockDataTypeEnum.AliroCredentialIssuerKey
        elif credential_type == protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey:
            return protocol_messages.LockDataTypeEnum.AliroEvictableEndpointKey
        elif credential_type == protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey:
            return protocol_messages.LockDataTypeEnum.AliroNonEvictableEndpointKey

    @set_credential.handler
    def handle_set_credential(self, req: protocol_messages.SetCredentialRequest, session: matter.message.SessionContext):
        credential_type = protocol_messages.CredentialTypeEnum(req.credential.credential_type)
        if credential_type not in self.credentials:
            return protocol_messages.SetCredentialResponse(
                status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                user_index=matter.encoding.tlv.Null(),
                next_credential_index=matter.encoding.tlv.Null(),
            )

        credentials = self.credentials[credential_type]

        next_occupied = [i for i in credentials.keys() if i > req.credential.credential_type]
        if len(next_occupied) == 0:
            next_credential_index = matter.encoding.tlv.Null()
        else:
            next_credential_index = min(next_occupied)

        if req.operation_type == protocol_messages.DataOperationTypeEnum.Add and req.user_index == matter.encoding.tlv.Null():
            if req.credential.credential_index in credentials:
                return protocol_messages.SetCredentialResponse(
                    status=DoorLockStatusCode.OCCUPIED,
                    user_index=matter.encoding.tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            next_user_index = next(i for i in range(1, 65535) if i not in self.users)
            self.users[next_user_index] = LockUser(
                name="",
                unique_id=0xFFFFFFFF,
                user_status=protocol_messages.UserStatusEnum(req.user_status or protocol_messages.UserStatusEnum.OccupiedEnabled),
                user_type=protocol_messages.UserTypeEnum(req.user_type or protocol_messages.UserTypeEnum.UnrestrictedUser),
                credential_rule=protocol_messages.CredentialRuleEnum.Single,
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
            )
            credentials[req.credential.credential_index] = LockCredential(
                user_index=next_user_index,
                data=req.credential_data,
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
            )
            self.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=self.credential_type_to_data_type(credential_type),
                data_operation_type=protocol_messages.DataOperationTypeEnum.Add,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=next_user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.credential.credential_index,
            ))
            return protocol_messages.SetCredentialResponse(
                status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                user_index=next_user_index,
                next_credential_index=next_credential_index,
            )

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Add and req.user_index != matter.encoding.tlv.Null():
            if req.credential.credential_index in credentials:
                return protocol_messages.SetCredentialResponse(
                    status=DoorLockStatusCode.OCCUPIED,
                    user_index=matter.encoding.tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            if req.user_index not in self.users:
                return protocol_messages.SetCredentialResponse(
                    status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=matter.encoding.tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            user = self.users[req.user_index]

            if user.creator_fabric_index != session.local_fabric_index:
                return protocol_messages.SetCredentialResponse(
                    status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=matter.encoding.tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            credentials[req.credential.credential_index] = LockCredential(
                user_index=req.user_index,
                data=req.credential_data,
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
            )
            self.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=self.credential_type_to_data_type(credential_type),
                data_operation_type=protocol_messages.DataOperationTypeEnum.Add,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.credential.credential_index,
            ))
            return protocol_messages.SetCredentialResponse(
                status=matter.interaction_model.StatusCode.SUCCESS,
                user_index=matter.encoding.tlv.Null(),
                next_credential_index=next_credential_index,
            )

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Modify and req.user_index == matter.encoding.tlv.Null():
            return protocol_messages.SetCredentialResponse(
                status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                user_index=matter.encoding.tlv.Null(),
                next_credential_index=next_credential_index,
            )

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Modify and req.user_index != matter.encoding.tlv.Null():
            if req.credential.credential_index not in credentials:
                return protocol_messages.SetCredentialResponse(
                    status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=matter.encoding.tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            credential = credentials[req.credential.credential_index]
            if credential.user_index != req.user_index:
                return protocol_messages.SetCredentialResponse(
                    status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=matter.encoding.tlv.Null(),
                    next_credential_index=next_credential_index
                )

            if credential.creator_fabric_index != session.local_fabric_index:
                return protocol_messages.SetCredentialResponse(
                    status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=matter.encoding.tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            credential.data = req.credential_data
            self.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=self.credential_type_to_data_type(credential_type),
                data_operation_type=protocol_messages.DataOperationTypeEnum.Modify,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.credential.credential_index,
            ))
            return protocol_messages.SetCredentialResponse(
                status=matter.interaction_model.StatusCode.SUCCESS,
                user_index=matter.encoding.tlv.Null(),
                next_credential_index=next_credential_index,
            )
        else:
            return protocol_messages.SetCredentialResponse(
                status=matter.interaction_model.StatusCode.INVALID_COMMAND,
                user_index=matter.encoding.tlv.Null(),
                next_credential_index=matter.encoding.tlv.Null(),
            )

    @get_credential_status.handler
    def handle_get_credential_status(self, req: protocol_messages.GetCredentialStatusRequest):
        credential_type = protocol_messages.CredentialTypeEnum(req.credential.credential_type)
        if credential_type not in self.credentials:
            return matter.interaction_model.StatusCode.INVALID_COMMAND

        credentials = self.credentials[credential_type]
        next_occupied = [i for i in credentials.keys() if i > req.credential.credential_index]
        if len(next_occupied) == 0:
            next_credential_index = matter.encoding.tlv.Null()
        else:
            next_credential_index = min(next_occupied)

        if req.credential.credential_index in credentials:
            credential = credentials[req.credential.credential_index]
            return protocol_messages.GetCredentialStatusResponse(
                credential_exists=True,
                user_index=credential.user_index,
                creator_fabric_index=credential.creator_fabric_index,
                last_modified_fabric_index=credential.last_modified_fabric_index,
                next_credential_index=next_credential_index,
                credential_data=credential.data,
            )
        else:
            return protocol_messages.GetCredentialStatusResponse(
                credential_exists=False,
                user_index=matter.encoding.tlv.Null(),
                creator_fabric_index=matter.encoding.tlv.Null(),
                last_modified_fabric_index=matter.encoding.tlv.Null(),
                next_credential_index=next_credential_index,
                credential_data=matter.encoding.tlv.Null(),
            )

    @clear_credential.handler
    def handle_clear_credential(self, req: protocol_messages.ClearCredentialRequest, session: matter.message.SessionContext):
        if req.credential == matter.encoding.tlv.Null():
            self.credentials = {
                protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey: {},
                protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey: {},
                protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey: {},
            }
            self.save_state()
            for dt in (
                protocol_messages.LockDataTypeEnum.AliroCredentialIssuerKey,
                protocol_messages.LockDataTypeEnum.AliroEvictableEndpointKey,
                protocol_messages.LockDataTypeEnum.AliroNonEvictableEndpointKey,
            ):
                self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                    lock_data_type=dt,
                    data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                    operation_source=protocol_messages.OperationSourceEnum.Remote,
                    user_index=0xFFFE,
                    fabric_index=session.local_fabric_index,
                    source_node=session.peer_node_id,
                    data_index=0xFFFE,
                ))
            return matter.interaction_model.StatusCode.SUCCESS
        else:
            credential_type = protocol_messages.CredentialTypeEnum(req.credential.credential_type)
            if req.credential.credential_index == 0xFFFE:
                if credential_type not in self.credentials:
                    return matter.interaction_model.StatusCode.INVALID_COMMAND
                self.credentials[credential_type] = {}
                self.save_state()
                self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                    lock_data_type=self.credential_type_to_data_type(credential_type),
                    data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                    operation_source=protocol_messages.OperationSourceEnum.Remote,
                    user_index=0xFFFE,
                    fabric_index=session.local_fabric_index,
                    source_node=session.peer_node_id,
                    data_index=0xFFFE,
                ))
            else:
                if req.credential.credential_index not in self.credentials[credential_type]:
                    return matter.interaction_model.StatusCode.INVALID_COMMAND
                c = self.credentials[credential_type][req.credential.credential_index]
                del self.credentials[credential_type][req.credential.credential_index]
                self.save_state()
                self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                    lock_data_type=self.credential_type_to_data_type(credential_type),
                    data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                    operation_source=protocol_messages.OperationSourceEnum.Remote,
                    user_index=c.user_index,
                    fabric_index=session.local_fabric_index,
                    source_node=session.peer_node_id,
                    data_index=req.credential.credential_index,
                ))
            return matter.interaction_model.StatusCode.SUCCESS

    @set_aliro_reader_config.handler
    def handle_set_aliro_reader_config(self, req: protocol_messages.SetAliroReaderConfigRequest):
        if self.aliro_reader_config:
            return matter.interaction_model.StatusCode.INVALID_IN_STATE

        self.aliro_reader_config = AliroReaderConfig(
            signing_key=req.signing_key,
            verification_key=req.verification_key,
            group_identifier=req.group_identifier,
        )
        self.save_state()
        self.increment_data_version()
        self.attributes_changed([
            self.aliro_reader_verification_key,
            self.aliro_reader_group_identifier,
        ])
        return matter.interaction_model.StatusCode.SUCCESS

    @clear_aliro_reader_config.handler
    def handle_clear_aliro_reader_config(self):
        self.aliro_reader_config = None
        self.save_state()
        self.increment_data_version()
        self.attributes_changed([
            self.aliro_reader_verification_key,
            self.aliro_reader_group_identifier,
        ])
        return matter. interaction_model.StatusCode.SUCCESS


def main():
    logging.basicConfig(level=logging.DEBUG)

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

    d.add_endpoint(DoorLockDevice("door-lock", d.state))

    if not d.state.is_commissioned:
        qr = qrcode.QRCode()
        qr.add_data(d.state.qr_discovery_string)
        qr.print_ascii()
        print("QR contents:", d.state.qr_discovery_string)
        print("Manual pairing code:", d.state.manual_discovery_string)

    logging.info("Matter running")
    d.start()


if __name__ == "__main__":
    main()
