import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
from .matter import interaction_model
from .matter import message
from .matter.encoding import tlv, protocol_messages
from .aliro import ecp
from .aliro import util as aliro_util
from . import device
import secrets


class DoorLockStatusCode(interaction_model.StatusCodeType):
    DUPLICATE = 0x02
    OCCUPIED = 0x03


class DoorLockCluster(interaction_model.Cluster):
    cluster_id = 0x0101
    cluster_revision_number = 9
    features = [8, 13]  # USR, ALIRO

    lock_state = interaction_model.cluster.Attribute(
        0x0000, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        p_reportable=True, x_nullable=True
    )
    lock_type = interaction_model.cluster.Attribute(
        0x0001, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View
    )
    actuator_enabled = interaction_model.cluster.Attribute(
        0x0002, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View
    )
    number_of_total_users_supported = interaction_model.cluster.Attribute(
        0x0011, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    credential_rules_support = interaction_model.cluster.Attribute(
        0x001B, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    number_of_credentials_supported_per_user = interaction_model.cluster.Attribute(
        0x001C, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    operating_mode = interaction_model.cluster.Attribute(
        0x0025, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        p_reportable=True
    )
    supported_operating_modes = interaction_model.cluster.Attribute(
        0x0026, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    aliro_reader_verification_key = interaction_model.cluster.Attribute(
        0x0080, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.Administer,
        x_nullable=True
    )
    aliro_reader_group_identifier = interaction_model.cluster.Attribute(
        0x0081, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.Administer,
        x_nullable=True
    )
    aliro_reader_group_sub_identifier = interaction_model.cluster.Attribute(
        0x0082, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.Administer,
        x_nullable=True
    )
    aliro_expedited_transaction_supported_protocol_versions = interaction_model.cluster.ListAttribute(
        0x0083, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.Administer,
        f_fixed=True
    )
    number_of_aliro_credential_issuer_keys_supported = interaction_model.cluster.Attribute(
        0x0087, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        f_fixed=True
    )
    number_of_aliro_endpoint_keys_supported = interaction_model.cluster.Attribute(
        0x0088, interaction_model.cluster.RWAccess.Read,
        interaction_model.cluster.Privileges.View,
        f_fixed=True
    )

    lock_door = interaction_model.cluster.Command(
        0x0000, None,
        interaction_model.cluster.Privileges.Operate, t_timed=True
    )
    unlock_door = interaction_model.cluster.Command(
        0x0001, None,
        interaction_model.cluster.Privileges.Operate, t_timed=True
    )
    set_user = interaction_model.cluster.Command(
        0x001A, None,
        interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    get_user = interaction_model.cluster.Command(
        0x001B, 0x001C,
        interaction_model.cluster.Privileges.Administer
    )
    clear_user = interaction_model.cluster.Command(
        0x001D, None,
        interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    set_credential = interaction_model.cluster.Command(
        0x0022, 0x0023,
        interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    get_credential_status = interaction_model.cluster.Command(
        0x0024, 0x0025,
        interaction_model.cluster.Privileges.Administer
    )
    clear_credential = interaction_model.cluster.Command(
        0x0026, None,
        interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    set_aliro_reader_config = interaction_model.cluster.Command(
        0x0028, None,
        interaction_model.cluster.Privileges.Administer, t_timed=True
    )
    clear_aliro_reader_config = interaction_model.cluster.Command(
        0x0029, None,
        interaction_model.cluster.Privileges.Administer, t_timed=True
    )

    door_lock_alarm = interaction_model.cluster.Event(
        0x0000, interaction_model.cluster.EventPriority.INFO,
        interaction_model.cluster.Privileges.View
    )
    lock_operation = interaction_model.cluster.Event(
        0x0002, interaction_model.cluster.EventPriority.CRITICAL,
        interaction_model.cluster.Privileges.View
    )
    lock_operation_error = interaction_model.cluster.Event(
        0x0003, interaction_model.cluster.EventPriority.CRITICAL,
        interaction_model.cluster.Privileges.View
    )
    lock_user_change = interaction_model.cluster.Event(
        0x0004, interaction_model.cluster.EventPriority.INFO,
        interaction_model.cluster.Privileges.View
    )

    def __init__(self, d: "device.DoorLockDevice"):
        super().__init__()
        self.device = d

    @lock_state.reader
    def read_lock_state(self):
        return protocol_messages.LockStateEnum.Locked.value if self.device.locked else protocol_messages.LockStateEnum.Unlocked.value

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
        if self.device.aliro_reader_config:
            return self.device.aliro_reader_config.signing_key.public_key().public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.X962,
                cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint,
            )
        else:
            return None

    @aliro_reader_group_identifier.reader
    def read_aliro_reader_group_identifier(self):
        if self.device.aliro_reader_config:
            return self.device.aliro_reader_config.group_identifier
        else:
            return None

    @aliro_reader_group_sub_identifier.reader
    def read_aliro_reader_group_sub_identifier(self):
        if self.device.aliro_reader_config:
            return self.device.aliro_reader_config.sub_group_identifier
        else:
            return None

    @aliro_expedited_transaction_supported_protocol_versions.reader
    def read_aliro_expedited_transaction_supported_protocol_versions(self):
        return [b"\x01\x00"]  # Version 1

    @number_of_aliro_credential_issuer_keys_supported.reader
    def read_number_of_aliro_credential_issuer_keys_supported(self):
        return 65535

    @number_of_aliro_endpoint_keys_supported.reader
    def read_number_of_aliro_endpoint_keys_supported(self):
        return 65535

    @lock_door.handler
    def handle_lock_door(self, _: None, session: message.SessionContext):
        print("LOCK DOOR")
        self.device.locked = True
        self.device.save_state()
        self.increment_data_version()
        self.attributes_changed([self.lock_state])
        self.report_event(self.lock_operation, protocol_messages.LockOperation(
            lock_operation_type=protocol_messages.LockOperationTypeEnum.Lock.value,
            operation_source=protocol_messages.OperationSourceEnum.Remote.value,
            user_index=tlv.Null(),
            fabric_index=session.local_fabric_index,
            source_node=session.peer_node_id,
            credentials=tlv.Null(),
        ))
        return interaction_model.StatusCode.SUCCESS

    @unlock_door.handler
    def handle_unlock_door(self, _: None, session: message.SessionContext):
        print("UNLOCK DOOR")
        self.device.locked = False
        self.device.save_state()
        self.increment_data_version()
        self.attributes_changed([self.lock_state])
        self.report_event(self.lock_operation, protocol_messages.LockOperation(
            lock_operation_type=protocol_messages.LockOperationTypeEnum.Unlock.value,
            operation_source=protocol_messages.OperationSourceEnum.Remote.value,
            user_index=tlv.Null(),
            fabric_index=session.local_fabric_index,
            source_node=session.peer_node_id,
            credentials=tlv.Null(),
        ))
        return interaction_model.StatusCode.SUCCESS

    @set_user.handler
    def handle_set_user(self, req: protocol_messages.SetUserRequest, session: message.SessionContext):
        if req.operation_type == protocol_messages.DataOperationTypeEnum.Add.value:
            if req.user_index in self.device.users:
                return DoorLockStatusCode.OCCUPIED

            self.device.users[req.user_index] = device.LockUser(
                name=req.user_name or "",
                unique_id=req.user_unique_id or 0xFFFFFFFF,
                user_status=protocol_messages.UserStatusEnum(
                    req.user_status or protocol_messages.UserStatusEnum.OccupiedEnabled),
                user_type=protocol_messages.UserTypeEnum(
                    req.user_type or protocol_messages.UserTypeEnum.UnrestrictedUser),
                credential_rule=protocol_messages.CredentialRuleEnum(
                    req.credential_rule or protocol_messages.CredentialRuleEnum.Single),
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
            )
            self.device.save_state()

            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Add,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))

            return interaction_model.StatusCode.SUCCESS

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Modify.value:
            if req.user_index not in self.device.users:
                return interaction_model.StatusCode.INVALID_COMMAND

            user = self.device.users[req.user_index]
            if req.user_name != tlv.Null() and session.local_fabric_index != user.creator_fabric_index:
                return interaction_model.StatusCode.INVALID_COMMAND
            if req.user_unique_id != tlv.Null() and session.local_fabric_index != user.creator_fabric_index:
                return interaction_model.StatusCode.INVALID_COMMAND

            if req.user_name != tlv.Null():
                user.name = req.user_name
            if req.user_unique_id != tlv.Null():
                user.unique_id = req.user_unique_id
            if req.user_status != tlv.Null():
                user.user_status = protocol_messages.UserStatusEnum(req.user_status)
            if req.user_type != tlv.Null():
                user.user_type = protocol_messages.UserTypeEnum(req.user_type)
            if req.credential_rule != tlv.Null():
                user.credential_rule = protocol_messages.CredentialRuleEnum(req.credential_rule)

            user.last_modified_fabric_index = session.local_fabric_index
            self.device.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Modify,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))

            return interaction_model.StatusCode.SUCCESS

        else:
            return interaction_model.StatusCode.INVALID_COMMAND

    @get_user.handler
    def handle_get_user(self, req: protocol_messages.GetUserRequest):
        next_occupied = [i for i in self.device.users.keys() if i > req.user_index]
        if len(next_occupied) == 0:
            next_user_index = tlv.Null()
        else:
            next_user_index = min(next_occupied)

        if req.user_index in self.device.users:
            user = self.device.users[req.user_index]

            user_creds = []
            for ct, creds in self.device.credentials.items():
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
                user_name=tlv.Null(),
                user_unique_id=tlv.Null(),
                user_type=tlv.Null(),
                credential_rule=tlv.Null(),
                credentials=tlv.Null(),
                creator_fabric_index=tlv.Null(),
                last_modified_fabric_index=tlv.Null(),
                next_user_index=next_user_index,
            )

    @clear_user.handler
    def handle_clear_user(self, req: protocol_messages.ClearUserRequest, session: message.SessionContext):
        if req.user_index == 0xFFFE:
            self.device.users = {}
            self.device.credentials = {
                protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey: {},
                protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey: {},
                protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey: {},
            }
            self.device.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))
            return interaction_model.StatusCode.SUCCESS
        elif req.user_index in self.device.users:
            del self.device.users[req.user_index]
            for ct in self.device.credentials.values():
                tbd = set()
                for i, c in ct.items():
                    if c.user_index == req.user_index:
                        tbd.add(i)
                for i in tbd:
                    del ct[i]
            self.device.save_state()
            self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                lock_data_type=protocol_messages.LockDataTypeEnum.UserIndex,
                data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                operation_source=protocol_messages.OperationSourceEnum.Remote,
                user_index=req.user_index,
                fabric_index=session.local_fabric_index,
                source_node=session.peer_node_id,
                data_index=req.user_index,
            ))
            return interaction_model.StatusCode.SUCCESS
        else:
            return interaction_model.StatusCode.INVALID_COMMAND

    @staticmethod
    def credential_type_to_data_type(
            credential_type: protocol_messages.CredentialTypeEnum) -> protocol_messages.LockDataTypeEnum:
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
    def handle_set_credential(self, req: protocol_messages.SetCredentialRequest,
                              session: message.SessionContext):
        credential_type = protocol_messages.CredentialTypeEnum(req.credential.credential_type)
        if credential_type not in self.device.credentials:
            return protocol_messages.SetCredentialResponse(
                status=interaction_model.StatusCode.INVALID_COMMAND,
                user_index=tlv.Null(),
                next_credential_index=tlv.Null(),
            )

        credentials = self.device.credentials[credential_type]

        next_occupied = [i for i in credentials.keys() if i > req.credential.credential_type]
        if len(next_occupied) == 0:
            next_credential_index = tlv.Null()
        else:
            next_credential_index = min(next_occupied)

        if req.operation_type == protocol_messages.DataOperationTypeEnum.Add and req.user_index == tlv.Null():
            if req.credential.credential_index in credentials:
                return protocol_messages.SetCredentialResponse(
                    status=DoorLockStatusCode.OCCUPIED,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )
            if len(req.credential_data) != 65:
                return protocol_messages.SetCredentialResponse(
                    status=interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            next_user_index = next(i for i in range(1, 65535) if i not in self.device.users)
            self.device.users[next_user_index] = device.LockUser(
                name="",
                unique_id=0xFFFFFFFF,
                user_status=protocol_messages.UserStatusEnum(
                    req.user_status or protocol_messages.UserStatusEnum.OccupiedEnabled),
                user_type=protocol_messages.UserTypeEnum(
                    req.user_type or protocol_messages.UserTypeEnum.UnrestrictedUser),
                credential_rule=protocol_messages.CredentialRuleEnum.Single,
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
            )
            key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
                req.credential_data
            )
            credentials[req.credential.credential_index] = device.LockCredential(
                user_index=next_user_index,
                data=key,
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
                aliro_discriminator=aliro_util.aliro_key_identifier(key) \
                    if req.credential.credential_type == protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey else \
                    aliro_util.aliro_key_slot(key),
                persistent_key=None,
            )
            self.device.save_state()
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
                status=interaction_model.StatusCode.INVALID_COMMAND,
                user_index=next_user_index,
                next_credential_index=next_credential_index,
            )

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Add and req.user_index != tlv.Null():
            if req.credential.credential_index in credentials:
                return protocol_messages.SetCredentialResponse(
                    status=DoorLockStatusCode.OCCUPIED,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            if req.user_index not in self.device.users:
                return protocol_messages.SetCredentialResponse(
                    status=interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            if len(req.credential_data) != 65:
                return protocol_messages.SetCredentialResponse(
                    status=interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            user = self.device.users[req.user_index]

            if user.creator_fabric_index != session.local_fabric_index:
                return protocol_messages.SetCredentialResponse(
                    status=interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
                req.credential_data
            )
            credentials[req.credential.credential_index] = device.LockCredential(
                user_index=req.user_index,
                data=key,
                creator_fabric_index=session.local_fabric_index,
                last_modified_fabric_index=session.local_fabric_index,
                aliro_discriminator=aliro_util.aliro_key_identifier(key) \
                    if req.credential.credential_type == protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey else \
                    aliro_util.aliro_key_slot(key),
                persistent_key=None,
            )
            self.device.save_state()
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
                status=interaction_model.StatusCode.SUCCESS,
                user_index=tlv.Null(),
                next_credential_index=next_credential_index,
            )

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Modify and req.user_index == tlv.Null():
            return protocol_messages.SetCredentialResponse(
                status=interaction_model.StatusCode.INVALID_COMMAND,
                user_index=tlv.Null(),
                next_credential_index=next_credential_index,
            )

        elif req.operation_type == protocol_messages.DataOperationTypeEnum.Modify and req.user_index != tlv.Null():
            if req.credential.credential_index not in credentials:
                return protocol_messages.SetCredentialResponse(
                    status=interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            credential = credentials[req.credential.credential_index]
            if credential.user_index != req.user_index:
                return protocol_messages.SetCredentialResponse(
                    status=interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index
                )

            if credential.creator_fabric_index != session.local_fabric_index:
                return protocol_messages.SetCredentialResponse(
                    status=interaction_model.StatusCode.INVALID_COMMAND,
                    user_index=tlv.Null(),
                    next_credential_index=next_credential_index,
                )

            credential.data = req.credential_data
            self.device.save_state()
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
                status=interaction_model.StatusCode.SUCCESS,
                user_index=tlv.Null(),
                next_credential_index=next_credential_index,
            )
        else:
            return protocol_messages.SetCredentialResponse(
                status=interaction_model.StatusCode.INVALID_COMMAND,
                user_index=tlv.Null(),
                next_credential_index=tlv.Null(),
            )

    @get_credential_status.handler
    def handle_get_credential_status(self, req: protocol_messages.GetCredentialStatusRequest):
        credential_type = protocol_messages.CredentialTypeEnum(req.credential.credential_type)
        if credential_type not in self.device.credentials:
            return interaction_model.StatusCode.INVALID_COMMAND

        credentials = self.device.credentials[credential_type]
        next_occupied = [i for i in credentials.keys() if i > req.credential.credential_index]
        if len(next_occupied) == 0:
            next_credential_index = tlv.Null()
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
                credential_data=credential.data.public_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.X962,
                    cryptography.hazmat.primitives.serialization.PublicFormat.CompressedPoint,
                ),
            )
        else:
            return protocol_messages.GetCredentialStatusResponse(
                credential_exists=False,
                user_index=tlv.Null(),
                creator_fabric_index=tlv.Null(),
                last_modified_fabric_index=tlv.Null(),
                next_credential_index=next_credential_index,
                credential_data=tlv.Null(),
            )

    @clear_credential.handler
    def handle_clear_credential(self, req: protocol_messages.ClearCredentialRequest,
                                session: message.SessionContext):
        if req.credential == tlv.Null():
            self.device.credentials = {
                protocol_messages.CredentialTypeEnum.AliroCredentialIssuerKey: {},
                protocol_messages.CredentialTypeEnum.AliroEvictableEndpointKey: {},
                protocol_messages.CredentialTypeEnum.AliroNonEvictableEndpointKey: {},
            }
            self.device.save_state()
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
            return interaction_model.StatusCode.SUCCESS
        else:
            credential_type = protocol_messages.CredentialTypeEnum(req.credential.credential_type)
            if req.credential.credential_index == 0xFFFE:
                if credential_type not in self.device.credentials:
                    return interaction_model.StatusCode.INVALID_COMMAND
                self.device.credentials[credential_type] = {}
                self.device.save_state()
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
                if req.credential.credential_index not in self.device.credentials[credential_type]:
                    return interaction_model.StatusCode.INVALID_COMMAND
                c = self.device.credentials[credential_type][req.credential.credential_index]
                del self.device.credentials[credential_type][req.credential.credential_index]
                self.device.save_state()
                self.report_event(self.lock_user_change, protocol_messages.LockUserChange(
                    lock_data_type=self.credential_type_to_data_type(credential_type),
                    data_operation_type=protocol_messages.DataOperationTypeEnum.Clear,
                    operation_source=protocol_messages.OperationSourceEnum.Remote,
                    user_index=c.user_index,
                    fabric_index=session.local_fabric_index,
                    source_node=session.peer_node_id,
                    data_index=req.credential.credential_index,
                ))
            return interaction_model.StatusCode.SUCCESS

    @set_aliro_reader_config.handler
    def handle_set_aliro_reader_config(self, req: protocol_messages.SetAliroReaderConfigRequest):
        if self.device.aliro_reader_config:
            return interaction_model.StatusCode.INVALID_IN_STATE

        self.device.aliro_reader_config = device.AliroReaderConfig(
            signing_key=cryptography.hazmat.primitives.asymmetric.ec.derive_private_key(
                int.from_bytes(req.signing_key, "big"),
                cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
            ),
            group_identifier=req.group_identifier,
            sub_group_identifier=secrets.token_bytes(16),
            ecp_broadcast=ecp.ECPv2.aliro(req.group_identifier).encode()
        )
        self.device.save_state()
        self.increment_data_version()
        self.attributes_changed([
            self.aliro_reader_verification_key,
            self.aliro_reader_group_identifier,
        ])
        return interaction_model.StatusCode.SUCCESS

    @clear_aliro_reader_config.handler
    def handle_clear_aliro_reader_config(self):
        self.device.aliro_reader_config = None
        self.device.save_state()
        self.increment_data_version()
        self.attributes_changed([
            self.aliro_reader_verification_key,
            self.aliro_reader_group_identifier,
        ])
        return interaction_model.StatusCode.SUCCESS
