import asyncio
import logging
import time
import typing
import cryptography.x509
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.utils
from . import endpoint, cluster, interaction_model, acl
from .. import device, message, mdns, crypto
from ..encoding import tlv
from ..crypto import certs
from ..encoding import protocol_messages
from ..mdns import MDNS

logger = logging.getLogger(__name__)

class RootNode(endpoint.Endpoint):
    DEVICE_TYPES = {endpoint.DeviceType(id=0x0016, revision=4)}

    def __init__(self, unique_id: str, state: device.DeviceState, layer: message.MessageLayer, dns: mdns.MDNS):
        super().__init__(unique_id)

        self.access_control = AccessControl(state)
        self.basic_information = BasicInformation(state)
        self.general_commissioning = GeneralCommissioning(state, layer)
        self.network_commissioning = NetworkCommissioning()
        self.administrator_commissioning = AdministratorCommissioning(state, layer)
        self.operational_credentials = OperationalCredentials(state, layer, dns)

        self.add_server(self.access_control)
        self.add_server(self.basic_information)
        self.add_server(self.general_commissioning)
        self.add_server(self.network_commissioning)
        # TODO: general diagnostics 0x0033
        self.add_server(self.administrator_commissioning)
        self.add_server(self.operational_credentials)
        # TODO: group key management 0x003F

class AccessControl(cluster.Cluster):
    cluster_id = 0x001F
    cluster_revision_number = 2
    features = [0]

    acl = cluster.ListAttribute(0x0000, cluster.RWAccess.ReadWrite, cluster.Privileges.Administer)
    extension = cluster.ListAttribute(0x0001, cluster.RWAccess.ReadWrite, cluster.Privileges.Administer)
    subjects_per_access_control_entry = cluster.Attribute(0x0002, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    targets_per_access_control_entry = cluster.Attribute(0x0003, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    access_control_entries_per_fabric = cluster.Attribute(0x0004, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)

    access_control_entry_changed = cluster.Event(0x0000, cluster.EventPriority.INFO, cluster.Privileges.Administer)
    access_control_extensions_changed = cluster.Event(0x0001, cluster.EventPriority.INFO, cluster.Privileges.Administer)

    def __init__(self, device_state: device.DeviceState):
        super().__init__()
        self.device_state = device_state

    @acl.reader
    def read_acl(self, session: message.SessionContext):
        out = []
        for entry in filter(lambda e: e.fabric_index == session.local_fabric_index, self.device_state.acl):
            if entry.privilege_level == cluster.Privileges.Administer:
                privilege = protocol_messages.AccessControlEntryPrivilegeEnumEnum.Administer.value
            elif entry.privilege_level == cluster.Privileges.Manage:
                privilege = protocol_messages.AccessControlEntryPrivilegeEnumEnum.Manage.value
            elif entry.privilege_level == cluster.Privileges.Operate:
                privilege = protocol_messages.AccessControlEntryPrivilegeEnumEnum.Operate.value
            elif entry.privilege_level == cluster.Privileges.View:
                privilege = protocol_messages.AccessControlEntryPrivilegeEnumEnum.View.value
            else:
                continue

            if entry.authentication_mode == acl.AuthenticationMode.PASE:
                auth_mode = protocol_messages.AccessControlEntryAuthModeEnumEnum.PASE.value
            elif entry.authentication_mode == acl.AuthenticationMode.CASE:
                auth_mode = protocol_messages.AccessControlEntryAuthModeEnumEnum.CASE.value
            elif entry.authentication_mode == acl.AuthenticationMode.Group:
                auth_mode = protocol_messages.AccessControlEntryAuthModeEnumEnum.Group.value
            else:
                continue

            out.append(protocol_messages.AccessControlEntryStruct(
                privilege=privilege,
                auth_mode=auth_mode,
                subjects=entry.subjects or tlv.Null(),
                targets=[protocol_messages.AccessControlTargetStruct(
                    cluster=t.cluster if t.cluster is not None else tlv.Null(),
                    endpoint=t.endpoint if t.endpoint is not None else tlv.Null(),
                    device_type=t.device_type if t.device_type is not None else tlv.Null(),
                ) for t in entry.targets] or tlv.Null(),
            ))

        return out

    @acl.list_replacer
    def replace_acl(self, data: typing.List[protocol_messages.AccessControlEntryStruct], session: message.SessionContext):
        new_entries = []
        for entry in data:
            if entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.Administer.value:
                privilege_level = cluster.Privileges.Administer
            elif entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.Manage.value:
                privilege_level = cluster.Privileges.Manage
            elif entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.Operate.value:
                privilege_level = cluster.Privileges.Operate
            elif entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.View.value:
                privilege_level = cluster.Privileges.View
            else:
                return interaction_model.StatusCode.CONSTRAINT_ERROR
            if entry.auth_mode == protocol_messages.AccessControlEntryAuthModeEnumEnum.PASE.value:
                authentication_mode = acl.AuthenticationMode.PASE
            elif entry.auth_mode == protocol_messages.AccessControlEntryAuthModeEnumEnum.CASE.value:
                authentication_mode = acl.AuthenticationMode.CASE
            elif entry.auth_mode == protocol_messages.AccessControlEntryAuthModeEnumEnum.Group.value:
                authentication_mode = acl.AuthenticationMode.Group
            else:
                return interaction_model.StatusCode.CONSTRAINT_ERROR

            new_entries.append(acl.ACLEntry(
                fabric_index=session.local_fabric_index,
                privilege_level=privilege_level,
                authentication_mode=authentication_mode,
                subjects=entry.subjects or [],
                targets=[acl.ACLTarget(
                    endpoint=t.endpoint or None,
                    cluster=t.cluster or None,
                    device_type=t.device_type or None,
                ) for t in entry.targets] if entry.targets else [],
            ))

        self.device_state.acl = list(filter(lambda a: a.fabric_index != session.local_fabric_index, self.device_state.acl)) + new_entries
        self.increment_data_version()
        self.attributes_changed([self.acl])
        self.device_state.save_state()
        return interaction_model.StatusCode.SUCCESS

    @acl.list_adder
    def add_acl(self, data: typing.List[protocol_messages.AccessControlEntryStruct], session: message.SessionContext):
        new_entries = []
        for entry in data:
            if entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.Administer.value:
                privilege_level = cluster.Privileges.Administer
            elif entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.Manage.value:
                privilege_level = cluster.Privileges.Manage
            elif entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.Operate.value:
                privilege_level = cluster.Privileges.Operate
            elif entry.privilege == protocol_messages.AccessControlEntryPrivilegeEnumEnum.View.value:
                privilege_level = cluster.Privileges.View
            else:
                return interaction_model.StatusCode.CONSTRAINT_ERROR
            if entry.auth_mode == protocol_messages.AccessControlEntryAuthModeEnumEnum.PASE.value:
                authentication_mode = acl.AuthenticationMode.PASE
            elif entry.auth_mode == protocol_messages.AccessControlEntryAuthModeEnumEnum.CASE.value:
                authentication_mode = acl.AuthenticationMode.CASE
            elif entry.auth_mode == protocol_messages.AccessControlEntryAuthModeEnumEnum.Group.value:
                authentication_mode = acl.AuthenticationMode.Group
            else:
                return interaction_model.StatusCode.CONSTRAINT_ERROR

            new_entries.append(acl.ACLEntry(
                fabric_index=session.local_fabric_index,
                privilege_level=privilege_level,
                authentication_mode=authentication_mode,
                subjects=entry.subjects or [],
                targets=[acl.ACLTarget(
                    endpoint=t.endpoint or None,
                    cluster=t.cluster or None,
                    device_type=t.device_type or None,
                ) for t in entry.targets] if entry.targets else [],
            ))

        self.device_state.acl += new_entries
        self.increment_data_version()
        self.attributes_changed([self.acl])
        self.device_state.save_state()
        return interaction_model.StatusCode.SUCCESS

    @extension.list_replacer
    def replace_extensions(self, data: typing.List[protocol_messages.AccessControlExtensionStruct]):
        print("Replace ACL extensions", data)
        return interaction_model.StatusCode.SUCCESS

    @extension.list_adder
    def add_extensions(self, data: typing.List[protocol_messages.AccessControlExtensionStruct]):
        print("Add ACL extension", data)
        return interaction_model.StatusCode.SUCCESS

    @subjects_per_access_control_entry.reader
    def read_subjects_per_access_control_entry(self):
        return 65535

    @targets_per_access_control_entry.reader
    def read_targets_per_access_control_entry(self):
        return 65535

    @access_control_entries_per_fabric.reader
    def read_access_control_entries_per_fabric(self):
        return 65535

class BasicInformation(cluster.Cluster):
    cluster_id = 0x0028
    cluster_revision_number = 5

    data_model_revision = cluster.Attribute(0x0000, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    vendor_name = cluster.Attribute(0x0001, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    vendor_id = cluster.Attribute(0x0002, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    product_name = cluster.Attribute(0x0003, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    product_id = cluster.Attribute(0x0004, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    node_label = cluster.Attribute(
        0x0005, cluster.RWAccess.ReadWrite, cluster.Privileges.View, cluster.Privileges.Manage,
        n_nonvolatile=True
    )
    location = cluster.Attribute(
        0x0006, cluster.RWAccess.ReadWrite, cluster.Privileges.View, cluster.Privileges.Administer,
        n_nonvolatile=True
    )
    hardware_version = cluster.Attribute(0x0007, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    hardware_version_string = cluster.Attribute(0x0008, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    software_version = cluster.Attribute(0x0009, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    software_version_string = cluster.Attribute(0x000A, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    manufacturing_date = cluster.Attribute(0x000B, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    part_number = cluster.Attribute(0x000C, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    product_url = cluster.Attribute(0x000D, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    product_label = cluster.Attribute(0x000E, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    serial_number = cluster.Attribute(0x000F, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    local_config_disabled = cluster.Attribute(
        0x0010, cluster.RWAccess.ReadWrite, cluster.Privileges.View, cluster.Privileges.Manage,
        n_nonvolatile=True
    )
    reachable = cluster.Attribute(0x0011, cluster.RWAccess.Read, cluster.Privileges.View)
    unique_id = cluster.Attribute(0x0012, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    capability_minima = cluster.Attribute(0x0013, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    product_appearance = cluster.Attribute(0x0014, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    specification_version = cluster.Attribute(0x0015, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    max_paths_per_invoke = cluster.Attribute(0x0016, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    configuration_version = cluster.Attribute(
        0x0018, cluster.RWAccess.Read, cluster.Privileges.View, n_nonvolatile=True
    )

    startup = cluster.Event(0x0000, cluster.EventPriority.CRITICAL, cluster.Privileges.View)

    def __init__(self, device_state: device.DeviceState):
        super().__init__()
        self.device_state = device_state

    @data_model_revision.reader
    def read_data_model_revision(self):
        return 19

    @vendor_name.reader
    def read_vendor_name(self):
        return self.device_state.meta.vendor_name

    @vendor_id.reader
    def read_vendor_id(self):
        return self.device_state.meta.vendor_id

    @product_name.reader
    def read_product_name(self):
        return self.device_state.meta.product_name

    @product_id.reader
    def read_product_id(self):
        return self.device_state.meta.product_id

    @node_label.reader
    def read_node_label(self):
        return self.device_state.meta.device_name

    @location.reader
    def read_location(self):
        return self.device_state.country_code

    @hardware_version.reader
    def read_hardware_version(self):
        return self.device_state.meta.hardware_version

    @hardware_version_string.reader
    def read_hardware_version_string(self):
        return self.device_state.meta.hardware_version_string

    @software_version.reader
    def read_software_version(self):
        return self.device_state.meta.software_version

    @software_version_string.reader
    def read_software_version_string(self):
        return self.device_state.meta.software_version_string

    @serial_number.reader
    def read_serial_number(self):
        return self.device_state.meta.serial_number

    @unique_id.reader
    def read_unique_id(self):
        return self.device_state.meta.unique_id

    @capability_minima.reader
    def read_capability_minima(self):
        return protocol_messages.CapabilityMinimaStruct(
            case_sessions_per_fabric=65535,
            subscriptions_per_fabric=65535
        )

    @specification_version.reader
    def read_specification_version(self):
        return 0x01050000

    @max_paths_per_invoke.reader
    def read_max_paths_per_invoke(self):
        return 65535

    @configuration_version.reader
    def read_configuration_version(self):
        return 1

    def startup_complete(self):
        self.report_event(self.startup, protocol_messages.StartUpEvent(
            software_version=0
        ))


class GeneralCommissioning(cluster.Cluster):
    cluster_id = 0x0030
    cluster_revision_number = 1

    breadcrumb = cluster.Attribute(
        0x0000, cluster.RWAccess.ReadWrite, cluster.Privileges.View, cluster.Privileges.Administer
    )
    basic_commissioning_info = cluster.Attribute(0x0001, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    regulatory_config = cluster.Attribute(0x0002, cluster.RWAccess.Read, cluster.Privileges.View)
    location_capability = cluster.Attribute(0x0003, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    supports_concurrent_connection = cluster.Attribute(
        0x0004, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True
    )
    is_commissioning_without_power = cluster.Attribute(0x000C, cluster.RWAccess.Read, cluster.Privileges.View)

    arm_fail_safe = cluster.Command(0x0000, 0x0001, cluster.Privileges.Administer)
    set_regulatory_config = cluster.Command(0x0002, 0x0003, cluster.Privileges.Administer)
    commissioning_complete = cluster.Command(0x0004, 0x0005, cluster.Privileges.Administer)

    def __init__(self, device_state: device.DeviceState, ml: message.MessageLayer):
        super().__init__()
        self.device_state = device_state
        self.message_layer = ml
        self._breadcrumb = 0

    @breadcrumb.reader
    def read_breadcrumb(self):
        return self._breadcrumb

    @breadcrumb.writer
    def set_breadcrumb(self, value):
        self._breadcrumb = value
        self.increment_data_version()
        self.attributes_changed([self.breadcrumb])

    @basic_commissioning_info.reader
    def read_basic_commissioning_info(self):
        return protocol_messages.BasicCommissioningInfo(
            fail_safe_expiry_length_seconds=60,
            max_cumulative_failsafe_seconds=900
        )

    @regulatory_config.reader
    def read_regulatory_config(self):
        return protocol_messages.RegulatoryLocationEnum.Indoor

    @location_capability.reader
    def read_location_capability(self):
        return protocol_messages.RegulatoryLocationEnum.Indoor

    @supports_concurrent_connection.reader
    def read_supports_concurrent_connection(self):
        return True

    @is_commissioning_without_power.reader
    def read_is_commissioning_without_power(self):
        return False

    @arm_fail_safe.handler
    def handle_arm_fail_safe(self, data: protocol_messages.ArmFailSafe) -> protocol_messages.ArmFailSafeResponse:
        logger.debug(f"Arm fail safe: {data}")
        self._breadcrumb = data.breadcrumb
        self.increment_data_version()
        self.attributes_changed([self.breadcrumb])
        return protocol_messages.ArmFailSafeResponse(
            error_code=protocol_messages.CommissioningErrorEnum.OK,
            debug_text=""
        )

    @set_regulatory_config.handler
    def handle_set_regulatory_config(
            self, data: protocol_messages.SetRegulatoryConfig
    ) -> protocol_messages.SetRegulatoryConfigResponse:
        logger.debug(f"Set regulatory config: {data}")
        if data.new_regulatory_config != protocol_messages.RegulatoryLocationEnum.Indoor.value:
            return protocol_messages.SetRegulatoryConfigResponse(
                error_code=protocol_messages.CommissioningErrorEnum.ValueOutsideRange,
                debug_text=""
            )

        self.device_state.country_code = data.country_code
        self._breadcrumb = data.breadcrumb
        self.increment_data_version()
        self.attributes_changed([self.breadcrumb])
        self.device_state.save_state()

        return protocol_messages.SetRegulatoryConfigResponse(
            error_code=protocol_messages.CommissioningErrorEnum.OK,
            debug_text=""
        )

    @commissioning_complete.handler
    def handle_commissioning_complete(self, data: None, session: message.SessionContext) -> protocol_messages.CommissioningCompleteResponse:
        if not session.local_fabric_index or not isinstance(session, message.SecureSessionContext) or session.session_type != message.SecureSessionType.CASE:
            return protocol_messages.CommissioningCompleteResponse(
                error_code=protocol_messages.CommissioningErrorEnum.InvalidAuthentication,
                debug_text=""
            )

        logger.info("Commissioning complete")

        self.device_state.in_commissioning_mode = False
        self._breadcrumb = 0
        self.message_layer.terminate_all_pase_sessions()
        self.increment_data_version()
        self.attributes_changed([self.breadcrumb])
        self.device_state.save_state()

        return protocol_messages.CommissioningCompleteResponse(
            error_code=protocol_messages.CommissioningErrorEnum.OK,
            debug_text=""
        )


class NetworkCommissioning(cluster.Cluster):
    cluster_id = 0x0031
    cluster_revision_number = 2
    features = [2]

    max_networks = cluster.Attribute(0x0000, cluster.RWAccess.Read, cluster.Privileges.Administer, f_fixed=True)
    networks = cluster.ListAttribute(0x0001, cluster.RWAccess.Read, cluster.Privileges.Administer)
    interface_enabled = cluster.Attribute(
        0x0004, cluster.RWAccess.ReadWrite, cluster.Privileges.View, cluster.Privileges.Administer,
        n_nonvolatile=True
    )
    last_networking_status = cluster.Attribute(0x0005, cluster.RWAccess.Read, cluster.Privileges.Administer, x_nullable=True)
    last_network_id = cluster.Attribute(0x0006, cluster.RWAccess.Read, cluster.Privileges.Administer, x_nullable=True)
    last_connect_error_value = cluster.Attribute(0x0007, cluster.RWAccess.Read, cluster.Privileges.Administer, x_nullable=True)

    @max_networks.reader
    def read_max_networks(self):
        return 1

    @networks.reader
    def read_networks(self):
        return [protocol_messages.NetworkInfoStruct(
            network_id=b"native",
            connected=True
        )]

    @interface_enabled.reader
    def read_interface_enabled(self):
        return True

    @last_networking_status.reader
    def read_last_networking_status(self):
        return 0

    @last_network_id.reader
    def read_last_network_id(self):
        return b"native"

    @last_connect_error_value.reader
    def read_last_connect_error_value(self):
        return None


class AdministratorCommissioning(cluster.Cluster):
    cluster_id = 0x003C
    cluster_revision_number = 1

    window_status = cluster.Attribute(0x0000, cluster.RWAccess.Read, cluster.Privileges.View)
    admin_fabric_index = cluster.Attribute(0x0001, cluster.RWAccess.Read, cluster.Privileges.View, x_nullable=True)
    admin_vendor_id = cluster.Attribute(0x0002, cluster.RWAccess.Read, cluster.Privileges.View, x_nullable=True)

    open_commissioning_window = cluster.Command(0x0000, None, cluster.Privileges.Administer, t_timed=True)
    open_basic_commissioning_window = cluster.Command(0x0001, None, cluster.Privileges.Administer, t_timed=True)
    revoke_commissioning_window = cluster.Command(0x0002, None, cluster.Privileges.Administer, t_timed=True)

    def __init__(self, device_state: device.DeviceState, ml: message.MessageLayer, dns: mdns.MDNS):
        super().__init__()
        self.device_state = device_state
        self.message_layer = ml
        self.mdns = dns
        self.enhanced_commissioning = False
        self.basic_commissioning = False
        self.current_admin_fabric_index = None
        self.current_admin_vendor_id = None

    @window_status.reader
    def read_window_status(self):
        if self.enhanced_commissioning:
            return protocol_messages.CommissioningWindowStatusEnum.EnhancedWindowOpen
        elif self.basic_commissioning:
            return protocol_messages.CommissioningWindowStatusEnum.EnhancedWindowOpen
        else:
            return protocol_messages.CommissioningWindowStatusEnum.WindowNotOpen

    @admin_fabric_index.reader
    def read_admin_fabric_index(self):
        return self.current_admin_fabric_index

    @admin_vendor_id.reader
    def read_admin_vendor_id(self):
        return self.current_admin_vendor_id

    @open_commissioning_window.handler
    def handle_open_commissioning_window(self, data: protocol_messages.OpenCommissioningWindow, session: message.SessionContext) -> protocol_messages.CommissioningWindowStatusCodeEnum:
        if self.device_state.in_commissioning_mode or self.enhanced_commissioning or self.basic_commissioning:
            return protocol_messages.CommissioningWindowStatusCodeEnum.Busy

        asyncio.create_task(self.cancel_commissioning(data.commissioning_timeout))
        self.message_layer.secure_channel.pbkdf_params = crypto.CryptoPBKDFParameterSet(
            iterations=data.iterations,
            salt=data.salt,
        )
        self.message_layer.secure_channel.pake_values_responder = crypto.CryptoPAKEValuesResponder.from_bytes(data.pake_passcode_verifier)
        self.enhanced_commissioning = True
        self.device_state.in_commissioning_mode = True
        self.device_state.discriminator = data.discriminator
        self.current_admin_fabric_index = session.local_fabric_index
        self.current_admin_vendor_id = self.device_state.fabrics[session.local_fabric_index].admin_vendor_id
        self.increment_data_version()
        self.attributes_changed([self.window_status, self.admin_fabric_index, self.admin_vendor_id])
        asyncio.create_task(self.mdns.send_unsolicited_packets())
        return protocol_messages.CommissioningWindowStatusCodeEnum.Success

    @open_basic_commissioning_window.handler
    def handle_open_basic_commissioning_window(self, data: protocol_messages.OpenBasicCommissioningWindow, session: message.SessionContext) -> protocol_messages.CommissioningWindowStatusCodeEnum:
        if self.device_state.in_commissioning_mode or self.enhanced_commissioning or self.basic_commissioning:
            return protocol_messages.CommissioningWindowStatusCodeEnum.Busy

        asyncio.create_task(self.cancel_commissioning(data.commissioning_timeout))
        self.basic_commissioning = True
        self.device_state.in_commissioning_mode = True
        self.current_admin_fabric_index = session.local_fabric_index
        self.current_admin_vendor_id = self.device_state.fabrics[session.local_fabric_index].admin_vendor_id
        self.increment_data_version()
        self.attributes_changed([self.window_status, self.admin_fabric_index, self.admin_vendor_id])
        asyncio.create_task(self.mdns.send_unsolicited_packets())
        return protocol_messages.CommissioningWindowStatusCodeEnum.Success

    @revoke_commissioning_window.handler
    def handle_revoke_commissioning_window(self) -> protocol_messages.CommissioningWindowStatusCodeEnum:
        if not self.enhanced_commissioning and not self.basic_commissioning:
            return protocol_messages.CommissioningWindowStatusCodeEnum.WindowNotOpen
        asyncio.create_task(self.cancel_commissioning())
        return protocol_messages.CommissioningWindowStatusCodeEnum.Success

    async def cancel_commissioning(self, delay: typing.Optional[float] = None):
        if delay is not None:
            await asyncio.sleep(delay)

        if not self.enhanced_commissioning and not self.basic_commissioning:
            return

        self.message_layer.secure_channel.pbkdf_params = self.message_layer.secure_channel.basic_pbkdf_params
        self.message_layer.secure_channel.pake_values_responder = self.message_layer.secure_channel.basic_pake_values_responder
        self.device_state.in_commissioning_mode = False
        self.device_state.discriminator = self.device_state.basic_discriminator
        self.basic_commissioning = False
        self.enhanced_commissioning = False
        self.current_admin_fabric_index = None
        self.current_admin_vendor_id = None
        self.increment_data_version()
        self.attributes_changed([self.window_status, self.admin_fabric_index, self.admin_vendor_id])


class OperationalCredentials(cluster.Cluster):
    cluster_id = 0x003E
    cluster_revision_number = 2

    nocs = cluster.ListAttribute(
        0x0000, cluster.RWAccess.Read, cluster.Privileges.Administer,
        c_changes_omitted=True, n_nonvolatile=True
    )
    fabrics = cluster.ListAttribute(
        0x0001, cluster.RWAccess.Read, cluster.Privileges.View, n_nonvolatile=True
    )
    supported_fabrics = cluster.Attribute(
        0x0002, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True
    )
    commissioned_fabrics = cluster.Attribute(
        0x0003, cluster.RWAccess.Read, cluster.Privileges.View, n_nonvolatile=True
    )
    trusted_root_certificates = cluster.ListAttribute(
        0x0004, cluster.RWAccess.Read, cluster.Privileges.View,
        c_changes_omitted=True, n_nonvolatile=True
    )
    current_fabric_index = cluster.Attribute(0x0005, cluster.RWAccess.Read, cluster.Privileges.View)

    attestation_request = cluster.Command(0x0000, 0x0001, cluster.Privileges.Administer)
    certificate_chain_request = cluster.Command(0x0002, 0x0003, cluster.Privileges.Administer)
    csr_request = cluster.Command(0x0004, 0x0005, cluster.Privileges.Administer)
    add_noc = cluster.Command(0x0006, 0x0008, cluster.Privileges.Administer)
    update_noc = cluster.Command(0x0007, 0x0008, cluster.Privileges.Administer)
    update_fabric_label = cluster.Command(0x0009, 0x0008, cluster.Privileges.Administer)
    remove_fabric = cluster.Command(0x000A, 0x0008, cluster.Privileges.Administer)
    add_trusted_root_certificate = cluster.Command(0x000B, None, cluster.Privileges.Administer)
    set_vid_verification_statement = cluster.Command(0x000C, None, cluster.Privileges.Administer)
    sign_vid_verification_request = cluster.Command(0x000D, 0x000E, cluster.Privileges.Administer)

    def __init__(self, device_state: device.DeviceState, ml: message.MessageLayer, dns: mdns.MDNS):
        super().__init__()
        self.device_state = device_state
        self.message_layer = ml
        self.mdns = dns
        self.candidate_operational_key = None
        self.candidate_root_ca = None
        self.candidate_fabric_idx = None

    @nocs.reader
    def read_nocs(self):
        return [protocol_messages.NOCStruct(
            NOC=fabric.noc,
            ICAC=fabric.icac,
            VVSC=None
        ) for fabric in self.device_state.fabrics.values()]

    @fabrics.reader
    def read_fabrics(self):
        return [protocol_messages.FabricDescriptorStruct(
            root_public_key=fabric.root_public_key.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.X962,
                cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
            ),
            vendor_id=fabric.admin_vendor_id,
            fabric_id=fabric.fabric_id,
            node_id=fabric.node_id,
            label=fabric.label,
            vid_verification_statement=None
        ) for fabric in self.device_state.fabrics.values()]

    @supported_fabrics.reader
    def read_supported_fabrics(self):
        return 254

    @commissioned_fabrics.reader
    def read_commissioned_fabrics(self):
        return len(self.device_state.fabrics)

    @trusted_root_certificates.reader
    def read_trusted_root_certificates(self):
        return [fabric.rcac for fabric in self.device_state.fabrics.values()]

    @current_fabric_index.reader
    def read_current_fabric_index(self, session: message.SessionContext):
        return session.local_fabric_index

    def sign_attestation(self, data: bytes, session: message.SessionContext):
        attestation_tbs = bytearray(data)
        attestation_tbs.extend(session.attestation_challenge)

        attestation_signature = self.device_state.dac_key.sign(
            attestation_tbs,
            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA256()
            )
        )
        r, s = cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature(attestation_signature)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    @attestation_request.handler
    def handle_attestation_request(
            self, data: protocol_messages.AttestationRequest, session: message.SessionContext
    ) -> protocol_messages.AttestationResponse:
        attestation_elements = protocol_messages.AttestationElements(
            certification_declaration=b"",
            timestamp=int(time.time()),
            attestation_nonce=data.attestation_nonce,
            firmware_information=None
        ).encode_to_bytes()
        attestation_signature = self.sign_attestation(attestation_elements, session)
        return protocol_messages.AttestationResponse(
            attestation_elements=attestation_elements,
            attestation_signature=attestation_signature,
        )

    @certificate_chain_request.handler
    def handle_certificate_chain_request(
            self, data: protocol_messages.CertificateChainRequest
    ) -> typing.Union[protocol_messages.CertificateChainResponse, interaction_model.StatusCode]:
        if data.certificate_type == protocol_messages.CertificateTypeEnum.DACCertificate.value:
            return protocol_messages.CertificateChainResponse(
                certificate=self.device_state.dac_cert.public_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.DER
                )
            )
        elif data.certificate_type == protocol_messages.CertificateTypeEnum.PAICertificate.value:
            return protocol_messages.CertificateChainResponse(
                certificate=self.device_state.pai_cert.public_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.DER
                )
            )
        else:
            return interaction_model.StatusCode.INVALID_COMMAND

    @csr_request.handler
    def handle_certificate_request(
            self, data: protocol_messages.CSRRequest, session: message.SessionContext
    ) -> protocol_messages.CSRResponse:
        pkey = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
        )
        csr = cryptography.x509.CertificateSigningRequestBuilder() \
            .subject_name(cryptography.x509.Name([])) \
            .sign(pkey, algorithm=cryptography.hazmat.primitives.hashes.SHA256(), ecdsa_deterministic=True)

        nocsr_elements = protocol_messages.NocsrElements(
            csr=csr.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER),
            csr_nonce=data.csr_nonce,
            vendor_reserved1=None,
            vendor_reserved2=None,
            vendor_reserved3=None,
        ).encode_to_bytes()
        attestation_signature = self.sign_attestation(nocsr_elements, session)
        self.candidate_operational_key = pkey
        return protocol_messages.CSRResponse(
            nocsr_elements=nocsr_elements,
            attestation_signature=attestation_signature
        )

    @add_noc.handler
    def handle_add_noc(
            self, data: protocol_messages.AddNOC, session: message.SessionContext
    ) -> protocol_messages.NOCResponse:
        if not self.candidate_operational_key:
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.MissingCsr,
                fabric_index=None,
                debug_text=""
            )
        if not self.candidate_root_ca:
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.InvalidNOC,
                fabric_index=None,
                debug_text=""
            )

        noc_cert = protocol_messages.MatterCertificate.decode_from_bytes(data.noc_value)
        if data.icac_value:
            icac_cert = protocol_messages.MatterCertificate.decode_from_bytes(data.icac_value)
        else:
            icac_cert = None

        if not certs.verify_noc_dn(noc_cert):
            logger.warning("Invalid NOC DN")
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.InvalidNOC,
                fabric_index=None,
                debug_text=""
            )

        if icac_cert and not certs.verify_icac_dn(icac_cert):
            logger.warning("Invalid ICAC DN")
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.InvalidNOC,
                fabric_index=None,
                debug_text=""
            )

        if not certs.verify_rcac_dn(self.candidate_root_ca):
            logger.warning("Invalid RCAC DN")
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.InvalidNOC,
                fabric_index=None,
                debug_text=""
            )

        cert_chain = [noc_cert, icac_cert, self.candidate_root_ca] if icac_cert else [noc_cert, self.candidate_root_ca]
        if not certs.verify_chain(cert_chain):
            logger.warning("Certificate chain is invalid")
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.InvalidNOC,
                fabric_index=None,
                debug_text=""
            )

        if noc_cert.ec_pub_key != self.candidate_operational_key.public_key().public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.X962,
                cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
        ):
            logger.warning("Wrong public key on NOC")
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.InvalidPublicKey,
                fabric_index=None,
                debug_text=""
            )

        fabric_idx = None
        for i in range(1, 254):
            if i not in self.device_state.fabrics:
                fabric_idx = i
                break

        if not fabric_idx:
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.TableFull,
                fabric_index=None,
                debug_text=""
            )
        else:
            root_public_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
                self.candidate_root_ca.ec_pub_key,
            )
            fabric_id = next(filter(lambda a: a.variant == "matter-fabric-id", noc_cert.subject)).value
            node_id = next(filter(lambda a: a.variant == "matter-node-id", noc_cert.subject)).value

            self.candidate_fabric_idx = fabric_idx
            if session.local_fabric_index == 0:
                session.local_fabric_index = fabric_idx
            fabric = device.Fabric(
                root_public_key=root_public_key,
                admin_vendor_id=data.admin_vendor_id,
                operational_private_key=self.candidate_operational_key,
                fabric_id=fabric_id,
                node_id=node_id,
                noc=data.noc_value,
                icac=data.icac_value or None,
                rcac=self.candidate_root_ca,
                ipk=data.ipk_value,
            )
            self.device_state.fabrics[fabric_idx] = fabric
            self.device_state.acl.append(acl.ACLEntry(
                fabric_index=fabric_idx,
                privilege_level=cluster.Privileges.Administer,
                authentication_mode=acl.AuthenticationMode.CASE,
                subjects=[data.case_admin_subject],
                targets=[],
            ))
            asyncio.create_task(self.mdns.send_unsolicited_fabric_packets(fabric_idx))
            self.increment_data_version()
            self.attributes_changed([
                self.nocs, self.fabrics, self.commissioned_fabrics,
                self.trusted_root_certificates, self.current_fabric_index
            ])
            logger.info(f"Provisioned on Fabric as {fabric.instance_name}")
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.OK,
                fabric_index=fabric_idx,
                debug_text=""
            )

    @add_trusted_root_certificate.handler
    def handle_add_trusted_root_certificate(
            self, data: protocol_messages.AddTrustedRootCertificate,
    ) -> interaction_model.StatusCode:
        root_cert = protocol_messages.MatterCertificate.decode_from_bytes(data.root_ca_certificate)
        self.candidate_root_ca = root_cert
        return interaction_model.StatusCode.SUCCESS

    @update_fabric_label.handler
    def handle_update_fabric_label(
            self, data: protocol_messages.UpdateFabricLabel, session: message.SessionContext
    ) -> protocol_messages.NOCResponse:
        for idx, fabric in self.device_state.fabrics.items():
            if fabric.label == data.label and idx != session.local_fabric_index:
                return protocol_messages.NOCResponse(
                    status_code=protocol_messages.NodeOperationalCertStatusEnum.LabelConflict,
                    fabric_index=None,
                    debug_text=""
                )

        self.device_state.fabrics[session.local_fabric_index].label = data.label
        self.increment_data_version()
        self.attributes_changed([self.fabrics])
        self.device_state.save_state()
        return protocol_messages.NOCResponse(
            status_code=protocol_messages.NodeOperationalCertStatusEnum.OK,
            fabric_index=None,
            debug_text=""
        )

    @remove_fabric.handler
    def handle_remove_fabric(
            self, data: protocol_messages.RemoveFabric,
    ) -> protocol_messages.NOCResponse:
        if data.fabric_index not in self.device_state.fabrics:
            return protocol_messages.NOCResponse(
                status_code=protocol_messages.NodeOperationalCertStatusEnum.InvalidFabricIndex,
                fabric_index=data.fabric_index,
                debug_text=""
            )

        del self.device_state.fabrics[data.fabric_index]
        self.device_state.acl = list(filter(lambda a: a.fabric_index != data.fabric_index, self.device_state.acl))
        self.device_state.save_state()

        tbd_id = set()
        tbd_session = set()
        for sid, session in self.message_layer.secure_unicast_session_context.items():
            if session.local_fabric_index == data.fabric_index:
                tbd_id.add(sid)
                tbd_session.add(session)
                asyncio.create_task(self.message_layer.close_secure_unicast_session(session))

        tbd_exchange = set()
        for exchange in self.message_layer.exchanges:
            if exchange.context in tbd_session:
                tbd_exchange.add(exchange)
        self.message_layer.exchanges -= tbd_exchange

        self.message_layer.in_use_session_ids -= tbd_id
        for sid in tbd_id:
            del self.message_layer.secure_unicast_session_context[sid]

        self._interaction_model.cancel_subscriptions_for_fabric(data.fabric_index)

        if len(self.device_state.fabrics) == 0:
            self.device_state.in_commissioning_mode = True

        self.increment_data_version()
        self.attributes_changed([
            self.nocs, self.fabrics, self.commissioned_fabrics,
            self.trusted_root_certificates
        ])

        return protocol_messages.NOCResponse(
            status_code=protocol_messages.NodeOperationalCertStatusEnum.OK,
            fabric_index=data.fabric_index,
            debug_text=""
        )