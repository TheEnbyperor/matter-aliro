import dataclasses
import enum
import typing
from . import cluster, endpoint
from ..crypto import certs

class AuthenticationMode(enum.Enum):
    NoAuth = enum.auto()
    PASE = enum.auto()
    CASE = enum.auto()
    Group = enum.auto()

@dataclasses.dataclass
class ACLTarget:
    cluster: typing.Optional[int]
    endpoint: typing.Optional[int]
    device_type: typing.Optional[int]

@dataclasses.dataclass
class ACLEntry:
    fabric_index: int
    privilege_level: cluster.Privileges
    authentication_mode: AuthenticationMode
    subjects: typing.List[int]
    targets: typing.List[ACLTarget]

@dataclasses.dataclass
class ISD:
    is_commissioning: bool
    authentication_mode: AuthenticationMode
    node_id: int
    cats: typing.List[certs.CAT]
    fabric_index: int

def add_granted_privilege(granted_privileges: typing.Set[cluster.Privileges], privilege: cluster.Privileges):
    granted_privileges.add(privilege)
    if privilege == cluster.Privileges.Operate:
        granted_privileges.add(cluster.Privileges.View)
    elif privilege == cluster.Privileges.Manage:
        granted_privileges.add(cluster.Privileges.Operate)
        granted_privileges.add(cluster.Privileges.View)
    elif privilege == cluster.Privileges.Administer:
        granted_privileges.add(cluster.Privileges.Manage)
        granted_privileges.add(cluster.Privileges.Operate)
        granted_privileges.add(cluster.Privileges.View)

def get_granted_privileges(acl: typing.List[ACLEntry], subject_desc: ISD, endpoint_id: int, cluster_id: int, device_types: typing.Set[endpoint.DeviceType]) -> typing.Set[cluster.Privileges]:
    device_types = {dt.id for dt in device_types}
    granted_privileges = set()

    # PASE commissioning channel implicitly grants administer privilege to commissioner
    if subject_desc.authentication_mode == AuthenticationMode.PASE and subject_desc.is_commissioning:
        add_granted_privilege(granted_privileges, cluster.Privileges.Administer)

    for acl_entry in acl:
        # End checking if highest privilege is granted
        if cluster.Privileges.Administer in granted_privileges:
            break

        # FabricIndex must match, there are no valid entries with FabricIndex == 0
        # other than the implicit PASE entry, which we will not see explicitly in the
        # access control list
        if acl_entry.fabric_index == 0:
            continue
        if acl_entry.fabric_index != subject_desc.fabric_index:
            continue

        # Auth mode must match
        if acl_entry.authentication_mode != subject_desc.authentication_mode:
            continue

        # Subject must match, or be "wildcard"
        if len(acl_entry.subjects) != 0:
            # Non-empty requires a match
            matched_subject = False
            for acl_subject in acl_entry.subjects:
                if acl_subject == subject_desc.node_id:
                    matched_subject = True
                    break

                if 0xFFFF_FFFD_0000_0000 <= acl_subject <= 0xFFFF_FFFD_FFFF_FFFF:
                    acl_subject_cat_id = (acl_subject >> 16) & 0xFFFF
                    acl_subject_cat_version = acl_subject & 0xFFFF

                    for cat in subject_desc.cats:
                        if cat.id == acl_subject_cat_id and acl_subject_cat_version >= cat.version:
                            matched_subject = True
                            break

                if matched_subject:
                    break
            if not matched_subject:
                continue

        # Target must match, or be "wildcard"
        if len(acl_entry.targets) != 0:
            # Non-empty requires a match
            matched_target = False
            for target in acl_entry.targets:
                # Precondition: target cannot be empty
                assert (target.cluster is not None or target.endpoint is not None or target.device_type is not None)
                # Precondition: target cannot specify both endpoint and device type
                assert (target.endpoint is None or target.device_type is None)
                # Cluster must match, or be wildcard
                if target.cluster is not None and target.cluster != cluster_id:
                    continue
                # Endpoint must match, or be wildcard
                if target.endpoint is not None and target.endpoint != endpoint_id:
                    continue

                # Endpoint may be specified indirectly via device type
                if target.device_type is not None and target.device_type not in device_types:
                    continue

                matched_target = True
                break
            if not matched_target:
                continue

        add_granted_privilege(granted_privileges, acl_entry.privilege_level)

    return granted_privileges
