import collections
import logging
import typing
from . import interaction_model, cluster
from .. import device
from ..encoding import protocol_messages

DeviceType = collections.namedtuple("DeviceType", ["id", "revision"])
logger = logging.getLogger(__name__)

class Endpoint:
    DEVICE_TYPES: typing.Set[DeviceType] = {}

    unique_id: str
    parts: typing.Set[int]
    servers: typing.Dict[int, cluster.Cluster]
    clients: typing.Dict[int, cluster.Cluster]

    def __init__(self, unique_id: str):
        self.unique_id = unique_id
        self.parts = set()
        self.servers = {}
        self.clients = {}
        self.endpoint_id = None
        self.interaction_model = None
        self.device_state = None

        self.add_server(Descriptor(self))
        self.add_server(Identify(self))

    def add_server(self, c: cluster.Cluster):
        self.servers[c.cluster_id] = c

    def register_im(self, endpoint_id: int, im: interaction_model.InteractionModel, device_state: device.DeviceState):
        self.endpoint_id = endpoint_id
        self.interaction_model = im
        self.device_state = device_state
        for c in self.servers.values():
            c.register_im(endpoint_id, im, device_state)


class Descriptor(cluster.Cluster):
    cluster_id = 0x001D
    cluster_revision_number = 3

    device_type_list = cluster.Attribute(0x0000, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    server_list = cluster.Attribute(0x0001, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    client_list = cluster.Attribute(0x0002, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    parts_list = cluster.Attribute(0x0003, cluster.RWAccess.Read, cluster.Privileges.View)
    tag_list = cluster.Attribute(0x0004, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)
    endpoint_unique_id = cluster.Attribute(0x0005, cluster.RWAccess.Read, cluster.Privileges.View, f_fixed=True)

    def __init__(self, endpoint: Endpoint):
        super().__init__()
        self._endpoint = endpoint

    @device_type_list.reader
    def read_device_type_list(self):
        return [protocol_messages.DeviceTypeStruct(
            device_type=t.id,
            revision=t.revision,
        ) for t in self._endpoint.DEVICE_TYPES]

    @server_list.reader
    def read_server_list(self):
        return list(self._endpoint.servers.keys())

    @client_list.reader
    def read_client_list(self):
        return list(self._endpoint.clients.keys())

    @parts_list.reader
    def read_parts_list(self):
        return list(self._endpoint.parts)

    @tag_list.reader
    def read_tag_list(self):
        return []

    @endpoint_unique_id.reader
    def read_endpoint_unique_id(self):
        return self._endpoint.unique_id


class Identify(cluster.Cluster):
    cluster_id = 0x0003
    cluster_revision_number = 6

    identify_time = cluster.Attribute(0x000, cluster.RWAccess.ReadWrite, cluster.Privileges.View, cluster.Privileges.Operate, q_quieter_reporting=True)
    identity_type = cluster.Attribute(0x0001, cluster.RWAccess.Read, cluster.Privileges.View)
    identify = cluster.Command(0x0000, None, cluster.Privileges.Manage)

    def __init__(self, endpoint: Endpoint):
        super().__init__()
        self._endpoint = endpoint

    @identify_time.reader
    def read_identify_time(self):
        return 0

    @identify_time.writer
    def write_identify_time(self, value: int):
        if value != 0:
            logger.info(f"IDENTIFY: {self._endpoint.unique_id}")

    @identity_type.reader
    def read_identity_type(self):
        return protocol_messages.IdentifyTypeEnumEnum.NoIndication.value

    @identify.handler
    def handle_identify(self, req: protocol_messages.IdentifyRequest):
        if req.identify_time != 0:
            logger.info(f"IDENTIFY: {self._endpoint.unique_id}")