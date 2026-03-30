import collections
import dataclasses
import enum
import logging
import threading
import typing
import time
import datetime
from . import cluster, endpoint, root_node, acl
from .. import device, mdns
from ..encoding import tlv, protocol_messages
from ..message import protocol, message_layer, messages

INTERACTION_MODEL_REVISION = 12

logger = logging.getLogger(__name__)


class StatusCodeType(enum.IntEnum):
    pass


class StatusCode(StatusCodeType):
    SUCCESS = 0x00
    FAILURE = 0x01
    INVALID_SUBSCRIPTION = 0x7D
    UNSUPPORTED_ACCESS = 0x7E
    UNSUPPORTED_ENDPOINT = 0x7F
    INVALID_ACTION = 0x80
    UNSUPPORTED_COMMAND = 0x81
    INVALID_COMMAND = 0x85
    UNSUPPORTED_ATTRIBUTE = 0x86
    CONSTRAINT_ERROR = 0x87
    UNSUPPORTED_WRITE = 0x88
    RESOURCE_EXHAUSTED = 0x89
    NOT_FOUND = 0x8B
    UNREPORTABLE_ATTRIBUTE = 0x8C
    INVALID_DATA_TYPE = 0x8D
    UNSUPPORTED_READ = 0x8F
    DATA_VERSION_MISMATCH = 0x92
    TIMEOUT = 0x94
    UNSUPPORTED_NODE = 0x9B
    BUSY = 0x9C
    ACCESS_RESTRICTED = 0x9D
    UNSUPPORTED_CLUSTER = 0xC3
    NO_UPSTREAM_SUBSCRIPTION = 0xC5
    NEEDS_TIMED_INTERACTION = 0xC6
    UNSUPPORTED_EVENT = 0xC7
    PATHS_EXHAUSTED = 0xC8
    TIMED_REQUEST_MISMATCH = 0xC9
    FAILSAFE_REQUIRED = 0xCA
    INVALID_IN_STATE = 0xCB
    NO_COMMAND_RESPONSE = 0xCC
    TERMS_AND_CONDITIONS_CHANGED = 0xCD
    MAINTENANCE_REQUIRED = 0xCE
    DYNAMIC_CONSTRAINT_ERROR = 0xCF
    ALREADY_EXISTS = 0xD0
    INVALID_TRANSPORT_TYPE = 0xD1


SubscriberKey = collections.namedtuple("SubscriberKey", ["local_fabric_index", "node_id"])
AttributeKey = collections.namedtuple("AttributeKey", ["endpoint_id", "cluster_id", "attribute_id"])
EventKey = collections.namedtuple("EventKey", ["endpoint_id", "cluster_id", "event_id"])


@dataclasses.dataclass
class Event:
    key: EventKey
    number: int
    priority: cluster.EventPriority
    timestamp: datetime.datetime
    data: typing.Any


class Subscription:
    id: int
    subscriber: SubscriberKey
    session: message_layer.SessionContext
    min_interval_secs: int
    max_interval_secs: int
    last_report: float
    attributes: typing.Dict[AttributeKey, cluster.Attribute]
    timer: threading.Timer
    interaction_model: "InteractionModel"

    def __init__(
            self, sid: int, session: message_layer.SessionContext,
            min_interval_secs: int, max_interval_secs: int,
            interaction_model: "InteractionModel"
    ):
        self.id = sid
        self.session = session
        self.subscriber = SubscriberKey(
            local_fabric_index=session.local_fabric_index,
            node_id=session.peer_node_id
        )
        self.min_interval_secs = min_interval_secs
        self.max_interval_secs = max_interval_secs
        self.interaction_model = interaction_model
        self.attributes: typing.Dict[AttributeKey, typing.Tuple[cluster.Cluster, cluster.Attribute]] = {}
        self.changed_attributes: typing.Set[AttributeKey] = set()
        self.events: typing.Dict[EventKey, typing.Tuple[bool, typing.List[Event]]] = {}
        self.timer = threading.Timer(
            max(min_interval_secs, max_interval_secs // 2),
            self.report
        )
        self.timer.start()
        self.last_report = time.time()
        self.pending_report = False

    def add_attribute(self, ak: AttributeKey, c: cluster.Cluster, attribute: cluster.Attribute):
        self.attributes[ak] = (c, attribute)

    def add_event(self, ek: EventKey, is_urgent: bool):
        self.events[ek] = (is_urgent, [])

    def attribute_changed(self, ak: AttributeKey):
        self.changed_attributes.add(ak)

    def new_event(self, event: Event):
        is_urgent, ev = self.events[event.key]
        ev.append(event)
        if is_urgent:
            self.report_now()

    def report(self):
        exchange = self.interaction_model.message_layer.initiate_exchange(self.session)
        attribute_reports = []
        event_reports = []
        for ak in self.changed_attributes:
            c, attr = self.attributes[ak]
            if not attr.read_supported():
                continue

            attribute_reports.append(InteractionModel.AttributeReportIB(
                attribute_data=InteractionModel.AttributeDataIB(
                    data_version=c.data_version,
                    path=InteractionModel.AttributePathIB(
                        enable_tag_compression=None,
                        node=None,
                        endpoint=ak.endpoint_id,
                        cluster=ak.cluster_id,
                        attribute=ak.attribute_id,
                        list_index=None,
                        wildcard_path_flags=None,
                        wildcard_filter_configuration_version=None,
                    ),
                    data=attr.read(c, exchange.context)
                ),
                attribute_status=None,
            ))
        self.changed_attributes = set()

        for ek, (_, events) in self.events.items():
            for event in events:
                event_reports.append(InteractionModel.EventReportIB(
                    event_data=InteractionModel.EventDataIB(
                        path=InteractionModel.EventPathIB(
                            node=None,
                            endpoint=ek.endpoint_id,
                            cluster=ek.cluster_id,
                            event=ek.event_id,
                            is_urgent=None,
                        ),
                        event_number=event.number,
                        priority=event.priority.value,
                        epoch_timestamp=int(event.timestamp.timestamp() * 1000),
                        system_timestamp=None,
                        delta_epoch_timestamp=None,
                        delta_system_timestamp=None,
                        data=event.data
                    ),
                    event_status=None,
                ))
            events.clear()

        expects_response = attribute_reports or event_reports
        self.interaction_model.chunk_report_data(
            exchange, attribute_reports, event_reports,
            subscription_id=self.id, suppress_response=not expects_response,
        )
        if expects_response:
            self.interaction_model.pending_subscription_reports[exchange] = self.id

        self.timer = threading.Timer(
            max(self.min_interval_secs, self.max_interval_secs - 5),
            self.report
        )
        self.timer.start()
        self.last_report = time.time()
        self.pending_report = False

    def report_now(self):
        if not self.pending_report:
            self.timer.cancel()
            seconds_since_last_report = time.time() - self.last_report
            if seconds_since_last_report < self.min_interval_secs:
                self.pending_report = True
                self.timer = threading.Timer(
                    self.min_interval_secs - seconds_since_last_report,
                    self.report
                )
                self.timer.start()
            else:
                self.report()


class InteractionModel(protocol_messages.ImProtocol, protocol.Protocol):
    OPCODE_STATUS_RESPONSE = 0x01
    OPCODE_READ_REQUEST = 0x02
    OPCODE_SUBSCRIBE_REQUEST = 0x03
    OPCODE_SUBSCRIBE_RESPONSE = 0x04
    OPCODE_REPORT_DATA = 0x05
    OPCODE_WRITE_REQUEST = 0x06
    OPCODE_WRITE_RESPONSE = 0x07
    OPCODE_INVOKE_REQUEST = 0x08
    OPCODE_INVOKE_RESPONSE = 0x09
    OPCODE_TIMED_REQUEST = 0x0A

    def __init__(self, state: device.DeviceState, layer: message_layer.MessageLayer, dns: mdns.MDNS):
        super().__init__(layer)
        self._endpoints: typing.Dict[int, endpoint.Endpoint] = {}
        self._next_endpoint = 0
        self._subscriptions: typing.Dict[int, Subscription] = {}
        self._timed_requests: typing.Dict[message_layer.Exchange, threading.Timer] = {}
        self._expired_timeouts: typing.Set[message_layer.Exchange] = set()
        self._root_node = root_node.RootNode("ROOT", state, layer, dns)
        self._state = state
        self.pending_subscription_reports: typing.Dict[message_layer.Exchange, int] = {}
        self.add_endpoint(self._root_node)

    def startup_complete(self):
        self._root_node.basic_information.startup_complete()

    def add_endpoint(self, d: endpoint.Endpoint):
        self._endpoints[self._next_endpoint] = d
        if self._next_endpoint != 0:
            self._root_node.parts.add(self._next_endpoint)
        d.register_im(self._next_endpoint, self, self._state)
        self._next_endpoint += 1
        pass

    def attributes_changed(self, keys: typing.List[AttributeKey]):
        for sub in self._subscriptions.values():
            to_notify = [ak for ak in keys if ak in sub.attributes]
            if to_notify:
                for ak in to_notify:
                    sub.attribute_changed(ak)
                sub.report_now()

    def report_event(self, ek: EventKey, priority: cluster.EventPriority, data: typing.Any):
        event = Event(
            number=self._state.next_event_id,
            key=ek,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            priority=priority,
            data=data
        )
        self._state.events.append(event)
        self._state.next_event_id += 1
        self._state.save_state()
        for sub in self._subscriptions.values():
            if ek in sub.events:
                sub.new_event(event)

    def allocate_subscription_id(self):
        for sid in range(1, 0x100000000):
            if sid not in self._subscriptions:
                return sid

        return None

    def handle_message(self, exchange: message_layer.Exchange, opcode: int, message: bytes):
        isd = acl.ISD(
            authentication_mode=acl.AuthenticationMode.NoAuth,
            is_commissioning=False,
            node_id=0,
            cats=[],
            fabric_index=0
        )

        if isinstance(exchange.context, message_layer.SecureSessionContext):
            if exchange.context.session_type == message_layer.SecureSessionType.PASE:
                isd.is_commissioning = self._state.in_commissioning_mode
                isd.authentication_mode = acl.AuthenticationMode.PASE
                isd.fabric_index = exchange.context.local_fabric_index
            elif exchange.context.session_type == message_layer.SecureSessionType.CASE:
                isd.is_commissioning = False
                isd.authentication_mode = acl.AuthenticationMode.CASE
                isd.node_id = exchange.context.peer_node_id
                isd.cats = exchange.context.cats
                isd.fabric_index = exchange.context.local_fabric_index

        if opcode == self.OPCODE_STATUS_RESPONSE:
            try:
                msg = self.StatusResponseMessage.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"invalid payload on status response: {e}")
                self.send_status_report(exchange=exchange, general_code=messages.GeneralCode.BAD_REQUEST)
                return
            self.status_response(exchange, msg)
        elif opcode == self.OPCODE_READ_REQUEST:
            try:
                msg = self.ReadRequestMessage.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"invalid payload on read request: {e}")
                self.send_status_report(exchange=exchange, general_code=messages.GeneralCode.BAD_REQUEST)
                return
            self.read_request(exchange, msg, isd)
        elif opcode == self.OPCODE_SUBSCRIBE_REQUEST:
            try:
                msg = self.SubscribeRequestMessage.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"invalid payload on subscribe request: {e}")
                self.send_status_report(exchange=exchange, general_code=messages.GeneralCode.BAD_REQUEST)
                return
            self.subscribe_request(exchange, msg, isd)
        elif opcode == self.OPCODE_WRITE_REQUEST:
            self.release_next_message(exchange)
            try:
                msg = self.WriteRequestMessage.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"invalid payload on write request: {e}")
                self.send_status_report(exchange=exchange, general_code=messages.GeneralCode.BAD_REQUEST)
                return
            self.write_request(exchange, msg, isd)
        elif opcode == self.OPCODE_INVOKE_REQUEST:
            self.release_next_message(exchange)
            try:
                msg = self.InvokeRequestMessage.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"invalid payload on invoke request: {e}")
                self.send_status_report(exchange=exchange, general_code=messages.GeneralCode.BAD_REQUEST)
                return
            self.invoke_request(exchange, msg, isd)
        elif opcode == self.OPCODE_TIMED_REQUEST:
            try:
                msg = self.TimedRequestMessage.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"invalid payload on invoke request: {e}")
                self.send_status_report(exchange=exchange, general_code=messages.GeneralCode.BAD_REQUEST)
                return
            self.timed_request(exchange, msg)
        else:
            self.send_status_report(exchange=exchange, general_code=messages.GeneralCode.BAD_REQUEST)
            logger.warning(f"unknown opcode {opcode:02X}")

    def handle_status_report(
            self,
            exchange: message_layer.Exchange,
            general_code: messages.GeneralCode,
            protocol_code: int,
            protocol_data: bytes
    ):
        logger.debug(f"{exchange} - status report: {general_code.name} code={protocol_code}")

    def status_response(
            self,
            exchange: message_layer.Exchange,
            message: protocol_messages.ImProtocol.StatusResponseMessage
    ):
        logger.debug(f"{exchange} - status response: {message.status}")

        if message.status == StatusCode.SUCCESS.value:
            if exchange in self.pending_subscription_reports:
                self._message_layer.close_exchange(exchange)
            else:
                self.release_next_message(exchange)
        else:
            if message.status == StatusCode.INVALID_SUBSCRIPTION.value:
                if sid := self.pending_subscription_reports.pop(exchange, None):
                    if sub := self._subscriptions.pop(sid, None):
                        sub.timer.cancel()

            self._message_layer.close_exchange(exchange)

    @staticmethod
    def decompress_paths(paths: typing.Iterable[protocol_messages.ImProtocol.AttributePathIB]) -> typing.Generator[
        typing.Tuple[int, int, int, int, int]]:
        previous_node = None
        previous_endpoint = None
        previous_cluster = None
        previous_attribute = None
        for path in paths:
            if path.enable_tag_compression:
                if path.node is None:
                    node_id = previous_node
                else:
                    node_id = path.node
                if path.endpoint is None:
                    endpoint_id = previous_endpoint
                else:
                    endpoint_id = path.endpoint
                if path.cluster is None:
                    cluster_id = previous_cluster
                else:
                    cluster_id = path.cluster
                if path.attribute is None:
                    attribute_id = previous_attribute
                else:
                    attribute_id = path.attribute

                yield node_id, endpoint_id, cluster_id, attribute_id, path.list_index
            else:
                previous_node = path.node
                previous_endpoint = path.endpoint
                previous_cluster = path.cluster
                previous_attribute = path.attribute

                yield path.node, path.endpoint, path.cluster, path.attribute, path.list_index

    def chunk_report_data(
            self,
            exchange: message_layer.Exchange,
            attribute_reports: typing.List[protocol_messages.ImProtocol.AttributeReportIB],
            event_reports: typing.List[protocol_messages.ImProtocol.EventReportIB],
            subscription_id: typing.Optional[int] = None,
            suppress_response: bool = True,
    ):
        current_attribute_reports = []
        current_event_reports = []
        current_len = 0
        messages_out = []

        def gen_next_message():
            nonlocal current_len, current_attribute_reports, current_event_reports
            if current_len >= 900:
                messages_out.append(self.ReportDataMessage(
                    subscription_id=subscription_id,
                    attribute_reports=current_attribute_reports,
                    event_reports=current_event_reports,
                    more_chunked_messages=True,
                    suppress_response=False,
                    interaction_model_revision=INTERACTION_MODEL_REVISION,
                ))
                current_attribute_reports = []
                current_event_reports = []
                current_len = 0

        for attribute_report in attribute_reports:
            report_len = len(attribute_report.encode_to_bytes())
            current_attribute_reports.append(attribute_report)
            current_len += report_len
            gen_next_message()

        for event_report in event_reports:
            report_len = len(event_report.encode_to_bytes())
            current_event_reports.append(event_report)
            current_len += report_len
            gen_next_message()

        if current_attribute_reports or current_event_reports or not messages_out:
            messages_out.append(self.ReportDataMessage(
                subscription_id=subscription_id,
                attribute_reports=current_attribute_reports,
                event_reports=current_event_reports,
                more_chunked_messages=False,
                suppress_response=suppress_response,
                interaction_model_revision=INTERACTION_MODEL_REVISION,
            ))

        for message in messages_out:
            self.send_message(exchange, self.OPCODE_REPORT_DATA, message)

    def read_request(
            self,
            exchange: message_layer.Exchange,
            message: protocol_messages.ImProtocol.ReadRequestMessage,
            isd: acl.ISD,
    ):
        attribute_reports = []
        event_reports = []
        for node_id, endpoint_id, cluster_id, attribute_id, list_index in self.decompress_paths(
                message.attribute_requests or []):
            attr_desc = f"endpoint={endpoint_id if endpoint_id is not None else '*'} cluster={f'0x{cluster_id:04X}' if cluster_id is not None else '*'} attribute={f'0x{attribute_id:04X}' if attribute_id is not None else '*'} list_index={list_index}"
            logger.debug(f"{exchange} - read attribute: {attr_desc}")
            for resp in self.read_attribute(node_id, endpoint_id, cluster_id, attribute_id, list_index, message.data_version_filters or [],
                                            exchange.context, isd):
                if isinstance(resp, self.AttributeDataIB):
                    attribute_reports.append(self.AttributeReportIB(
                        attribute_data=resp,
                        attribute_status=None
                    ))
                elif isinstance(resp, self.AttributeStatusIB):
                    print(f"{exchange} - failed to read attribute: {resp.status.status} ({attr_desc})")
                    attribute_reports.append(self.AttributeReportIB(
                        attribute_data=None,
                        attribute_status=resp
                    ))
        for e in message.event_requests or []:
            event_desc = f"endpoint={e.endpoint if e.endpoint is not None else '*'} cluster={f'0x{e.cluster:04X}' if e.cluster is not None else '*'} event={f'0x{e.event:04X}' if e.event is not None else '*'}"
            logger.debug(f"{exchange} - read event: {event_desc}")
            for resp in self.read_event(e.node, e.endpoint, e.cluster, e.event, False, exchange.context, isd):
                if isinstance(resp, self.EventDataIB):
                    event_reports.append(self.EventReportIB(
                        event_data=resp,
                        event_status=None
                    ))
                elif isinstance(resp, self.EventStatusIB):
                    print(f"{exchange} - failed to read event: {resp.status.status} ({event_desc})")
                    event_reports.append(self.EventReportIB(
                        event_data=None,
                        event_status=resp
                    ))

        self.chunk_report_data(exchange, attribute_reports, event_reports)
        self._message_layer.close_exchange(exchange)

    def subscribe_request(
            self,
            exchange: message_layer.Exchange,
            message: protocol_messages.ImProtocol.SubscribeRequestMessage,
            isd: acl.ISD,
    ):
        if not message.keep_subscriptions:
            tbd = []
            sk = SubscriberKey(local_fabric_index=exchange.context.local_fabric_index,
                               node_id=exchange.context.peer_node_id)
            for k, v in self._subscriptions.items():
                if v.subscriber == sk:
                    tbd.append(k)
            for k in tbd:
                del self._subscriptions[k]

        attribute_reports = []
        event_reports = []
        successfully_read = True
        subscription = Subscription(
            sid=self.allocate_subscription_id(),
            session=exchange.context,
            min_interval_secs=message.min_interval_floor,
            max_interval_secs=message.max_interval_ceiling,
            interaction_model=self
        )
        for node_id, endpoint_id, cluster_id, attribute_id, _ in self.decompress_paths(
                message.attribute_requests or []):
            attr_desc = f"endpoint={endpoint_id if endpoint_id is not None else '*'} cluster={f'0x{cluster_id:04X}' if cluster_id is not None else '*'} attribute={f'0x{attribute_id:04X}' if attribute_id is not None else '*'}"
            logger.debug(f"{exchange} - subscribe attribute: {attr_desc}")
            for resp in self.read_attribute(node_id, endpoint_id, cluster_id, attribute_id, None, message.data_version_filters or [], exchange.context,
                                            isd, subscription):
                if isinstance(resp, self.AttributeDataIB):
                    attribute_reports.append(self.AttributeReportIB(
                        attribute_data=resp,
                        attribute_status=None
                    ))
                elif isinstance(resp, self.AttributeStatusIB):
                    logger.debug(f"{exchange} - failed to read attribute: {resp.status.status} ({attr_desc})")
                    successfully_read = False
                    attribute_reports.append(self.AttributeReportIB(
                        attribute_data=None,
                        attribute_status=resp
                    ))
        for e in message.event_requests or []:
            event_desc = f"endpoint={e.endpoint if e.endpoint is not None else '*'} cluster={f'0x{e.cluster:04X}' if e.cluster is not None else '*'} event={f'0x{e.event:04X}' if e.event is not None else '*'}"
            logger.debug(f"{exchange} - subscribe event: {event_desc}")
            for resp in self.read_event(e.node, e.endpoint, e.cluster, e.event, e.is_urgent or False, exchange.context,
                                        isd, subscription):
                if isinstance(resp, self.EventDataIB):
                    event_reports.append(self.EventReportIB(
                        event_data=resp,
                        event_status=None
                    ))
                elif isinstance(resp, self.EventStatusIB):
                    logger.debug(f"{exchange} - failed to read event: {resp.status.status} ({event_desc})")
                    successfully_read = False
                    event_reports.append(self.EventReportIB(
                        event_data=None,
                        event_status=resp
                    ))

        if successfully_read:
            self._subscriptions[subscription.id] = subscription
        else:
            subscription = None

        self.chunk_report_data(
            exchange, attribute_reports, event_reports,
            subscription_id=subscription.id if subscription else None,
            suppress_response=False
        )
        if subscription:
            self.send_message(exchange, self.OPCODE_SUBSCRIBE_RESPONSE, self.SubscribeResponseMessage(
                subscription_id=subscription.id,
                max_interval=subscription.max_interval_secs,
                interaction_model_revision=INTERACTION_MODEL_REVISION,
            ))
        else:
            self._message_layer.close_exchange(exchange)

    def write_request(
            self,
            exchange: message_layer.Exchange,
            message: protocol_messages.ImProtocol.WriteRequestMessage,
            isd: acl.ISD,
    ):
        if not self.handle_timed_interaction(exchange, message):
            return

        if message.more_chunked_messages:
            logger.error("UNIMPLEMENTED: chunked write")
            return

        attribute_reports = []
        for req, (node_id, endpoint_id, cluster_id, attribute_id, list_index) in zip(
                message.write_requests, self.decompress_paths((req.path for req in message.write_requests))
        ):
            attr_desc = f"endpoint={endpoint_id if endpoint_id is not None else '*'} cluster={f'0x{cluster_id:04X}' if cluster_id is not None else '*'} attribute={f'0x{attribute_id:04X}' if attribute_id is not None else '*'}"
            logger.debug(f"{exchange} - write attribute: {attr_desc}")
            resp = self.write_attribute(node_id, endpoint_id, cluster_id, attribute_id, list_index, req.data,
                                        exchange.context, isd, message.timed_request)
            logger.debug(f"{exchange} - write status: {resp.status}")
            attribute_reports.append(self.AttributeStatusIB(
                path=self.AttributePathIB(
                    enable_tag_compression=None,
                    node=node_id,
                    endpoint=endpoint_id,
                    cluster=cluster_id,
                    attribute=attribute_id,
                    list_index=None,
                    wildcard_path_flags=None,
                    wildcard_filter_configuration_version=None,
                ),
                status=resp
            ))

        if not message.suppress_response:
            response = self.WriteResponseMessage(
                write_responses=attribute_reports,
                interaction_model_revision=INTERACTION_MODEL_REVISION,
            )
            self.send_message(exchange, self.OPCODE_WRITE_RESPONSE, response)
        self._message_layer.close_exchange(exchange)

    def invoke_request(
            self,
            exchange: message_layer.Exchange,
            message: protocol_messages.ImProtocol.InvokeRequestMessage,
            isd: acl.ISD,
    ):
        if not self.handle_timed_interaction(exchange, message):
            return

        responses = []
        for path in message.invoke_requests:
            invoke_desc = f"endpoint={path.command_path.endpoint} cluster=0x{path.command_path.cluster:04X} command=0x{path.command_path.command:04X}"
            logger.debug(f"{exchange} - invoke command: {invoke_desc}")
            for resp in self.invoke_command(
                    path.command_path.endpoint, path.command_path.cluster, path.command_path.command,
                    path.command_fields, exchange.context, isd, message.timed_request
            ):
                if isinstance(resp, self.CommandDataIB):
                    resp.command_ref = path.command_ref
                    responses.append(self.InvokeResponseIB(
                        command=resp,
                        status=None
                    ))
                elif isinstance(resp, self.CommandStatusIB):
                    logger.debug(f"{exchange} - invoke status: {resp.status.status} ({invoke_desc})")
                    resp.command_ref = path.command_ref
                    responses.append(self.InvokeResponseIB(
                        command=None,
                        status=resp
                    ))

        if not message.suppress_response:
            response = self.InvokeResponseMessage(
                invoke_responses=responses,
                more_chunked_messages=False,
                suppress_response=True,
                interaction_model_revision=INTERACTION_MODEL_REVISION,
            )
            self.send_message(exchange, self.OPCODE_INVOKE_RESPONSE, response)
        self._message_layer.close_exchange(exchange)

    def timed_request(
            self,
            exchange: message_layer.Exchange,
            message: protocol_messages.ImProtocol.TimedRequestMessage
    ):
        if exchange in self._timed_requests or exchange in self._expired_timeouts:
            self.send_message(exchange, self.OPCODE_STATUS_RESPONSE, self.StatusResponseMessage(
                status=StatusCode.TIMED_REQUEST_MISMATCH,
                interaction_model_revision=INTERACTION_MODEL_REVISION,
            ))

        def cancel():
            del self._timed_requests[exchange]
            self._expired_timeouts.add(exchange)

        t = threading.Timer(message.timeout / 1000, cancel)
        self._timed_requests[exchange] = t
        t.start()
        self.send_message(exchange, self.OPCODE_STATUS_RESPONSE, self.StatusResponseMessage(
            status=StatusCode.SUCCESS,
            interaction_model_revision=INTERACTION_MODEL_REVISION,
        ))

    def handle_timed_interaction(
            self,
            exchange: message_layer.Exchange,
            message: typing.Union[
                protocol_messages.ImProtocol.WriteRequestMessage, protocol_messages.ImProtocol.InvokeRequestMessage]
    ):
        if message.timed_request:
            if exchange in self._expired_timeouts:
                self.send_message(exchange, self.OPCODE_STATUS_RESPONSE, self.StatusResponseMessage(
                    status=StatusCode.TIMEOUT,
                    interaction_model_revision=INTERACTION_MODEL_REVISION,
                ))
                return False
            elif exchange in self._timed_requests:
                self._timed_requests[exchange].cancel()
                del self._timed_requests[exchange]
                return True
            else:
                self.send_message(exchange, self.OPCODE_STATUS_RESPONSE, self.StatusResponseMessage(
                    status=StatusCode.TIMED_REQUEST_MISMATCH,
                    interaction_model_revision=INTERACTION_MODEL_REVISION,
                ))
                return False
        else:
            if exchange in self._expired_timeouts or exchange in self._timed_requests:
                self.send_message(exchange, self.OPCODE_STATUS_RESPONSE, self.StatusResponseMessage(
                    status=StatusCode.TIMED_REQUEST_MISMATCH,
                    interaction_model_revision=INTERACTION_MODEL_REVISION,
                ))
                return False
            else:
                return True

    def read_attribute(
            self,
            node_id: typing.Optional[int],
            endpoint_id: typing.Optional[int],
            cluster_id: typing.Optional[int],
            attribute_id: typing.Optional[int],
            list_index: typing.Optional[int | tlv.Null],
            dvf: typing.List[protocol_messages.ImProtocol.DataVersionFilterIB],
            session: message_layer.SessionContext,
            isd: acl.ISD,
            subscription: typing.Optional[Subscription] = None,
    ) -> typing.List[
        typing.Union[protocol_messages.ImProtocol.AttributeDataIB, protocol_messages.ImProtocol.AttributeStatusIB]
    ]:
        data_versions = {
            (f.path.endpoint, f.path.cluster): f.data_version
            for f in dvf if f.path.node is not None
        }

        if node_id is not None:
            return [self.AttributeStatusIB(
                path=self.AttributePathIB(
                    enable_tag_compression=None,
                    node=node_id,
                    endpoint=endpoint_id,
                    cluster=cluster_id,
                    attribute=attribute_id,
                    list_index=list_index,
                    wildcard_path_flags=None,
                    wildcard_filter_configuration_version=None,
                ),
                status=self.StatusIB(
                    status=StatusCode.UNSUPPORTED_NODE.value,
                    cluster_status=0
                )
            )]

        if endpoint_id is not None and cluster_id is not None and attribute_id is not None:
            device_types = self._endpoints[endpoint_id].DEVICE_TYPES if endpoint_id in self._endpoints else set()
            granted_privileges = acl.get_granted_privileges(self._state.acl, isd, endpoint_id, cluster_id, device_types)
            if cluster.Privileges.View not in granted_privileges:
                return [self.AttributeStatusIB(
                    path=self.AttributePathIB(
                        enable_tag_compression=None,
                        node=None,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        attribute=attribute_id,
                        list_index=list_index,
                        wildcard_path_flags=None,
                        wildcard_filter_configuration_version=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ACCESS.value,
                        cluster_status=0
                    )
                )]

            if endpoint_id not in self._endpoints:
                return [self.AttributeStatusIB(
                    path=self.AttributePathIB(
                        enable_tag_compression=None,
                        node=None,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        attribute=attribute_id,
                        list_index=list_index,
                        wildcard_path_flags=None,
                        wildcard_filter_configuration_version=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ENDPOINT.value,
                        cluster_status=0
                    )
                )]

            if cluster_id not in self._endpoints[endpoint_id].servers:
                return [self.AttributeStatusIB(
                    path=self.AttributePathIB(
                        enable_tag_compression=None,
                        node=node_id,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        attribute=attribute_id,
                        list_index=list_index,
                        wildcard_path_flags=None,
                        wildcard_filter_configuration_version=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_CLUSTER.value,
                        cluster_status=0
                    )
                )]

            c = self._endpoints[endpoint_id].servers[cluster_id]
            attr = c.get_attribute(attribute_id)
            if not attr:
                return [self.AttributeStatusIB(
                    path=self.AttributePathIB(
                        enable_tag_compression=None,
                        node=None,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        attribute=attribute_id,
                        list_index=list_index,
                        wildcard_path_flags=None,
                        wildcard_filter_configuration_version=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ATTRIBUTE.value,
                        cluster_status=0
                    )
                )]

            if attr.read_privilege not in granted_privileges:
                return [self.AttributeStatusIB(
                    path=self.AttributePathIB(
                        enable_tag_compression=None,
                        node=None,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        attribute=attribute_id,
                        list_index=list_index,
                        wildcard_path_flags=None,
                        wildcard_filter_configuration_version=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ACCESS.value,
                        cluster_status=0
                    )
                )]

            if not attr.read_supported():
                return [self.AttributeStatusIB(
                    path=self.AttributePathIB(
                        enable_tag_compression=None,
                        node=None,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        attribute=attribute_id,
                        list_index=list_index,
                        wildcard_path_flags=None,
                        wildcard_filter_configuration_version=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_READ.value,
                        cluster_status=0
                    )
                )]

            if data_versions.get((endpoint_id, cluster_id), 0) >= c.data_version:
                return []

            def register_subscription(a):
                ak = AttributeKey(
                    endpoint_id=endpoint_id,
                    cluster_id=cluster_id,
                    attribute_id=attribute_id,
                )
                subscription.add_attribute(ak, c, a)

            data = c.get_attribute_data(
                attribute_id, list_index, session,
                register_subscription=register_subscription if subscription else None
            )
            return [self.AttributeDataIB(
                data_version=c.data_version,
                path=self.AttributePathIB(
                    enable_tag_compression=None,
                    node=None,
                    endpoint=endpoint_id,
                    cluster=cluster_id,
                    attribute=attribute_id,
                    list_index=list_index,
                    wildcard_path_flags=None,
                    wildcard_filter_configuration_version=None,
                ),
                data=data
            )]

        else:
            possible_paths = []
            attribute_reports = []

            if endpoint_id is None:
                endpoints = self._endpoints.keys()
            else:
                endpoints = [endpoint_id]

            for e in endpoints:
                if cluster_id is None:
                    for c in self._endpoints[e].servers.keys():
                        possible_paths.append((e, c))
                else:
                    possible_paths.append((e, cluster_id))

            for e, c in possible_paths:
                if e not in self._endpoints or c not in self._endpoints[e].servers:
                    continue

                device_types = self._endpoints[e].DEVICE_TYPES
                granted_privileges = acl.get_granted_privileges(self._state.acl, isd, e, c, device_types)
                if cluster.Privileges.View not in granted_privileges:
                    continue

                cl = self._endpoints[e].servers[c]
                if data_versions.get((e, c), 0) >= cl.data_version:
                    continue

                if attribute_id is None:
                    attrs = cl.get_attributes()
                else:
                    if a := cl.get_attribute(attribute_id):
                        attrs = [a]
                    else:
                        attrs = []

                for a in attrs:
                    if a.read_privilege not in granted_privileges:
                        continue

                    if not a.read_supported():
                        continue

                    def register_subscription(a):
                        ak = AttributeKey(
                            endpoint_id=e,
                            cluster_id=c,
                            attribute_id=a.id,
                        )
                        subscription.add_attribute(ak, cl, a)

                    data = cl.get_attribute_data(
                        a.id, list_index, session,
                        register_subscription=register_subscription if subscription else None
                    )
                    if data:
                        attribute_reports.append(self.AttributeDataIB(
                            data_version=cl.data_version,
                            path=self.AttributePathIB(
                                enable_tag_compression=None,
                                node=None,
                                endpoint=e,
                                cluster=c,
                                attribute=a.id,
                                list_index=list_index,
                                wildcard_path_flags=None,
                                wildcard_filter_configuration_version=None,
                            ),
                            data=data
                        ))

            return attribute_reports

    def read_event(
            self,
            node_id: typing.Optional[int],
            endpoint_id: typing.Optional[int],
            cluster_id: typing.Optional[int],
            event_id: typing.Optional[int],
            is_urgent: bool,
            session: message_layer.SessionContext,
            isd: acl.ISD,
            subscription: typing.Optional[Subscription] = None,
    ) -> typing.List[
        typing.Union[protocol_messages.ImProtocol.EventDataIB, protocol_messages.ImProtocol.EventStatusIB]
    ]:
        if node_id is not None:
            return [self.EventStatusIB(
                path=self.EventPathIB(
                    node=node_id,
                    endpoint=endpoint_id,
                    cluster=cluster_id,
                    event=event_id,
                    is_urgent=None,
                ),
                status=self.StatusIB(
                    status=StatusCode.UNSUPPORTED_NODE.value,
                    cluster_status=0
                )
            )]

        if endpoint_id is not None and cluster_id is not None and event_id is not None:
            device_types = self._endpoints[endpoint_id].DEVICE_TYPES if endpoint_id in self._endpoints else set()
            granted_privileges = acl.get_granted_privileges(self._state.acl, isd, endpoint_id, cluster_id, device_types)
            if cluster.Privileges.View not in granted_privileges:
                return [self.EventStatusIB(
                path=self.EventPathIB(
                    node=node_id,
                    endpoint=endpoint_id,
                    cluster=cluster_id,
                    event=event_id,
                    is_urgent=None,
                ),
                status=self.StatusIB(
                    status=StatusCode.UNSUPPORTED_ACCESS.value,
                    cluster_status=0
                )
            )]

            if endpoint_id not in self._endpoints:
                return [self.EventStatusIB(
                    path=self.EventPathIB(
                        node=node_id,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        event=event_id,
                        is_urgent=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ENDPOINT.value,
                        cluster_status=0
                    )
                )]

            if cluster_id not in self._endpoints[endpoint_id].servers:
                return [self.EventStatusIB(
                    path=self.EventPathIB(
                        node=node_id,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        event=event_id,
                        is_urgent=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_CLUSTER.value,
                        cluster_status=0
                    )
                )]

            c = self._endpoints[endpoint_id].servers[cluster_id]
            evt = c.get_event(event_id)
            if not evt:
                return [self.EventStatusIB(
                    path=self.EventPathIB(
                        node=node_id,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        event=event_id,
                        is_urgent=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_EVENT.value,
                        cluster_status=0
                    )
                )]

            if evt.privilege not in granted_privileges:
                return [self.EventStatusIB(
                    path=self.EventPathIB(
                        node=node_id,
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        event=event_id,
                        is_urgent=None,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ACCESS.value,
                        cluster_status=0
                    )
                )]

            ek = EventKey(
                endpoint_id=endpoint_id,
                cluster_id=c.cluster_id,
                event_id=event_id,
            )
            if subscription:
                subscription.add_event(ek, is_urgent)

            return []

        else:
            possible_paths = []
            event_reports = []

            if endpoint_id is None:
                endpoints = self._endpoints.keys()
            else:
                endpoints = [endpoint_id]

            for e in endpoints:
                if cluster_id is None:
                    for c in self._endpoints[e].servers.keys():
                        possible_paths.append((e, c))
                else:
                    possible_paths.append((e, cluster_id))

            for e, c in possible_paths:
                if e not in self._endpoints or c not in self._endpoints[e].servers:
                    continue

                device_types = self._endpoints[e].DEVICE_TYPES
                granted_privileges = acl.get_granted_privileges(self._state.acl, isd, e, c, device_types)
                if cluster.Privileges.View not in granted_privileges:
                    continue

                cl = self._endpoints[e].servers[c]

                if event_id is None:
                    evts = cl.get_events()
                else:
                    if e := cl.get_event(event_id):
                        evts = [e]
                    else:
                        evts = []

                for ev in evts:
                    if ev.privilege not in granted_privileges:
                        continue

                    ek = EventKey(
                        endpoint_id=e,
                        cluster_id=c,
                        event_id=ev.id,
                    )
                    if subscription:
                        subscription.add_event(ek, is_urgent)

            return event_reports

    def write_attribute(
            self,
            node_id: typing.Optional[int],
            endpoint_id: int,
            cluster_id: int,
            attribute_id: int,
            list_index: typing.Optional[int | tlv.Null],
            data,
            session: message_layer.SessionContext,
            isd: acl.ISD,
            timed_request: bool
    ) -> protocol_messages.ImProtocol.StatusIB:
        device_types = self._endpoints[endpoint_id].DEVICE_TYPES if endpoint_id in self._endpoints else set()
        granted_privileges = acl.get_granted_privileges(self._state.acl, isd, endpoint_id, cluster_id, device_types)
        if cluster.Privileges.View not in granted_privileges:
            return self.StatusIB(
                status=StatusCode.UNSUPPORTED_ACCESS.value,
                cluster_status=0
            )

        if node_id is not None:
            return self.StatusIB(
                status=StatusCode.UNSUPPORTED_NODE.value,
                cluster_status=0
            )

        if endpoint_id not in self._endpoints:
            return self.StatusIB(
                status=StatusCode.UNSUPPORTED_ENDPOINT.value,
                cluster_status=0
            )

        if cluster_id not in self._endpoints[endpoint_id].servers:
            return self.StatusIB(
                status=StatusCode.UNSUPPORTED_CLUSTER.value,
                cluster_status=0
            )

        if list_index is None:
            action = cluster.WriteAction.Replace
        elif list_index == tlv.Null:
            action = cluster.WriteAction.Add
        else:
            return self.StatusIB(
                status=StatusCode.INVALID_ACTION.value,
                cluster_status=0
            )

        c = self._endpoints[endpoint_id].servers[cluster_id]
        attr = c.get_attribute(attribute_id)
        if not attr:
            return self.StatusIB(
                status=StatusCode.UNSUPPORTED_ATTRIBUTE.value,
                cluster_status=0
            )

        if attr.write_privilege not in granted_privileges:
            return self.StatusIB(
                status=StatusCode.UNSUPPORTED_ACCESS.value,
                cluster_status=0
            )

        if not attr.write_supported():
            return self.StatusIB(
                status=StatusCode.UNSUPPORTED_WRITE.value,
                cluster_status=0
            )

        if attr.t_timed and not timed_request:
            return self.StatusIB(
                status=StatusCode.NEEDS_TIMED_INTERACTION.value,
                cluster_status=0
            )

        data = c.write_attribute_data(attribute_id, action, data, session)
        return self.StatusIB(
            status=data.value,
            cluster_status=0
        )

    def invoke_command(
            self,
            endpoint_id: typing.Optional[int],
            cluster_id: int,
            command_id: int,
            data,
            session: message_layer.SessionContext,
            isd: acl.ISD,
            timed_request: bool
    ) -> typing.List[
        typing.Union[protocol_messages.ImProtocol.CommandDataIB, protocol_messages.ImProtocol.CommandStatusIB]
    ]:
        if endpoint_id is not None:
            device_types = self._endpoints[endpoint_id].DEVICE_TYPES if endpoint_id in self._endpoints else set()
            granted_privileges = acl.get_granted_privileges(self._state.acl, isd, endpoint_id, cluster_id, device_types)
            if cluster.Privileges.Operate not in granted_privileges:
                return [self.CommandStatusIB(
                    path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        command=command_id,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ACCESS.value,
                        cluster_status=0
                    ),
                    command_ref=None
                )]

            if endpoint_id not in self._endpoints:
                return [self.CommandStatusIB(
                    path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        command=command_id,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ENDPOINT.value,
                        cluster_status=0
                    ),
                    command_ref=None
                )]

            if cluster_id not in self._endpoints[endpoint_id].servers:
                return [self.CommandStatusIB(
                    path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        command=command_id,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_CLUSTER.value,
                        cluster_status=0
                    ),
                    command_ref=None
                )]

            c = self._endpoints[endpoint_id].servers[cluster_id]
            com = c.get_command(command_id)
            if not com:
                return [self.CommandStatusIB(
                    path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=c.cluster_id,
                        command=command_id,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_COMMAND.value,
                        cluster_status=0
                    ),
                    command_ref=None
                )]

            if com.privilege not in granted_privileges:
                return [self.CommandStatusIB(
                    path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=cluster_id,
                        command=command_id,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.UNSUPPORTED_ACCESS.value,
                        cluster_status=0
                    ),
                    command_ref=None
                )]

            if com.t_timed and not timed_request:
                return [self.CommandStatusIB(
                    path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=c.cluster_id,
                        command=command_id,
                    ),
                    status=self.StatusIB(
                        status=StatusCode.NEEDS_TIMED_INTERACTION.value,
                        cluster_status=0
                    ),
                    command_ref=None
                )]

            data = c.invoke_command(command_id, data, session)
            if data[0] is None:
                return [self.CommandStatusIB(
                    path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=c.cluster_id,
                        command=command_id,
                    ),
                    status=self.StatusIB(
                        status=data[1].value,
                        cluster_status=0
                    ),
                    command_ref=None
                )]
            else:
                return [self.CommandDataIB(
                    command_path=self.CommandPathIB(
                        endpoint=endpoint_id,
                        cluster=c.cluster_id,
                        command=data[0],
                    ),
                    command_fields=data[1],
                    command_ref=None,
                )]

        else:
            possible_paths = [(e, cluster_id) for e in self._endpoints.keys()]
            command_reports = []

            for e, c in possible_paths:
                if e not in self._endpoints or c not in self._endpoints[e].servers:
                    continue

                device_types = self._endpoints[e].DEVICE_TYPES
                granted_privileges = acl.get_granted_privileges(self._state.acl, isd, e, c, device_types)
                if cluster.Privileges.Operate not in granted_privileges:
                    continue

                cl = self._endpoints[e].servers[c]
                com = cl.get_command(command_id)
                if not com:
                    continue

                if com.privilege not in granted_privileges:
                    continue

                if com.t_timed and not timed_request:
                    continue

                data = cl.invoke_command(command_id, data, session)
                if data[0] is None:
                    command_reports.append(self.CommandStatusIB(
                        path=self.CommandPathIB(
                            endpoint=e,
                            cluster=c,
                            command=command_id,
                        ),
                        status=self.StatusIB(
                            status=data[1].value,
                            cluster_status=0
                        ),
                        command_ref=None
                    ))
                else:
                    command_reports.append(self.CommandDataIB(
                        command_path=self.CommandPathIB(
                            endpoint=e,
                            cluster=c,
                            command=data[0],
                        ),
                        command_fields=data[1],
                        command_ref=None,
                    ))

            return command_reports
