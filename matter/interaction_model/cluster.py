import abc
import collections
import enum
import inspect
import typing
from . import interaction_model
from .. import message, encoding
from ..encoding import tlv


class RWAccess(enum.Enum):
    Read = enum.auto()
    Write = enum.auto()
    ReadWrite = enum.auto()

class Privileges(enum.Enum):
    View = enum.auto()
    Operate = enum.auto()
    Manage = enum.auto()
    Administer = enum.auto()

class WriteAction(enum.Enum):
    Replace = enum.auto()
    Add = enum.auto()

class Attribute:
    def __init__(
            self,
            attr_id: int,
            access: RWAccess,
            privileges: typing.List[Privileges],
            c_changes_omitted=False,
            f_fixed=False,
            n_nonvolatile=False,
            p_reportable=False,
            q_quieter_reporting=False,
            s_scene=False,
            x_nullable=False,
            t_timed=False,
    ):
        self.id = attr_id
        self.access = access
        self.privileges = privileges
        self.c_changes_omitted = c_changes_omitted
        self.f_fixed = f_fixed
        self.n_nonvolatile = n_nonvolatile
        self.p_reportable = p_reportable
        self.q_quieter_reporting = q_quieter_reporting
        self.s_scene = s_scene
        self.x_nullable = x_nullable
        self.t_timed = t_timed
        self._getter = None
        self._setter = None

    def reader(self, getter):
        self._getter = getter

    def writer(self, setter):
        self._setter = setter

    def read_supported(self) -> bool:
        if self._getter is None:
            return False
        if self.access == RWAccess.Write:
            return False
        return True

    def write_supported(self) -> bool:
        if self._setter is None:
            return False
        if self.access == RWAccess.Read:
            return False
        return True

    def read(self, obj, session: message.SessionContexts):
        if self._getter is None:
            raise NotImplementedError(f"Getter not set on attribute {self.id:04X}")

        sig = inspect.signature(self._getter)
        args = list(sig.parameters.values())
        if len(args) == 2:
            return self._getter(obj, session)
        else:
            return self._getter(obj)

    def write(self, obj, data, session: message.SessionContexts):
        if self._setter is None:
            raise NotImplementedError(f"Setter not set on attribute {self.id:04X}")

        sig = inspect.signature(self._setter)
        args = list(sig.parameters.values())
        data_type = args[1].annotation
        try:
            data = tlv.TaggedFields.decode_type(self._setter.__name__, data, data_type, {})
        except ValueError:
            return interaction_model.StatusCode.INVALID_ACTION

        if len(args) == 3:
            return self._setter(obj, data, session)
        else:
            return self._setter(obj, data)


class ListAttribute(Attribute):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._list_getter = None
        self._list_replacer = None
        self._list_adder = None

    def write_supported(self) -> bool:
        if self._list_replacer is None or self._list_adder is None:
            return False
        if self.access == RWAccess.Read:
            return False
        return True

    def list_getter(self, getter):
        self._list_getter = getter

    def list_replacer(self, setter):
        self._list_replacer = setter

    def list_adder(self, setter):
        self._list_adder = setter

    def read_list(self, obj, index: int, session):
        if self._list_getter is not None:
            sig = inspect.signature(self._setter)
            args = list(sig.parameters.values())
            if len(args) == 3:
                return self._list_getter(obj, index, session)
            else:
                return self._list_getter(obj, index)
        else:
            val = self.read(obj, session)
            if index >= len(val):
                return None
            return val[index]

    def _list_writer_data_type(self, args):
        data_type = args[1].annotation
        data_type_origin = typing.get_origin(data_type)
        if not (data_type_origin and issubclass(data_type_origin, list)):
            raise NotImplementedError(f"List writer does not accept a list for attribute {self.id:04X}")
        ft_type_args = typing.get_args(data_type)
        return ft_type_args[0]

    def write_list_replace(self, obj, data, session: message.SessionContexts):
        if self._list_replacer is None:
            raise NotImplementedError(f"List replacer not set on attribute {self.id:04X}")

        sig = inspect.signature(self._list_replacer)
        args = list(sig.parameters.values())
        data_type = self._list_writer_data_type(args)

        if isinstance(data, encoding.TLVArray):
            try:
                data = [
                    tlv.TaggedFields.decode_type(self._list_replacer.__name__, d, data_type, {})
                    for d in data.values
                ]
            except ValueError:
                return interaction_model.StatusCode.INVALID_ACTION
        else:
            return interaction_model.StatusCode.INVALID_ACTION

        if len(args) == 3:
            return self._list_replacer(obj, data, session)
        else:
            return self._list_replacer(obj, data)

    def write_list_add(self, obj, data, session: message.SessionContexts):
        if self._list_adder is None:
            raise NotImplementedError(f"List adder not set on attribute {self.id:04X}")

        sig = inspect.signature(self._list_adder)
        args = list(sig.parameters.values())
        data_type = self._list_writer_data_type(args)

        if isinstance(data, encoding.TLVArray):
            try:
                data = [
                    tlv.TaggedFields.decode_type(self._list_adder.__name__, d, data_type, {})
                    for d in data.values
                ]
            except ValueError:
                return interaction_model.StatusCode.INVALID_ACTION
        else:
            try:
                data = [tlv.TaggedFields.decode_type(self._list_adder.__name__, data, data_type, {})]
            except ValueError:
                return interaction_model.StatusCode.INVALID_ACTION

        if len(args) == 3:
            return self._list_adder(obj, data, session)
        else:
            return self._list_adder(obj, data)

class Command:
    def __init__(
            self,
            command_id: int,
            response_command_id: typing.Optional[int],
            privileges: typing.List[Privileges],
            t_timed=False,
    ):
        self.id = command_id
        self.response_id = response_command_id
        self.privileges = privileges
        self.t_timed = t_timed
        self._exec = None

    def handler(self, handler):
        self._exec = handler

    def __call__(self, obj, data, session: message.SessionContexts):
        if self._exec is None:
            raise NotImplementedError(f"Handler not set on command {self.id:04X}")

        sig = inspect.signature(self._exec)
        args = list(sig.parameters.values())
        if len(args) > 1:
            data_type = args[1].annotation
            if data_type is None:
                data = None
            else:
                try:
                    data = tlv.TaggedFields.decode_type(self._exec.__name__, data, data_type, {})
                except ValueError:
                    return None, interaction_model.StatusCode.INVALID_ACTION

        if len(args) == 3:
            resp_data = self._exec(obj, data, session)
        elif len(args) == 2:
            resp_data = self._exec(obj, data)
        elif len(args) == 1:
            resp_data = self._exec(obj)
        else:
            raise ValueError(f"Incompatible handler signature for command {self.id:04X}")

        if resp_data is None:
            return None
        if self.response_id is None:
            return None, resp_data
        else:
            if isinstance(resp_data, interaction_model.StatusCodeType):
                return None, resp_data
            return self.response_id, tlv.TaggedFields.encode_type(resp_data, {})

class EventPriority(enum.IntEnum):
    DEBUG = 0
    INFO = 1
    CRITICAL = 2

class Event:
    def __init__(
            self,
            event_id: int,
            default_priority: EventPriority,
            privileges: typing.List[Privileges],
    ):
        self.id = event_id
        self.default_priority = default_priority
        self.privileges = privileges

AttributeData = collections.namedtuple("AttributeData", ["id", "data"])
EventReport = collections.namedtuple("EventReport", ["event", "data"])

class Cluster(metaclass=abc.ABCMeta):
    generated_command_list = ListAttribute(0xFFF8, RWAccess.Read, [Privileges.View], f_fixed=True)
    accepted_command_list = ListAttribute(0xFFF9, RWAccess.Read, [Privileges.View], f_fixed=True)
    event_list = ListAttribute(0xFFFA, RWAccess.Read, [Privileges.View], f_fixed=True)
    attribute_list = ListAttribute(0xFFFB, RWAccess.Read, [Privileges.View], f_fixed=True)
    feature_map = Attribute(0xFFFC, RWAccess.Read, [Privileges.View], f_fixed=True)
    cluster_revision = Attribute(0xFFFD, RWAccess.Read, [Privileges.View], f_fixed=True)

    def __init__(self):
        self._attributes: typing.Dict[int, Attribute] = {}
        self._commands: typing.Dict[int, Command] = {}
        self._events: typing.Dict[int, Event] = {}
        self._response_commands = set()
        self._endpoint_id = None
        self._interaction_model: typing.Optional[interaction_model.InteractionModel] = None
        self.data_version = 1

        for superclass in type(self).__mro__:
            for field_name, descriptor in vars(superclass).items():
                if field_name.startswith('_'):
                    continue

                if isinstance(descriptor, Attribute):
                    self._attributes[descriptor.id] = descriptor
                elif isinstance(descriptor, Command):
                    self._commands[descriptor.id] = descriptor
                    if descriptor.response_id:
                        self._response_commands.add(descriptor.response_id)
                elif isinstance(descriptor, Event):
                    self._events[descriptor.id] = descriptor

    def register_im(self, endpoint_id: int, im: interaction_model.InteractionModel):
        self._endpoint_id = endpoint_id
        self._interaction_model = im

    def attributes_changed(self, attributes: typing.List[Attribute]):
        keys = [interaction_model.AttributeKey(
            endpoint_id=self._endpoint_id,
            cluster_id=self.cluster_id,
            attribute_id=attribute.id,
        ) for attribute in attributes]
        if self._interaction_model:
            self._interaction_model.attributes_changed(keys)

    def report_event(self, event: Event, data: typing.Any, priority: typing.Optional[EventPriority] = None):
        key = interaction_model.EventKey(
            endpoint_id=self._endpoint_id,
            cluster_id=self.cluster_id,
            event_id=event.id
        )
        self._interaction_model.report_event(key, priority or event.default_priority, data)

    def increment_data_version(self):
        self.data_version = (self.data_version + 1) % 2**32

    @property
    @abc.abstractmethod
    def cluster_id(self) -> int:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def cluster_revision_number(self) -> int:
        raise NotImplementedError()

    @property
    def features(self) -> typing.List[int]:
        return []

    @cluster_revision.reader
    def read_cluster_revision(self):
        return self.cluster_revision_number

    @feature_map.reader
    def read_feature_map(self) -> encoding.TLVUInt:
        v = 0
        for feature in self.features:
            v |= 2**feature
        return encoding.TLVUInt(v)

    @attribute_list.reader
    def read_attribute_list(self) -> typing.List[encoding.TLVUInt]:
        return [encoding.TLVUInt(v) for v in self._attributes.keys()]

    @event_list.reader
    def read_event_list(self) -> typing.List[encoding.TLVUInt]:
        return []

    @accepted_command_list.reader
    def read_accepted_command_list(self) -> typing.List[encoding.TLVUInt]:
        return [encoding.TLVUInt(v) for v in self._commands.keys()]

    @generated_command_list.reader
    def read_generated_command_list(self) -> typing.List[encoding.TLVUInt]:
        return [encoding.TLVUInt(v) for v in self._response_commands]

    def get_attribute_data(
            self, attribute_id: typing.Optional[int], list_index: typing.Optional[int],
            session: message.SessionContexts,
            register_subscription: typing.Optional[typing.Callable[[Attribute], None]] = None
    ) -> typing.List[AttributeData]:
        if attribute_id is None:
            out = []
            for attr_id, attribute in self._attributes.items():
                if attribute.read_supported():
                    out.append(AttributeData(attr_id, attribute.read(self, session)))
                    if register_subscription and not attribute.c_changes_omitted and not attribute.f_fixed:
                        register_subscription(attribute)
            return out

        if attribute_id not in self._attributes:
            return []

        attr = self._attributes[attribute_id]
        if not attr.read_supported():
            return []

        if list_index is not None:
            if not isinstance(attr, ListAttribute):
                return []
            if register_subscription and not attr.c_changes_omitted and not attr.f_fixed:
                register_subscription(attr)
            return [AttributeData(attribute_id, attr.read_list(self, list_index, session))]

        if register_subscription and not attr.c_changes_omitted and not attr.f_fixed:
            register_subscription(attr)
        return [AttributeData(attribute_id, attr.read(self, session))]

    def write_attribute_data(
            self, attribute_id: int, action: WriteAction, data, session: message.SessionContexts, timed_request: bool
    ) -> interaction_model.StatusCode:
        if attribute_id not in self._attributes:
            return interaction_model.StatusCode.UNSUPPORTED_ATTRIBUTE

        attr = self._attributes[attribute_id]
        if not attr.write_supported():
            return interaction_model.StatusCode.UNSUPPORTED_WRITE
        if attr.t_timed and not timed_request:
            return interaction_model.StatusCode.NEEDS_TIMED_INTERACTION

        if isinstance(attr, ListAttribute):
            if action == WriteAction.Replace:
                return attr.write_list_replace(self, data, session)
            elif action == WriteAction.Add:
                return attr.write_list_add(self, data, session)
        else:
            if action != WriteAction.Replace:
                return interaction_model.StatusCode.INVALID_ACTION

            return attr.write(self, data, session)

    def has_event(self, event_id: int) -> bool:
        return event_id in self._events

    @property
    def event_ids(self) -> typing.List[int]:
        return list(self._events.keys())

    def invoke_command(self, command_id: int, data, session: message.SessionContexts, timed_request: bool):
        if command_id not in self._commands:
            return None

        c = self._commands[command_id]
        if c.t_timed and not timed_request:
            return None, interaction_model.StatusCode.NEEDS_TIMED_INTERACTION

        return c(self, data, session)