import typing
import dataclasses
import enum
from . import tlv

class ImProtocol:
  protocol_vendor_id = 0
  protocol_id = 1

  @dataclasses.dataclass
  class ClusterPathIB(tlv.List):
    node: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615, 'min_count': 0, 'max_count': 1})
    endpoint: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535, 'min_count': 1, 'max_count': 1})
    cluster: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 1, 'max_count': 1})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="node", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="endpoint", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="cluster", optional=False),
      )

  @dataclasses.dataclass
  class AttributePathIB(tlv.List):
    enable_tag_compression: typing.Optional[bool] = dataclasses.field(metadata={'min_count': 0, 'max_count': 1})
    node: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615, 'min_count': 0, 'max_count': 1})
    endpoint: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535, 'min_count': 0, 'max_count': 1})
    cluster: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})
    attribute: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})
    list_index: typing.Optional[int | tlv.Null] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535, 'min_count': 0, 'max_count': 1})
    wildcard_path_flags: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})
    wildcard_filter_configuration_version: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="enable_tag_compression", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="node", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="endpoint", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="cluster", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="attribute", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="list_index", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(6), source="wildcard_path_flags", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(7), source="wildcard_filter_configuration_version", optional=True),
      )

  @dataclasses.dataclass
  class EventPathIB(tlv.List):
    node: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615, 'min_count': 0, 'max_count': 1})
    endpoint: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535, 'min_count': 0, 'max_count': 1})
    cluster: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})
    event: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})
    is_urgent: typing.Optional[bool] = dataclasses.field(metadata={'min_count': 0, 'max_count': 1})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="node", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="endpoint", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="cluster", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="event", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="is_urgent", optional=True),
      )

  @dataclasses.dataclass
  class CommandPathIB(tlv.List):
    endpoint: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535, 'min_count': 0, 'max_count': 1})
    cluster: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})
    command: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295, 'min_count': 0, 'max_count': 1})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="endpoint", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="cluster", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="command", optional=True),
      )

  @dataclasses.dataclass
  class EventFilterIB(tlv.Structure):
    node: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
    event_min: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="node", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="event_min", optional=False),
      )

  @dataclasses.dataclass
  class DataVersionFilterIB(tlv.Structure):
    path: typing.ForwardRef("ImProtocol.ClusterPathIB")
    data_version: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="path", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="data_version", optional=False),
      )

  @dataclasses.dataclass
  class AttributeDataIB(tlv.Structure):
    data_version: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
    path: typing.ForwardRef("ImProtocol.AttributePathIB")
    data: typing.Any

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="data_version", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="path", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="data", optional=False),
      )

  @dataclasses.dataclass
  class EventDataIB(tlv.Structure):
    path: typing.ForwardRef("ImProtocol.EventPathIB")
    event_number: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
    priority: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
    epoch_timestamp: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
    system_timestamp: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
    delta_epoch_timestamp: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
    delta_system_timestamp: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
    data: typing.Any

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="path", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="event_number", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="priority", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="epoch_timestamp", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="system_timestamp", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="delta_epoch_timestamp", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(6), source="delta_system_timestamp", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(7), source="data", optional=False),
      )

  @dataclasses.dataclass
  class StatusIB(tlv.Structure):
    status: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
    cluster_status: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="status", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="cluster_status", optional=False),
      )

  @dataclasses.dataclass
  class AttributeStatusIB(tlv.Structure):
    path: typing.ForwardRef("ImProtocol.AttributePathIB")
    status: typing.ForwardRef("ImProtocol.StatusIB")

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="path", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="status", optional=False),
      )

  @dataclasses.dataclass
  class EventStatusIB(tlv.Structure):
    path: typing.ForwardRef("ImProtocol.EventPathIB")
    status: typing.ForwardRef("ImProtocol.StatusIB")

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="path", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="status", optional=False),
      )

  @dataclasses.dataclass
  class CommandStatusIB(tlv.Structure):
    path: typing.ForwardRef("ImProtocol.CommandPathIB")
    status: typing.ForwardRef("ImProtocol.StatusIB")
    command_ref: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="path", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="status", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="command_ref", optional=True),
      )

  @dataclasses.dataclass
  class AttributeReportIB(tlv.Structure):
    attribute_status: typing.Optional[typing.ForwardRef("ImProtocol.AttributeStatusIB")]
    attribute_data: typing.Optional[typing.ForwardRef("ImProtocol.AttributeDataIB")]

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="attribute_status", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="attribute_data", optional=True),
      )

  @dataclasses.dataclass
  class EventReportIB(tlv.Structure):
    event_status: typing.Optional[typing.ForwardRef("ImProtocol.EventStatusIB")]
    event_data: typing.Optional[typing.ForwardRef("ImProtocol.EventDataIB")]

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="event_status", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="event_data", optional=True),
      )

  @dataclasses.dataclass
  class CommandDataIB(tlv.Structure):
    command_path: typing.ForwardRef("ImProtocol.CommandPathIB")
    command_fields: typing.Optional[typing.Any]
    command_ref: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="command_path", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="command_fields", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="command_ref", optional=True),
      )

  @dataclasses.dataclass
  class InvokeResponseIB(tlv.Structure):
    command: typing.Optional[typing.ForwardRef("ImProtocol.CommandDataIB")]
    status: typing.Optional[typing.ForwardRef("ImProtocol.CommandStatusIB")]

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="command", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="status", optional=True),
      )

  @dataclasses.dataclass
  class StatusResponseMessage(tlv.Structure):
    status: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="status", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class ReadRequestMessage(tlv.Structure):
    attribute_requests: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.AttributePathIB")]] = dataclasses.field(metadata={'is_list': False})
    event_requests: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.EventPathIB")]] = dataclasses.field(metadata={'is_list': False})
    event_filters: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.EventFilterIB")]] = dataclasses.field(metadata={'is_list': False})
    fabric_filtered: bool
    data_version_filters: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.DataVersionFilterIB")]] = dataclasses.field(metadata={'is_list': False})
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="attribute_requests", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="event_requests", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="event_filters", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="fabric_filtered", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="data_version_filters", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class ReportDataMessage(tlv.Structure):
    subscription_id: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
    attribute_reports: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.AttributeReportIB")]] = dataclasses.field(metadata={'is_list': False})
    event_reports: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.EventReportIB")]] = dataclasses.field(metadata={'is_list': False})
    more_chunked_messages: typing.Optional[bool]
    suppress_response: typing.Optional[bool]
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="subscription_id", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="attribute_reports", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="event_reports", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="more_chunked_messages", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="suppress_response", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class SubscribeRequestMessage(tlv.Structure):
    keep_subscriptions: bool
    min_interval_floor: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    max_interval_ceiling: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    attribute_requests: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.AttributePathIB")]] = dataclasses.field(metadata={'is_list': False})
    event_requests: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.EventPathIB")]] = dataclasses.field(metadata={'is_list': False})
    event_filters: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.EventFilterIB")]] = dataclasses.field(metadata={'is_list': False})
    fabric_filtered: bool
    data_version_filters: typing.Optional[typing.List[typing.ForwardRef("ImProtocol.DataVersionFilterIB")]] = dataclasses.field(metadata={'is_list': False})
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="keep_subscriptions", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="min_interval_floor", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="max_interval_ceiling", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="attribute_requests", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="event_requests", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="event_filters", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(7), source="fabric_filtered", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(8), source="data_version_filters", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class SubscribeResponseMessage(tlv.Structure):
    subscription_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
    max_interval: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="subscription_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="max_interval", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class WriteRequestMessage(tlv.Structure):
    suppress_response: typing.Optional[bool]
    timed_request: bool
    write_requests: typing.List[typing.ForwardRef("ImProtocol.AttributeDataIB")] = dataclasses.field(metadata={'is_list': False})
    more_chunked_messages: typing.Optional[bool]
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="suppress_response", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="timed_request", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="write_requests", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="more_chunked_messages", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class WriteResponseMessage(tlv.Structure):
    write_responses: typing.List[typing.ForwardRef("ImProtocol.AttributeStatusIB")] = dataclasses.field(metadata={'is_list': False})
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="write_responses", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class InvokeRequestMessage(tlv.Structure):
    suppress_response: bool
    timed_request: bool
    invoke_requests: typing.List[typing.ForwardRef("ImProtocol.CommandDataIB")] = dataclasses.field(metadata={'is_list': False})
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="suppress_response", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="timed_request", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="invoke_requests", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class InvokeResponseMessage(tlv.Structure):
    suppress_response: bool
    invoke_responses: typing.List[typing.ForwardRef("ImProtocol.InvokeResponseIB")] = dataclasses.field(metadata={'is_list': False})
    more_chunked_messages: bool
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="suppress_response", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="invoke_responses", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="more_chunked_messages", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )

  @dataclasses.dataclass
  class TimedRequestMessage(tlv.Structure):
    timeout: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    interaction_model_revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 1
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(0), source="timeout", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(255), source="interaction_model_revision", optional=False),
      )


@dataclasses.dataclass
class StartUpEvent(tlv.Structure):
  software_version: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="software_version", optional=False),
    )

@dataclasses.dataclass
class CapabilityMinimaStruct(tlv.Structure):
  case_sessions_per_fabric: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  subscriptions_per_fabric: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="case_sessions_per_fabric", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="subscriptions_per_fabric", optional=False),
    )

@dataclasses.dataclass
class BasicCommissioningInfo(tlv.Structure):
  fail_safe_expiry_length_seconds: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  max_cumulative_failsafe_seconds: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="fail_safe_expiry_length_seconds", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="max_cumulative_failsafe_seconds", optional=False),
    )

@dataclasses.dataclass
class ArmFailSafe(tlv.Structure):
  expiry_length_seconds: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  breadcrumb: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="expiry_length_seconds", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="breadcrumb", optional=False),
    )

@dataclasses.dataclass
class ArmFailSafeResponse(tlv.Structure):
  error_code: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  debug_text: str = dataclasses.field(metadata={'min_len': 0, 'max_len': 128})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="error_code", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="debug_text", optional=False),
    )

class RegulatoryLocationEnum(enum.IntEnum):
  Indoor = 0
  Outdoor = 1
  IndoorOutdoor = 2

@dataclasses.dataclass
class SetRegulatoryConfig(tlv.Structure):
  new_regulatory_config: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  country_code: str = dataclasses.field(metadata={'min_len': 2, 'max_len': 2})
  breadcrumb: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="new_regulatory_config", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="country_code", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="breadcrumb", optional=False),
    )

class CommissioningErrorEnum(enum.IntEnum):
  OK = 0
  ValueOutsideRange = 1
  InvalidAuthentication = 2
  NoFailSafe = 3
  BusyWithOtherAdmin = 4
  RequiredTCNotAccepted = 5
  TCAcknowledgementsNotReceived = 6
  TCMinVersionNotMet = 7

@dataclasses.dataclass
class SetRegulatoryConfigResponse(tlv.Structure):
  error_code: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  debug_text: str = dataclasses.field(metadata={'min_len': 0, 'max_len': 128})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="error_code", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="debug_text", optional=False),
    )

@dataclasses.dataclass
class CommissioningCompleteResponse(tlv.Structure):
  error_code: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  debug_text: str = dataclasses.field(metadata={'min_len': 0, 'max_len': 128})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="error_code", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="debug_text", optional=False),
    )

class CertificateTypeEnum(enum.IntEnum):
  DACCertificate = 1
  PAICertificate = 2

@dataclasses.dataclass
class CertificateChainRequest(tlv.Structure):
  certificate_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="certificate_type", optional=False),
    )

@dataclasses.dataclass
class CertificateChainResponse(tlv.Structure):
  certificate: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 600})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="certificate", optional=False),
    )

@dataclasses.dataclass
class AttestationRequest(tlv.Structure):
  attestation_nonce: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="attestation_nonce", optional=False),
    )

@dataclasses.dataclass
class AttestationResponse(tlv.Structure):
  attestation_elements: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 9000})
  attestation_signature: bytes = dataclasses.field(metadata={'min_len': 64, 'max_len': 64})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="attestation_elements", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="attestation_signature", optional=False),
    )

@dataclasses.dataclass
class AttestationElements(tlv.Structure):
  certification_declaration: bytes
  attestation_nonce: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
  timestamp: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
  firmware_information: typing.Optional[bytes]

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="certification_declaration", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="attestation_nonce", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="timestamp", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="firmware_information", optional=True),
    )

@dataclasses.dataclass
class CSRRequest(tlv.Structure):
  csr_nonce: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
  is_for_update_noc: typing.Optional[bool]

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="csr_nonce", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="is_for_update_noc", optional=True),
    )

@dataclasses.dataclass
class CSRResponse(tlv.Structure):
  nocsr_elements: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 9000})
  attestation_signature: bytes = dataclasses.field(metadata={'min_len': 64, 'max_len': 64})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="nocsr_elements", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="attestation_signature", optional=False),
    )

@dataclasses.dataclass
class NocsrElements(tlv.Structure):
  csr: bytes
  csr_nonce: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
  vendor_reserved1: typing.Optional[bytes]
  vendor_reserved2: typing.Optional[bytes]
  vendor_reserved3: typing.Optional[bytes]

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="csr", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="csr_nonce", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="vendor_reserved1", optional=True),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="vendor_reserved2", optional=True),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="vendor_reserved3", optional=True),
    )

class NodeOperationalCertStatusEnum(enum.IntEnum):
  OK = 0
  InvalidPublicKey = 1
  InvalidNodeOpId = 2
  InvalidNOC = 3
  MissingCsr = 4
  TableFull = 5
  InvalidAdminSubject = 6
  FabricConflict = 9
  LabelConflict = 10
  InvalidFabricIndex = 11

@dataclasses.dataclass
class AddNOC(tlv.Structure):
  noc_value: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})
  icac_value: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})
  ipk_value: bytes = dataclasses.field(metadata={'min_len': 16, 'max_len': 16})
  case_admin_subject: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
  admin_vendor_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="noc_value", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="icac_value", optional=True),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="ipk_value", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="case_admin_subject", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="admin_vendor_id", optional=False),
    )

@dataclasses.dataclass
class UpdateNOC(tlv.Structure):
  noc_value: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})
  icac_value: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="noc_value", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="icac_value", optional=True),
    )

@dataclasses.dataclass
class UpdateFabricLabel(tlv.Structure):
  label: str = dataclasses.field(metadata={'min_len': 0, 'max_len': 32})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="label", optional=False),
    )

@dataclasses.dataclass
class RemoveFabric(tlv.Structure):
  fabric_index: int = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="fabric_index", optional=False),
    )

@dataclasses.dataclass
class NOCResponse(tlv.Structure):
  status_code: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  fabric_index: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  debug_text: str = dataclasses.field(metadata={'min_len': 0, 'max_len': 128})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="status_code", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="fabric_index", optional=True),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="debug_text", optional=False),
    )

@dataclasses.dataclass
class AddTrustedRootCertificate(tlv.Structure):
  root_ca_certificate: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="root_ca_certificate", optional=False),
    )

@dataclasses.dataclass
class NOCStruct(tlv.Structure):
  NOC: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})
  ICAC: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})
  VVSC: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 0, 'max_len': 400})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="NOC", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="ICAC", optional=True),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="VVSC", optional=True),
    )

@dataclasses.dataclass
class FabricDescriptorStruct(tlv.Structure):
  root_public_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})
  vendor_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  fabric_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
  node_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
  label: str = dataclasses.field(metadata={'min_len': 0, 'max_len': 32})
  vid_verification_statement: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 0, 'max_len': 85})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="root_public_key", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="vendor_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="fabric_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="node_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="label", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(6), source="vid_verification_statement", optional=True),
    )

class CommissioningWindowStatusEnum(enum.IntEnum):
  WindowNotOpen = 0
  EnhancedWindowOpen = 1
  BasicWindowOpen = 2

class CommissioningWindowStatusCodeEnum(enum.IntEnum):
  Success = 0
  Busy = 2
  PAKEParameterError = 3
  WindowNotOpen = 4

@dataclasses.dataclass
class OpenCommissioningWindow(tlv.Structure):
  commissioning_timeout: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  pake_passcode_verifier: bytes = dataclasses.field(metadata={'min_len': 97, 'max_len': 97})
  discriminator: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4095})
  iterations: int = dataclasses.field(metadata={'signed': False, 'min': 1000, 'max': 100000})
  salt: bytes = dataclasses.field(metadata={'min_len': 16, 'max_len': 32})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="commissioning_timeout", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="pake_passcode_verifier", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="discriminator", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="iterations", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="salt", optional=False),
    )

@dataclasses.dataclass
class OpenBasicCommissioningWindow(tlv.Structure):
  commissioning_timeout: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="commissioning_timeout", optional=False),
    )

@dataclasses.dataclass
class DeviceTypeStruct(tlv.Structure):
  device_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
  revision: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="device_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="revision", optional=False),
    )

@dataclasses.dataclass
class SemanticTagStruct(tlv.Structure):
  mfg_code: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  namespace_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  tag: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  label: typing.Optional[str] = dataclasses.field(metadata={'min_len': 0, 'max_len': 64})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="mfg_code", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="namespace_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="tag", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="label", optional=True),
    )

@dataclasses.dataclass
class NetworkInfoStruct(tlv.Structure):
  network_id: bytes = dataclasses.field(metadata={'min_len': 1, 'max_len': 32})
  connected: bool

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="network_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="connected", optional=False),
    )

class AccessControlEntryPrivilegeEnumEnum(enum.IntEnum):
  View = 1
  ProxyView = 2
  Operate = 3
  Manage = 4
  Administer = 5

class AccessControlEntryAuthModeEnumEnum(enum.IntEnum):
  PASE = 1
  CASE = 2
  Group = 3

@dataclasses.dataclass
class AccessControlTargetStruct(tlv.Structure):
  cluster: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
  endpoint: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  device_type: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="cluster", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="endpoint", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="device_type", optional=False),
    )

@dataclasses.dataclass
class AccessControlEntryStruct(tlv.Structure):
  privilege: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  auth_mode: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  subjects: typing.List[int] | tlv.Null = dataclasses.field(metadata={'is_list': False, 'base_meta': {'signed': False, 'min': 0, 'max': 18446744073709551615}})
  targets: typing.List[typing.ForwardRef("AccessControlTargetStruct")] | tlv.Null = dataclasses.field(metadata={'is_list': False})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="privilege", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="auth_mode", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="subjects", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="targets", optional=False),
    )

@dataclasses.dataclass
class AccessControlExtensionStruct(tlv.Structure):
  data: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 128})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="data", optional=False),
    )

class IdentifyTypeEnumEnum(enum.IntEnum):
  NoIndication = 0
  LightOutput = 1
  VisibleIndicator = 2
  AudibleBeep = 3
  Display = 4
  Actuator = 5

@dataclasses.dataclass
class IdentifyRequest(tlv.Structure):
  identify_time: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="identify_time", optional=False),
    )

class LockStateEnum(enum.IntEnum):
  NotFullyLocked = 0
  Locked = 1
  Unlocked = 2
  Unlatched = 3

class LockTypeEnum(enum.IntEnum):
  DeadBolt = 0
  Magnetic = 1
  Other = 2
  Mortise = 3
  Rim = 4
  LatchBolt = 5
  CylindricalLock = 6
  TubularLock = 7
  InterconnectedLock = 8
  DeadLatch = 9
  DoorFurniture = 10
  Eurocylinder = 11

class CredentialRuleEnum(enum.IntEnum):
  Single = 0
  Dual = 1
  Tri = 2

class UserStatusEnum(enum.IntEnum):
  Available = 0
  OccupiedEnabled = 1
  OccupiedDisabled = 3

class UserTypeEnum(enum.IntEnum):
  UnrestrictedUser = 0
  NonAccessUser = 4
  ForcedUser = 5
  DisposableUser = 6
  ExpiringUser = 7

class CredentialTypeEnum(enum.IntEnum):
  ProgrammingPIN = 0
  PIN = 1
  RFID = 2
  Fingerprint = 3
  FingerVein = 4
  Face = 5
  AliroCredentialIssuerKey = 6
  AliroEvictableEndpointKey = 7
  AliroNonEvictableEndpointKey = 8

class DataOperationTypeEnum(enum.IntEnum):
  Add = 0
  Clear = 1
  Modify = 2

@dataclasses.dataclass
class CredentialStruct(tlv.Structure):
  credential_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  credential_index: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="credential_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="credential_index", optional=False),
    )

@dataclasses.dataclass
class LockDoorRequest(tlv.Structure):
  pin_code: typing.Optional[bytes]

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="pin_code", optional=True),
    )

@dataclasses.dataclass
class SetUserRequest(tlv.Structure):
  operation_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_index: int = dataclasses.field(metadata={'signed': False})
  user_name: str | tlv.Null = dataclasses.field(metadata={'min_len': 0, 'max_len': 10})
  user_unique_id: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
  user_status: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_type: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  credential_rule: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="operation_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="user_name", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="user_unique_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="user_status", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="user_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(6), source="credential_rule", optional=False),
    )

@dataclasses.dataclass
class GetUserRequest(tlv.Structure):
  user_index: int = dataclasses.field(metadata={'signed': False})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="user_index", optional=False),
    )

@dataclasses.dataclass
class GetUserResponse(tlv.Structure):
  user_index: int = dataclasses.field(metadata={'signed': False})
  user_name: str | tlv.Null = dataclasses.field(metadata={'min_len': 0, 'max_len': 10})
  user_unique_id: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
  user_status: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_type: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  credential_rule: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  credentials: typing.List[typing.ForwardRef("CredentialStruct")] | tlv.Null = dataclasses.field(metadata={'is_list': False})
  creator_fabric_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  last_modified_fabric_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  next_user_index: int | tlv.Null = dataclasses.field(metadata={'signed': False})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="user_name", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="user_unique_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="user_status", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="user_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="credential_rule", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(6), source="credentials", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(7), source="creator_fabric_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(8), source="last_modified_fabric_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(9), source="next_user_index", optional=False),
    )

@dataclasses.dataclass
class ClearUserRequest(tlv.Structure):
  user_index: int = dataclasses.field(metadata={'signed': False})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="user_index", optional=False),
    )

@dataclasses.dataclass
class SetCredentialRequest(tlv.Structure):
  operation_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  credential: typing.ForwardRef("CredentialStruct")
  credential_data: bytes
  user_index: int | tlv.Null = dataclasses.field(metadata={'signed': False})
  user_status: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_type: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="operation_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="credential", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="credential_data", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="user_status", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="user_type", optional=False),
    )

@dataclasses.dataclass
class SetCredentialResponse(tlv.Structure):
  status: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
  next_credential_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="status", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="next_credential_index", optional=False),
    )

@dataclasses.dataclass
class GetCredentialStatusRequest(tlv.Structure):
  credential: typing.ForwardRef("CredentialStruct")

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="credential", optional=False),
    )

@dataclasses.dataclass
class GetCredentialStatusResponse(tlv.Structure):
  credential_exists: bool
  user_index: int | tlv.Null = dataclasses.field(metadata={'signed': False})
  creator_fabric_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  last_modified_fabric_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  next_credential_index: int | tlv.Null = dataclasses.field(metadata={'signed': False})
  credential_data: bytes | tlv.Null

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="credential_exists", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="creator_fabric_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="last_modified_fabric_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="next_credential_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="credential_data", optional=False),
    )

@dataclasses.dataclass
class ClearCredentialRequest(tlv.Structure):
  credential: ('typing.ForwardRef("CredentialStruct")', None) | tlv.Null

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="credential", optional=False),
    )

@dataclasses.dataclass
class SetAliroReaderConfigRequest(tlv.Structure):
  signing_key: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
  verification_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})
  group_identifier: bytes = dataclasses.field(metadata={'min_len': 16, 'max_len': 16})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="signing_key", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="verification_key", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="group_identifier", optional=False),
    )

@dataclasses.dataclass
class DoorLockAlarm(tlv.Structure):
  alarm_code: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="alarm_code", optional=False),
    )

@dataclasses.dataclass
class DoorStateChange(tlv.Structure):
  door_state: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="door_state", optional=False),
    )

class LockOperationTypeEnum(enum.IntEnum):
  Lock = 0
  Unlock = 1
  NonAccessUserEvent = 2
  ForcedUserEvent = 3
  Unlatch = 4

class OperationSourceEnum(enum.IntEnum):
  Unspecified = 0
  Manual = 1
  ProprietaryRemote = 2
  Keypad = 3
  Auto = 4
  Button = 5
  Schedule = 6
  Remote = 7
  RFID = 8
  Biometric = 9
  Aliro = 10

@dataclasses.dataclass
class LockOperation(tlv.Structure):
  lock_operation_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  operation_source: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_index: int | tlv.Null = dataclasses.field(metadata={'signed': False})
  fabric_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  source_node: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
  credentials: typing.List[typing.ForwardRef("CredentialStruct")] | tlv.Null = dataclasses.field(metadata={'is_list': False})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="lock_operation_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="operation_source", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="fabric_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="source_node", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="credentials", optional=False),
    )

@dataclasses.dataclass
class LockOperationError(tlv.Structure):
  lock_operation_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  operation_source: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  operation_error: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_index: int | tlv.Null = dataclasses.field(metadata={'signed': False})
  fabric_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  source_node: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
  credentials: typing.List[typing.ForwardRef("CredentialStruct")] | tlv.Null = dataclasses.field(metadata={'is_list': False})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="lock_operation_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="operation_source", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="operation_error", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="fabric_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="source_node", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(6), source="credentials", optional=False),
    )

class LockDataTypeEnum(enum.IntEnum):
  Unspecified = 0
  ProgrammingCode = 1
  UserIndex = 2
  WeekDaySchedule = 3
  YearDaySchedule = 4
  HolidaySchedule = 5
  PIN = 6
  RFID = 7
  Fingerprint = 8
  FingerVein = 9
  Face = 10
  AliroCredentialIssuerKey = 11
  AliroEvictableEndpointKey = 12
  AliroNonEvictableEndpointKey = 13

@dataclasses.dataclass
class LockUserChange(tlv.Structure):
  lock_data_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  data_operation_type: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  operation_source: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  user_index: int | tlv.Null = dataclasses.field(metadata={'signed': False})
  fabric_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 1, 'max': 254})
  source_node: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 18446744073709551615})
  data_index: int | tlv.Null = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(0), source="lock_data_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="data_operation_type", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="operation_source", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="user_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="fabric_index", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="source_node", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(6), source="data_index", optional=False),
    )


class SecureChannelProtocol:
  protocol_vendor_id = 0
  protocol_id = 0

  @dataclasses.dataclass
  class SessionParameterStruct(tlv.Structure):
    SESSION_IDLE_INTERVAL: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
    SESSION_ACTIVE_INTERVAL: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
    SESSION_ACTIVE_THRESHOLD: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    DATA_MODEL_REVISION: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    INTERACTION_MODEL_REVISION: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    SPECIFICATION_VERSION: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
    MAX_PATHS_PER_INVOKE: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    SUPPORTED_TRANSPORTS: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    MAX_TCP_MESSAGE_SIZE: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="SESSION_IDLE_INTERVAL", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="SESSION_ACTIVE_INTERVAL", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="SESSION_ACTIVE_THRESHOLD", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="DATA_MODEL_REVISION", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="INTERACTION_MODEL_REVISION", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(6), source="SPECIFICATION_VERSION", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(7), source="MAX_PATHS_PER_INVOKE", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(8), source="SUPPORTED_TRANSPORTS", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(9), source="MAX_TCP_MESSAGE_SIZE", optional=True),
      )

  @dataclasses.dataclass
  class CryptoPBKDFParameterSet(tlv.Structure):
    iterations: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
    salt: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 16, 'max_len': 32})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="iterations", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="salt", optional=True),
      )

  @dataclasses.dataclass
  class PbkdfparamreqStruct(tlv.Structure):
    initiator_random: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
    initiator_session_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    passcode_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    has_pbkdf_parameters: bool
    initiator_session_params: typing.Optional[typing.ForwardRef("SecureChannelProtocol.SessionParameterStruct")]

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="initiator_random", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="initiator_session_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="passcode_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="has_pbkdf_parameters", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="initiator_session_params", optional=True),
      )

  @dataclasses.dataclass
  class PbkdfparamrespStruct(tlv.Structure):
    initiator_random: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
    responder_random: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
    responder_session_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    pbkdf_parameters: typing.ForwardRef("SecureChannelProtocol.CryptoPBKDFParameterSet")
    responder_session_params: typing.Optional[typing.ForwardRef("SecureChannelProtocol.SessionParameterStruct")]

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="initiator_random", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="responder_random", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="responder_session_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="pbkdf_parameters", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="responder_session_params", optional=True),
      )

  @dataclasses.dataclass
  class Pake1Struct(tlv.Structure):
    p_a: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="p_a", optional=False),
      )

  @dataclasses.dataclass
  class Pake2Struct(tlv.Structure):
    p_b: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})
    c_b: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="p_b", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="c_b", optional=False),
      )

  @dataclasses.dataclass
  class Pake3Struct(tlv.Structure):
    c_a: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="c_a", optional=False),
      )

  @dataclasses.dataclass
  class Sigma1Struct(tlv.Structure):
    initiator_random: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
    initiator_session_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    destination_id: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
    initiator_eph_pub_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})
    initiator_session_params: typing.Optional[typing.ForwardRef("SecureChannelProtocol.SessionParameterStruct")]
    resumption_id: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 16, 'max_len': 16})
    initiator_resume_mic: typing.Optional[bytes] = dataclasses.field(metadata={'min_len': 16, 'max_len': 16})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="initiator_random", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="initiator_session_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="destination_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="initiator_eph_pub_key", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="initiator_session_params", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(6), source="resumption_id", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(7), source="initiator_resume_mic", optional=True),
      )

  @dataclasses.dataclass
  class Sigma2Tbsdata(tlv.Structure):
    responder_noc: bytes
    responder_icac: typing.Optional[bytes]
    responder_eph_pub_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})
    initiator_eph_pub_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="responder_noc", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="responder_icac", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="responder_eph_pub_key", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="initiator_eph_pub_key", optional=False),
      )

  @dataclasses.dataclass
  class Sigma2Tbedata(tlv.Structure):
    responder_noc: bytes
    responder_icac: typing.Optional[bytes]
    signature: bytes = dataclasses.field(metadata={'min_len': 64, 'max_len': 64})
    resumption_id: bytes = dataclasses.field(metadata={'min_len': 16, 'max_len': 16})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="responder_noc", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="responder_icac", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="signature", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="resumption_id", optional=False),
      )

  @dataclasses.dataclass
  class Sigma2Struct(tlv.Structure):
    responder_random: bytes = dataclasses.field(metadata={'min_len': 32, 'max_len': 32})
    responder_session_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    responder_eph_pub_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})
    encrypted2: bytes
    responder_session_params: typing.Optional[typing.ForwardRef("SecureChannelProtocol.SessionParameterStruct")]

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="responder_random", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="responder_session_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="responder_eph_pub_key", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="encrypted2", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(5), source="responder_session_params", optional=True),
      )

  @dataclasses.dataclass
  class Sigma3Tbsdata(tlv.Structure):
    initiator_noc: bytes
    initiator_icac: typing.Optional[bytes]
    initiator_eph_pub_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})
    responder_eph_pub_key: bytes = dataclasses.field(metadata={'min_len': 65, 'max_len': 65})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="initiator_noc", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="initiator_icac", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="initiator_eph_pub_key", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="responder_eph_pub_key", optional=False),
      )

  @dataclasses.dataclass
  class Sigma3Tbedata(tlv.Structure):
    initiator_noc: bytes
    initiator_icac: typing.Optional[bytes]
    signature: bytes = dataclasses.field(metadata={'min_len': 64, 'max_len': 64})

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="initiator_noc", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="initiator_icac", optional=True),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="signature", optional=False),
      )

  @dataclasses.dataclass
  class Sigma3Struct(tlv.Structure):
    encrypted3: bytes

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="encrypted3", optional=False),
      )

  @dataclasses.dataclass
  class Sigma2ResumeStruct(tlv.Structure):
    resumption_id: bytes = dataclasses.field(metadata={'min_len': 16, 'max_len': 16})
    sigma2_resume_mic: bytes = dataclasses.field(metadata={'min_len': 16, 'max_len': 16})
    responder_session_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 65535})
    responder_session_params: typing.Optional[typing.ForwardRef("SecureChannelProtocol.SessionParameterStruct")]

    class Meta:
      implicit_vendor_id = 0
      implicit_profile = 0
      order = "tag"
      extensible = False
      fields = (
        tlv.Field(tag=tlv.ContextSpecificTag(1), source="resumption_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(2), source="sigma2_resume_mic", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(3), source="responder_session_id", optional=False),
        tlv.Field(tag=tlv.ContextSpecificTag(4), source="responder_session_params", optional=True),
      )


class SignatureAlgorithmEnum(enum.IntEnum):
  EcdsaWithSha256 = 1

@dataclasses.dataclass
class DnAttribute(tlv.ChoiceOf):
  variant: str
  value: typing.Union[str, int]

  class Meta:
    options = (
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(1), name="common-name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(2), name="surname", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(3), name="serial-num", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(4), name="country-name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(5), name="locality-name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(6), name="state-or-province-name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(7), name="org-name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(8), name="org-unit-name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(9), name="title", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(10), name="name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(11), name="given-name", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(12), name="initials", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(13), name="gen-qualifier", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(14), name="dn-qualifier", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(15), name="pseudonym", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(16), name="domain-component", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(17), name="matter-node-id", type=int, annotation={'signed': False}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(18), name="matter-firmware-signing-id", type=int, annotation={'signed': False}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(19), name="matter-icac-id", type=int, annotation={'signed': False}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(20), name="matter-rcac-id", type=int, annotation={'signed': False}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(21), name="matter-fabric-id", type=int, annotation={'signed': False}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(22), name="matter-noc-cat", type=int, annotation={'signed': False}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(23), name="matter-vvs-id", type=int, annotation={'signed': False}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(129), name="common-name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(130), name="surname-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(131), name="serial-num-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(132), name="country-name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(133), name="locality-name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(134), name="state-or-province-name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(135), name="org-name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(136), name="org-unit-name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(137), name="title-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(138), name="name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(139), name="given-name-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(140), name="initials-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(141), name="gen-qualifier-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(142), name="dn-qualifier-ps", type=str, annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(143), name="pseudonym-ps", type=str, annotation={}),
    )

class PublicKeyAlgorithmEnum(enum.IntEnum):
  EcPubKey = 1

class EllipticCurveIdEnum(enum.IntEnum):
  Prime256v1 = 1

@dataclasses.dataclass
class BasicConstraints(tlv.Structure):
  is_ca: bool
  path_len_constraint: typing.Optional[int] = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="is_ca", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="path_len_constraint", optional=True),
    )

class KeyUsageFlagEnum(enum.IntEnum):
  DigitalSignature = 1
  NonRepudiation = 2
  KeyEncipherment = 4
  DataEncipherment = 8
  KeyAgreement = 16
  KeyCertSign = 32
  CRLSign = 64
  EncipherOnly = 128
  DecipherOnly = 256

@dataclasses.dataclass
class Extension(tlv.ChoiceOf):
  variant: str
  value: typing.Union[typing.ForwardRef("BasicConstraints"), typing.List[int], bytes, int]

  class Meta:
    options = (
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(1), name="basic-cnstr", type=typing.ForwardRef("BasicConstraints"), annotation={}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(2), name="key-usage", type=int, annotation={'signed': False, 'min': 0, 'max': 65535}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(3), name="extended-key-usage", type=typing.List[int], annotation={'is_list': False, 'base_meta': {'signed': False, 'min': 0, 'max': 255}, 'min_len': 1}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(4), name="subject-key-id", type=bytes, annotation={'min_len': 20, 'max_len': 20}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(5), name="authority-key-id", type=bytes, annotation={'min_len': 20, 'max_len': 20}),
      tlv.ChoiceField(tag=tlv.ContextSpecificTag(6), name="future-extension", type=bytes, annotation={}),
    )

@dataclasses.dataclass
class MatterCertificate(tlv.Structure):
  serial_num: bytes = dataclasses.field(metadata={'min_len': 0, 'max_len': 20})
  sig_algo: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  issuer: typing.List[typing.ForwardRef("DnAttribute")] = dataclasses.field(metadata={'is_list': True, 'min_len': 1})
  not_before: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
  not_after: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 4294967295})
  subject: typing.List[typing.ForwardRef("DnAttribute")] = dataclasses.field(metadata={'is_list': True, 'min_len': 1})
  pub_key_algo: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  ec_curve_id: int = dataclasses.field(metadata={'signed': False, 'min': 0, 'max': 255})
  ec_pub_key: bytes
  extensions: typing.List[typing.ForwardRef("Extension")] = dataclasses.field(metadata={'is_list': True, 'min_len': 1})
  signature: bytes = dataclasses.field(metadata={'min_len': 64, 'max_len': 64})

  class Meta:
    order = "tag"
    extensible = False
    fields = (
      tlv.Field(tag=tlv.ContextSpecificTag(1), source="serial_num", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(2), source="sig_algo", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(3), source="issuer", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(4), source="not_before", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(5), source="not_after", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(6), source="subject", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(7), source="pub_key_algo", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(8), source="ec_curve_id", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(9), source="ec_pub_key", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(10), source="extensions", optional=False),
      tlv.Field(tag=tlv.ContextSpecificTag(11), source="signature", optional=False),
    )


