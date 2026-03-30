import abc
import typing
from .. import encoding
from . import message_layer, messages

class Protocol(metaclass=abc.ABCMeta):
    def __init__(self, layer: message_layer.MessageLayer):
        self._message_layer = layer
        self._in_flight_exchanges = set()
        self._pending_messages = {}

    @property
    def message_layer(self):
        return self._message_layer

    @property
    @abc.abstractmethod
    def protocol_vendor_id(self) -> int:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def protocol_id(self) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_message(self, exchange: "message_layer.Exchange", opcode: int, message: bytes):
        raise NotImplementedError()

    @abc.abstractmethod
    def handle_status_report(self, exchange: "message_layer.Exchange", general_code: messages.GeneralCode, protocol_code: int, protocol_data: bytes):
        raise NotImplementedError()

    def send_status_report(self, exchange: "message_layer.Exchange", general_code: messages.GeneralCode, protocol_code: typing.Optional[int] = None, protocol_data: typing.Optional[bytes] = None):
        status_report = messages.StatusReport(
            general_code=general_code,
            protocol_vendor_id=self.protocol_vendor_id,
            protocol_id=self.protocol_id,
            protocol_code=protocol_code if protocol_code is not None else 0xFFFF,
            protocol_data=protocol_data or b"",
        )
        self._message_layer.send_message(
            exchange=exchange,
            protocol_vendor_id=0,
            protocol_id=0,
            protocol_opcode=0x40,
            payload=status_report.encode_to_bytes(),
            reliability=True
        )

    def send_message(
            self,
            exchange: "message_layer.Exchange",
            opcode: int,
            message: typing.Union[encoding.Encodable, bytes],
            reliability: bool = True
    ):
        if isinstance(message, encoding.Encodable):
            message = message.encode_to_bytes()

        if exchange in self._in_flight_exchanges:
            if exchange not in self._pending_messages:
                self._pending_messages[exchange] = []
            self._pending_messages[exchange].append((opcode, message, reliability))
        else:
            self._in_flight_exchanges.add(exchange)
            self._message_layer.send_message(
                exchange=exchange,
                protocol_vendor_id=self.protocol_vendor_id,
                protocol_id=self.protocol_id,
                protocol_opcode=opcode,
                payload=message,
                reliability=reliability
            )

    def release_next_message(self, exchange: "message_layer.Exchange"):
        if pending_payloads := self._pending_messages.get(exchange, []):
            opcode, message, reliability = pending_payloads.pop(0)
            self._message_layer.send_message(
                exchange=exchange,
                protocol_vendor_id=self.protocol_vendor_id,
                protocol_id=self.protocol_id,
                protocol_opcode=opcode,
                payload=message,
                reliability=reliability
            )
            if len(pending_payloads) == 0:
                del self._pending_messages[exchange]
        else:
            if exchange in self._in_flight_exchanges:
                self._in_flight_exchanges.remove(exchange)