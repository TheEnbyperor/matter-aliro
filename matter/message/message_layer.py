import logging
import socket
import random
import time
import abc
import typing
import enum
import dataclasses
import threading
import cryptography.exceptions
import cryptography.hazmat.primitives.ciphers.aead
from .. import device, crypto
from ..crypto import secure_channel, certs
from . import protocol, messages

logger = logging.getLogger(__name__)

# Per § 4.12.8
MRP_MAX_TRANSMISSIONS = 5
MRP_BACKOFF_BASE = 1.6
MRP_BACKOFF_JITTER = 0.25
MRP_BACKOFF_MARGIN = 1.1
MRP_BACKOFF_THRESHOLD = 1
MRP_STANDALONE_ACK_TIMEOUT = 0.2

# Per § 4.13.1
SESSION_IDLE_INTERVAL = 0.5
SESSION_ACTIVE_INTERVAL = 0.3
SESSION_ACTIVE_THRESHOLD = 4.0

class NetworkChannel(metaclass=abc.ABCMeta):
    is_reliable: bool

    @abc.abstractmethod
    def send_frame(self, frame: bytes) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def __hash__(self) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def __eq__(self, other: typing.Any) -> bool:
        raise NotImplementedError()


class UDPChannel(NetworkChannel):
    is_reliable = False

    def __init__(self, sock: socket.socket, peer_addr: typing.Any):
        self.socket = sock
        self.peer_addr = peer_addr

    def send_frame(self, frame: bytes) -> None:
        try:
            self.socket.sendto(frame, self.peer_addr)
        except OSError:
            pass

    def __hash__(self) -> int:
        return hash(self.peer_addr)

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, UDPChannel):
            return False
        return self.peer_addr == other.peer_addr

class Role(enum.Enum):
    Initiator = enum.auto()
    Responder = enum.auto()

@dataclasses.dataclass
class MessageReceptionState:
    # Per § 4.11.2
    MSG_COUNTER_WINDOW_SIZE = 32

    max_message_counter: int
    reception_bitmap: int

    @classmethod
    def init(cls, initial_counter: int) -> "MessageReceptionState":
        return cls(
            max_message_counter=initial_counter,
            reception_bitmap=(2 ** 32) - 1,
        )

    def _counter_in_range(self, counter: int) -> bool:
        in_range = {(self.max_message_counter - i) % 2 ** 32 for i in range(1, self.MSG_COUNTER_WINDOW_SIZE + 1)}
        return counter in in_range

    def _in_range_duplicate(self, counter: int) -> bool:
        position = (self.max_message_counter - 1 - counter) % 2 ** 32
        if self.reception_bitmap & (1 << position):
            return True
        else:
            self.reception_bitmap |= (1 << position)
            return False

    def _update_max(self, counter: int) -> None:
        self.reception_bitmap <<= (counter - self.max_message_counter) % 2 ** 32
        self.max_message_counter = counter

    # Per § 4.6.5.2
    # Returns true if a duplicate
    def process_reception_encrypted(self, counter: int, *, has_maximum: bool) -> bool:
        if counter == self.max_message_counter:
            return True

        if self._counter_in_range(counter):
            return self._in_range_duplicate(counter)
        elif has_maximum:
            if self.max_message_counter + 1 <= counter <= (2 ** 32) - 1:
                self._update_max(counter)
                return False
            else:
                return True
        else:
            in_range = {(self.max_message_counter + i) % 2 ** 32 for i in range(1, 2 ** 31)}
            if counter in in_range:
                self._update_max(counter)
                return False
            else:
                return True

    # Per § 4.6.5.3
    # Returns true if a duplicate
    def process_reception_unencrypted(self, counter: int) -> bool:
        if counter == self.max_message_counter:
            return True
        if self._counter_in_range(counter):
            return self._in_range_duplicate(counter)
        else:
            self._update_max(counter)
            return False

class SessionContext(metaclass=abc.ABCMeta):
    local_fabric_index: int
    peer_node_id: int
    attestation_challenge: bytes


@dataclasses.dataclass
class UnsecuredSessionContext(SessionContext):
    peer: NetworkChannel
    session_role: Role
    ephemeral_initiator_node_id: bytes
    message_reception_state: MessageReceptionState
    local_fabric_index: int = 0

    def __hash__(self) -> int:
        return hash((self.session_role, self.ephemeral_initiator_node_id, self.peer))

    def __eq__(self, other) -> bool:
        if not isinstance(other, UnsecuredSessionContext):
            return False
        if self.session_role != other.session_role:
            return False
        if self.ephemeral_initiator_node_id != other.ephemeral_initiator_node_id:
            return False
        if self.peer != other.peer:
            return False
        return True

    def __str__(self):
        role = "I" if self.session_role == Role.Initiator else "R"
        return f"UU:{role}:{self.ephemeral_initiator_node_id.hex():>016}"

    @property
    def peer_node_id(self) -> int:
        return 0

    @property
    def cats(self) -> typing.List[certs.CAT]:
        return []

    @property
    def attestation_challenge(self) -> bytes:
        return b""

class SecureSessionType(enum.Enum):
    PASE = enum.auto()
    CASE = enum.auto()

@dataclasses.dataclass
class SecureSessionContext(SessionContext):
    peer: NetworkChannel
    session_type: SecureSessionType
    session_role: Role
    local_session_identifier: int
    peer_session_identifier: int
    i2r_key: bytes
    r2i_key: bytes
    shared_secret: bytes
    local_message_counter: int
    message_reception_state: MessageReceptionState
    resumption_id: bytes
    local_fabric_index: int
    local_node_id: int
    peer_node_id: int
    cats: typing.List[certs.CAT]
    attestation_challenge: bytes
    session_timestamp: float = dataclasses.field(default_factory=time.time)
    active_timestamp: float = dataclasses.field(default_factory=time.time)
    session_idle_interval: float = SESSION_IDLE_INTERVAL
    session_active_interval: float = SESSION_ACTIVE_INTERVAL
    session_active_threshold: float = SESSION_ACTIVE_THRESHOLD

    def __hash__(self) -> int:
        return hash((self.session_type, self.session_role, self.local_session_identifier, self.peer_session_identifier))

    def __eq__(self, other) -> bool:
        if not isinstance(other, SecureSessionContext):
            return False
        if self.session_type != other.session_type:
            return False
        if self.session_role != other.session_role:
            return False
        if self.local_session_identifier != other.local_session_identifier:
            return False
        if self.peer_session_identifier != other.peer_session_identifier:
            return False
        return True

    def __str__(self):
        session_type = "P" if self.session_type == SecureSessionType.PASE else "C"
        role = "I" if self.session_role == Role.Initiator else "R"
        return f"SU:{session_type}:{role}:{self.local_session_identifier:04X}"

    def peer_active_mode(self) -> bool:
        return (time.time() - self.active_timestamp) < self.session_active_threshold

@dataclasses.dataclass
class ExchangeRetransmission:
    frame: bytes
    send_count: int
    retransmission_timeout_counter: int
    timer: threading.Timer


@dataclasses.dataclass
class ExchangeAcknowledgement:
    message_counter: int
    standalone_acknowledgement_sent: bool


@dataclasses.dataclass
class Exchange:
    exchange_id: int
    exchange_role: Role
    context: SessionContext
    ephemeral: bool
    retransmissions: typing.Dict[int, ExchangeRetransmission] = dataclasses.field(default_factory=dict)
    acknowledgement: typing.Optional[ExchangeAcknowledgement] = None
    standalone_acknowledgement_timer: typing.Optional[threading.Timer] = None
    closing: bool = False

    def __hash__(self) -> int:
        return hash((self.exchange_id, self.exchange_role, self.context))

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, Exchange):
            return False
        if self.exchange_id != other.exchange_id:
            return False
        if self.exchange_role != other.exchange_role:
            return False
        if self.context != other.context:
            return False
        return True

    def __str__(self):
        role = "I" if self.exchange_role == Role.Initiator else "R"
        return f"({self.context}):{role}:{self.exchange_id:04X}"

class MessageLayer:
    protocols: typing.Dict[typing.Tuple[int, int], protocol.Protocol]
    unsecured_session_context: typing.Dict[bytes, UnsecuredSessionContext]
    secure_unicast_session_context: typing.Dict[int, SecureSessionContext]
    exchanges: typing.Set[Exchange]

    def __init__(self, device_state: device.DeviceState):
        self.device_state = device_state
        self.port = 5451
        self.matter_udp_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.matter_udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.matter_udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.matter_udp_socket.bind(("", self.port))

        self.global_unencrypted_message_counter = random.randint(1, 2 ** 28)
        self.unsecured_session_context = {}
        self.secure_unicast_session_context = {}
        self.exchanges = set()
        self.in_use_session_ids = set()
        self.next_exchange_id = random.randint(0, 2 ** 16)
        self.protocols = {}
        self.register_protocol_handler(secure_channel.SecureChannel(self, device_state))

    def register_protocol_handler(self, handler: protocol.Protocol):
        self.protocols[(handler.protocol_vendor_id, handler.protocol_id)] = handler

    def process_matter_udp_packets(self):
        while True:
            buf, addr = self.matter_udp_socket.recvfrom(9000)
            try:
                frame = messages.MatterFrame.decode_from_bytes(buf)
            except ValueError as e:
                logger.warning(f"Failed to decode Matter frame: {e}")
                continue
            self.process_recv_matter_frame(
                frame, UDPChannel(self.matter_udp_socket, addr),
                is_unreliable_transport=True
            )

    def process_recv_matter_frame(
            self, frame: messages.MatterFrame, peer: NetworkChannel,
            is_unreliable_transport: bool = True
    ):
        # Message validity checks per § 4.7.2.1
        # § 4.7.2.1.a
        if frame.version != 0:
            logger.warning(f"Invalid frame: invalid version {frame.version}")
            return
        # § 4.7.2.1.b
        if frame.is_secure_unicast_session:
            # § 4.7.2.1.b.i
            if frame.destination_group_id:
                logger.warning("Invalid frame: secure unicast session with group ID destination")
                return
        # § 4.7.2.1.c
        if frame.is_group_session:
            # § 4.7.2.1.c.i
            if not frame.destination_node_id and not frame.destination_group_id:
                logger.warning("Invalid frame: group session without destination ID")
                return
            # § 4.7.2.1.c.ii
            if not frame.source_node_id:
                logger.warning("Invalid frame: group session without source node ID")
                return

        # Secured message handling per § 4.7.2.2
        if not frame.is_unsecured_session:
            if frame.session_id in self.secure_unicast_session_context:
                session_context = self.secure_unicast_session_context[frame.session_id]
                if frame.privacy:
                    logger.warning("Unimplemented: frame privacy")
                    return

                # Per § 4.8.3
                if session_context.session_role == Role.Initiator:
                    k = session_context.r2i_key
                else:
                    k = session_context.i2r_key

                cipher = cryptography.hazmat.primitives.ciphers.aead.AESCCM(k, tag_length=crypto.CRYPTO_AEAD_MIC_LENGTH_BYTES)

                nonce = bytearray()
                nonce.extend(frame.security_flags)
                nonce.extend(frame.message_counter.to_bytes(4, "little"))
                nonce.extend(session_context.peer_node_id.to_bytes(8, "little"))
                try:
                    payload = cipher.decrypt(nonce, frame.payload, frame.authenticated_header)
                except cryptography.exceptions.InvalidTag:
                    logger.warning("Invalid frame AEAD tag")
                    return
            else:
                logger.debug("Unimplemented: group secured frames")
                return
        else:
            payload = frame.payload

        # Replay and duplicate protection per § 4.7.2.3
        is_duplicate = False
        session_context = None
        if frame.is_secure_unicast_session:
            session_context = self.secure_unicast_session_context[frame.session_id]
            session_context.peer = peer
            if session_context.message_reception_state.process_reception_encrypted(frame.message_counter, has_maximum=True):
                is_duplicate = True
        elif frame.is_group_session:
            # Handling per § 4.6.7.b
            # TODO: implement
            logger.warning("Unimplemented: group session")
            return
        elif frame.is_unsecured_session:
            # Handling per § 4.13.2.1
            if frame.source_node_id in self.unsecured_session_context and self.unsecured_session_context[frame.source_node_id].session_role == Role.Responder:
                session_context = self.unsecured_session_context[frame.source_node_id]
                session_context.peer = peer
                if session_context.message_reception_state.process_reception_unencrypted(frame.message_counter):
                    is_duplicate = True
            elif frame.destination_node_id in self.unsecured_session_context and self.unsecured_session_context[frame.destination_node_id].session_role == Role.Initiator:
                session_context = self.unsecured_session_context[frame.source_node_id]
                session_context.peer = peer
                if session_context.message_reception_state.process_reception_unencrypted(frame.message_counter):
                    is_duplicate = True
            elif frame.source_node_id:
                session_context = UnsecuredSessionContext(
                    session_role=Role.Responder,
                    ephemeral_initiator_node_id=frame.source_node_id,
                    message_reception_state=MessageReceptionState.init(frame.message_counter),
                    peer=peer,
                )
                self.unsecured_session_context[frame.source_node_id] = session_context
            else:
                return

        try:
            message = messages.ProtocolMessage.decode_from_bytes(payload)
        except ValueError as e:
            logger.warning(f"Invalid protocol message: {e}")
            return

        # Message reliability per § 4.7.2.4
        if is_unreliable_transport:
            # Per § 4.12.5.2.1.a
            if message.reliability:
                if frame.is_group_session and not frame.control:
                    logger.warning(f"Invalid message: Non-control group message sent reliably")
                    return
            # Per § 4.12.5.2.1.b
            if message.acknowledged_message_counter is not None:
                if frame.is_group_session and not frame.control:
                    logger.warning(f"Invalid message: Non-control group message sent with acknowledgment")
                    return

            exchange = self.find_exchange(message, session_context, is_duplicate)
            if not exchange:
                return

            # Per § 4.12.5.2 - Received acknowledgement processing
            if message.acknowledged_message_counter is not None and exchange:
                if message.acknowledged_message_counter in exchange.retransmissions:
                    if exchange.retransmissions[message.acknowledged_message_counter].timer:
                        exchange.retransmissions[message.acknowledged_message_counter].timer.cancel()
                    del exchange.retransmissions[message.acknowledged_message_counter]

            # Per § 4.12.5.2 - Standalone acknowledgement processing
            if message.reliability:
                if is_duplicate:
                    self.send_standalone_acknowledgement(exchange)
                    if exchange.ephemeral:
                        self.close_exchange(exchange)
                    return
                else:
                    if exchange.acknowledgement and not exchange.acknowledgement.standalone_acknowledgement_sent:
                        if exchange.standalone_acknowledgement_timer:
                            exchange.standalone_acknowledgement_timer.cancel()
                        self.send_standalone_acknowledgement(exchange)
                    exchange.acknowledgement = ExchangeAcknowledgement(
                        frame.message_counter, standalone_acknowledgement_sent=False
                    )
                    exchange.standalone_acknowledgement_timer = threading.Timer(
                        MRP_STANDALONE_ACK_TIMEOUT,
                        self.send_standalone_acknowledgement,
                        args=(exchange,)
                    )
                    exchange.standalone_acknowledgement_timer.start()
        else:
            exchange = self.find_exchange(message, session_context, is_duplicate)
            if not exchange:
                return

        if exchange.closing:
            self.close_exchange(exchange)

        if is_duplicate:
            return

        # Setting timestamps per § 4.7.2.5
        if isinstance(session_context, SecureSessionContext):
            session_context.session_timestamp = session_context.active_timestamp = time.time()

        if not exchange.ephemeral:
            k = (message.protocol_vendor_id, message.protocol_id)
            if h := self.protocols.get(k):
                h.handle_message(exchange, message.protocol_opcode, message.payload)

    def status_report(self, exchange: Exchange, report: messages.StatusReport):
        k = (report.protocol_vendor_id, report.protocol_id)
        if h := self.protocols.get(k):
            h.handle_status_report(exchange, report.general_code, report.protocol_code, report.protocol_data)

    def send_standalone_acknowledgement(self, exchange: "Exchange"):
        if exchange.acknowledgement:
            message = messages.ProtocolMessage(
                initiator=exchange.exchange_role == Role.Initiator,
                reliability=False,
                exchange_id=exchange.exchange_id,
                acknowledged_message_counter=exchange.acknowledgement.message_counter,
                protocol_vendor_id=secure_channel.SecureChannel.protocol_vendor_id,
                protocol_id=secure_channel.SecureChannel.protocol_id,
                protocol_opcode=secure_channel.SecureChannel.OPCODE_MSG_STANDALONE_ACK,
                secured_message_extensions=None,
                payload=b""
            )
            self.send_with_session(message.encode_to_bytes(), exchange.context)
            exchange.acknowledgement.standalone_acknowledgement_sent = True
            exchange.standalone_acknowledgement_timer.cancel()

    def send_message(self, exchange: "Exchange", protocol_vendor_id: int, protocol_id: int, protocol_opcode: int, payload: bytes, reliability: bool = False):
        if exchange.context.peer.is_reliable:
            reliability = False
        message = messages.ProtocolMessage(
            initiator=exchange.exchange_role == Role.Initiator,
            reliability=reliability,
            exchange_id=exchange.exchange_id,
            acknowledged_message_counter=None,
            protocol_vendor_id=protocol_vendor_id,
            protocol_id=protocol_id,
            protocol_opcode=protocol_opcode,
            secured_message_extensions=None,
            payload=payload,
        )
        if exchange.acknowledgement:
            message.acknowledged_message_counter = exchange.acknowledgement.message_counter
        message_counter, frame = self.send_with_session(message.encode_to_bytes(), exchange.context)
        exchange.acknowledgement = None
        if reliability:
            t = threading.Timer(self.mrp_backoff_time(exchange.context, 0), self.retransmit, args=(exchange, message_counter,))
            t.start()
            exchange.retransmissions[message_counter] = ExchangeRetransmission(
                frame=frame,
                send_count=1,
                retransmission_timeout_counter=0,
                timer=t
            )

    def initiate_exchange(self, context: SessionContext) -> Exchange:
        exchange = Exchange(
            exchange_id=self.next_exchange_id,
            exchange_role=Role.Initiator,
            ephemeral=False,
            context=context,
        )
        self.next_exchange_id = (self.next_exchange_id + 1) % 2**16
        self.exchanges.add(exchange)
        return exchange

    @staticmethod
    def mrp_backoff_time(session_context: SessionContext, send_count: int):
        if isinstance(session_context, SecureSessionContext):
            if session_context.peer_active_mode():
                i = session_context.session_active_interval
            else:
                i = session_context.session_idle_interval
        else:
            i = SESSION_ACTIVE_INTERVAL
        return i * MRP_BACKOFF_MARGIN * (MRP_BACKOFF_BASE ** max(0, send_count - MRP_BACKOFF_THRESHOLD)) * (1.0 + random.random() * MRP_BACKOFF_JITTER)

    def retransmit(self, exchange: "Exchange", message_counter: int):
        if message_counter not in exchange.retransmissions:
            return
        retransmission = exchange.retransmissions[message_counter]
        retransmission.retransmission_timeout_counter += 1
        exchange.context.peer.send_frame(retransmission.frame)
        t = threading.Timer(self.mrp_backoff_time(exchange.context, retransmission.send_count), self.retransmit, args=(exchange, message_counter,))
        t.start()
        retransmission.send_count += 1

    def send_with_session(self, data: bytes, session_context: SessionContext) -> typing.Tuple[int, bytes]:
        if isinstance(session_context, UnsecuredSessionContext):
            frame = messages.MatterFrame(
                version=0,
                session_id=0,
                privacy=False,
                control=False,
                session_type=messages.SessionType.Unicast,
                source_node_id=None,
                destination_group_id=None,
                destination_node_id=session_context.ephemeral_initiator_node_id,
                message_counter=self.global_unencrypted_message_counter,
                message_extensions=None,
                payload=data,
            )
            self.global_unencrypted_message_counter = (self.global_unencrypted_message_counter + 1) % 2 ** 32
            d = frame.encode_to_bytes()
            session_context.peer.send_frame(d)
            return frame.message_counter, d

        elif isinstance(session_context, SecureSessionContext):
            frame = messages.MatterFrame(
                version=0,
                session_id=session_context.peer_session_identifier,
                privacy=False,
                control=False,
                session_type=messages.SessionType.Unicast,
                source_node_id=None,
                destination_group_id=None,
                destination_node_id=None,
                message_counter=session_context.local_message_counter,
                message_extensions=None,
                payload=b"",
            )
            authenticated_header = frame.encode_to_bytes()

            session_context.local_message_counter = (session_context.local_message_counter + 1) % 2 ** 32
            if session_context.local_message_counter == 0:
                del self.secure_unicast_session_context[session_context.local_session_identifier]

            session_context.session_timestamp = time.time()

            if session_context.session_role == Role.Initiator:
                k = session_context.i2r_key
            else:
                k = session_context.r2i_key

            cipher = cryptography.hazmat.primitives.ciphers.aead.AESCCM(k, tag_length=crypto.CRYPTO_AEAD_MIC_LENGTH_BYTES)

            nonce = bytearray()
            nonce.extend(authenticated_header[3:8])
            nonce.extend(session_context.local_node_id.to_bytes(8, "little"))

            enc = cipher.encrypt(nonce, data, authenticated_header)
            d = authenticated_header + enc

            session_context.peer.send_frame(d)
            return frame.message_counter, d

        else:
            raise NotImplementedError()

    def find_exchange(
            self, message: messages.ProtocolMessage, session_context: SessionContext, is_duplicate: bool
    ) -> typing.Optional[Exchange]:
        for exchange in self.exchanges:
            # Per § 4.10.5.1.1
            if exchange.context != session_context:
                continue
            # Per § 4.10.5.1.2
            if exchange.exchange_id != message.exchange_id:
                continue
            # Per § 4.10.5.1.3
            if exchange.exchange_role == Role.Responder and not message.initiator:
                continue
            if exchange.exchange_role == Role.Initiator and message.initiator:
                continue
            return exchange

        if (message.protocol_vendor_id, message.protocol_id) in self.protocols and message.initiator and not is_duplicate:
            exchange = Exchange(
                exchange_id=message.exchange_id,
                exchange_role=Role.Responder,
                ephemeral=False,
                context=session_context,
            )
            self.exchanges.add(exchange)
            return exchange
        elif message.reliability:
            exchange = Exchange(
                exchange_id=message.exchange_id,
                exchange_role=Role.Responder if message.initiator else Role.Initiator,
                ephemeral=True,
                context=session_context,
            )
            self.exchanges.add(exchange)
            return exchange
        else:
            return None

    def close_exchange(self, exchange: Exchange):
        exchange.closing = True
        if exchange.acknowledgement and not exchange.acknowledgement.standalone_acknowledgement_sent:
            self.send_standalone_acknowledgement(exchange)
            exchange.acknowledgement = None

        if len(exchange.retransmissions):
            return

        if exchange in self.exchanges:
            self.exchanges.remove(exchange)

    def allocate_session_id(self):
        if len(self.in_use_session_ids) < 0xFFFF:
            for sid in range(1, 0x10000):
                if sid not in self.in_use_session_ids:
                    self.in_use_session_ids.add(sid)
                    return sid

        raise NotImplementedError("Terminating sessions")

    def terminate_all_pase_sessions(self):
        to_remove = set()
        for sid, session in self.secure_unicast_session_context.items():
            if session.session_type == SecureSessionType.PASE:
                to_remove.add(sid)
        for sid in to_remove:
            self.secure_unicast_session_context.pop(sid)
            self.in_use_session_ids.remove(sid)