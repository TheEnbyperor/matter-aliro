import asyncio
import dataclasses
import pathlib
import traceback
import typing
import aiocoap.resource
import aiocoap.error
import asn1tools
from ..aliro import iso7816

aiocoap.ContentFormat.define(65000, media_type="application/vnd.as207960.nfc-frontend.config+uper")
aiocoap.ContentFormat.define(65001, media_type="application/vnd.as207960.nfc-frontend.config+jer")
aiocoap.ContentFormat.define(65002, media_type="application/vnd.as207960.nfc-frontend.new-target+uper")
aiocoap.ContentFormat.define(65003, media_type="application/vnd.as207960.nfc-frontend.new-target+jer")
aiocoap.ContentFormat.define(65004, media_type="application/vnd.as207960.nfc-frontend.apdu-command+uper")
aiocoap.ContentFormat.define(65005, media_type="application/vnd.as207960.nfc-frontend.apdu-command+jer")
aiocoap.ContentFormat.define(65006, media_type="application/vnd.as207960.nfc-frontend.apdu-response+uper")
aiocoap.ContentFormat.define(65007, media_type="application/vnd.as207960.nfc-frontend.apdu-response+jer")

BASE_DIR = pathlib.Path(__file__).resolve().parent

ASN_UPER = asn1tools.compile_files([BASE_DIR / "asn1" / "proto.asn"], "uper")
ASN_JER = asn1tools.compile_files([BASE_DIR / "asn1" / "proto.asn"], "jer")


@dataclasses.dataclass(frozen=True)
class MessageType:
    asn1_data_type: str
    uper_content_format: aiocoap.ContentFormat
    jer_content_format: aiocoap.ContentFormat


CONFIG_MESSAGE = MessageType(
    asn1_data_type="ReaderConfig",
    uper_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.config+uper"),
    jer_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.config+jer")
)
NEW_TARGET_MESSAGE = MessageType(
    asn1_data_type="TargetDetected",
    uper_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.new-target+uper"),
    jer_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.new-target+jer")
)
APDU_COMMAND_MESSAGE = MessageType(
    asn1_data_type="APDUCommand",
    uper_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.apdu-command+uper"),
    jer_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.apdu-command+jer")
)
APDU_RESPONSE_MESSAGE = MessageType(
    asn1_data_type="APDUResponse",
    uper_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.apdu-response+uper"),
    jer_content_format=aiocoap.ContentFormat.by_media_type("application/vnd.as207960.nfc-frontend.apdu-response+jer")
)


def render_response(request: aiocoap.Message, data, message_type: MessageType):
    accept = aiocoap.ContentFormat(request.opt.accept) if request.opt.accept else None
    if accept is None or accept == message_type.uper_content_format:
        return aiocoap.Message(
            payload=ASN_UPER.encode(message_type.asn1_data_type, data),
            content_format=message_type.uper_content_format,
        )
    elif accept == message_type.jer_content_format:
        return aiocoap.Message(
            payload=ASN_JER.encode(message_type.asn1_data_type, data),
            content_format=message_type.jer_content_format,
        )
    else:
        return aiocoap.Message(code=aiocoap.Code.NOT_ACCEPTABLE)


def parse_request(request: aiocoap.Message, message_types: typing.Iterable[MessageType]) -> typing.Tuple[MessageType, typing.Any]:
    if not request.opt.content_format:
        raise aiocoap.error.UnsupportedContentFormat()

    content_format = aiocoap.ContentFormat(request.opt.content_format)
    for message_type in message_types:
        if content_format == message_type.uper_content_format:
            try:
                data = ASN_UPER.decode(message_type.asn1_data_type, request.payload)
            except asn1tools.DecodeError:
                raise aiocoap.error.BadRequest()
            return message_type, data
        elif content_format == message_type.jer_content_format:
            try:
                data = ASN_JER.decode(message_type.asn1_data_type, request.payload)
            except (ValueError, AttributeError, IndexError):
                raise aiocoap.error.BadRequest()
            return message_type, data

    raise aiocoap.error.UnsupportedContentFormat()

class Target(iso7816.Terminal):
    def __init__(self, uid: bytes, command_queue: asyncio.Queue, response_queue: asyncio.Queue):
        self._uid = uid
        self._command_queue = command_queue
        self._response_queue = response_queue

    def __str__(self):
        return f"Target(uid={self._uid.hex().upper()})"

    def __repr__(self):
        return str(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._command_queue.shutdown(True)

    async def transmit(self, request: iso7816.RequestAPDU) -> iso7816.ResponseAPDU:
        await self._command_queue.put(request)
        try:
            return await self._response_queue.get()
        except asyncio.QueueShutDown:
            raise RuntimeError("Target gone")

class DeviceConfig(aiocoap.resource.ObservableResource):
    def __init__(self, handler: typing.Callable[[bytes], typing.Any]):
        super().__init__()
        self.handler = handler

    async def render_get(self, request):
        return render_response(request, self.handler(request.remote.device), CONFIG_MESSAGE)

@dataclasses.dataclass
class DeviceState:
    handler_task: asyncio.Task
    command: asyncio.Queue
    response: asyncio.Queue

class Interact(aiocoap.resource.Resource):
    def __init__(self, handler: typing.Callable[[bytes, Target], typing.Awaitable[None]]):
        super().__init__()
        self.handler = handler
        self.devices: typing.Dict[bytes, DeviceState] = {}

    async def handle(self, device: bytes, terminal: Target):
        with terminal as t:
            try:
                await self.handler(device, t)
            except Exception:
                traceback.print_exc()

    async def render_post(self, request):
        message_type, data = parse_request(request, message_types=[
            NEW_TARGET_MESSAGE, APDU_RESPONSE_MESSAGE
        ])
        device = request.remote.device

        if message_type == NEW_TARGET_MESSAGE:
            if device in self.devices:
                self.devices[device].response.shutdown(True)
            command_queue = asyncio.Queue(1)
            response_queue = asyncio.Queue(1)
            state = DeviceState(
                handler_task=asyncio.create_task(self.handle(
                    device,
                    Target(data["uid"], command_queue, response_queue)
                )),
                command=command_queue,
                response=response_queue,
            )
            self.devices[device] = state
        elif message_type == APDU_RESPONSE_MESSAGE:
            if device not in self.devices:
                return aiocoap.Message(code=aiocoap.Code.PRECONDITION_FAILED)
            state = self.devices[device]
            await state.response.put(iso7816.ResponseAPDU(
                data=data["data"],
                sw1=data["sw1"],
                sw2=data["sw2"],
            ))
        else:
            raise NotImplementedError()

        try:
            command: iso7816.RequestAPDU = await state.command.get()
            return render_response(request, {
                "instructionClass": command.instruction_class,
                "instruction": command.instruction,
                "p1": command.p1,
                "p2": command.p2,
                "data": command.data,
                "expectedResponseLength": command.expected_response_length,
            }, APDU_COMMAND_MESSAGE)
        except asyncio.QueueShutDown:
            return aiocoap.Message(code=aiocoap.Code.CHANGED)

    async def render_delete(self, request):
        device = request.remote.device
        if device in self.devices:
            self.devices[device].response.shutdown(True)
            del self.devices[device]
        return aiocoap.Message(code=aiocoap.Code.DELETED)

class WhoAmI(aiocoap.resource.Resource):
    @staticmethod
    async def render_get(request):
        text = [
            "Used protocol: %s." % request.remote.scheme,
            "Request came from %s." % request.remote.hostinfo,
            "The server address used %s." % request.remote.hostinfo_local
        ]

        claims = list(request.remote.authenticated_claims)
        if claims:
            text.append(
                "Authenticated claims of the client: %s."
                % ", ".join(repr(c) for c in claims)
            )
        else:
            text.append("No claims authenticated.")

        return aiocoap.Message(
            payload="\n".join(text).encode("utf8"),
            content_format=aiocoap.ContentFormat.by_media_type("text/plain; charset=utf-8")
        )