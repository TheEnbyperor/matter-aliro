import logging
import asyncio
import aiocoap.interfaces
import aiocoap.message
import aiocoap.tokenmanager
import aiocoap.messagemanager
import aiocoap.pipe
import hashlib
from . import dtls

class Device:
    spki_fingerprint: bytes

    def __str__(self):
        return f"Device({':'.join(f'{b:02X}' for b in self.spki_fingerprint)})"

class CoAPDTLS:
    def __init__(self, mman, loop, bind):
        self.mman = mman
        self.loop = loop
        self.server = dtls.DTLSServer(bind)

        self.server.set_client_cert_types((dtls.WOLFSSL_CERT_TYPE_RPK,))
        self.server.set_server_cert_types((dtls.WOLFSSL_CERT_TYPE_RPK,))
        self.server.set_certificate_file("server-cert.der", False)
        self.server.set_private_key_file("server-key.der", False)
        self.server.set_verify(dtls.WOLFSSL_VERIFY_PEER, self.verify_peer_certificate)

        self.devices = {}

        asyncio.create_task(self.accept_connections())

    @staticmethod
    def verify_peer_certificate(_, ctx: dtls.X509StoreContext):
        certs = ctx.certs
        if len(certs) != 1:
            return False

        device_id = hashlib.sha256(certs[0]).digest()
        ctx.connection_extra_data["device"] = device_id
        return True

    async def accept_connections(self):
        async for conn in self.server.run(self.mman.loop):
            asyncio.create_task(self.process_connection(conn))

    async def process_connection(self, conn: dtls.DTLSConnection):
        remote = CoAPDTLSConnection(conn)
        while data := await conn.read():
            message = aiocoap.message.Message.decode(data, remote=remote)
            self.mman.dispatch_message(message)

    def send(self, message: aiocoap.message.Message):
        data = message.encode()
        asyncio.create_task(message.remote.conn.write(data, loop=self.mman.loop))


class CoAPDTLSConnection(aiocoap.interfaces.EndpointAddress):
    def __init__(self, conn: dtls.DTLSConnection):
        self.conn = conn

    @property
    def scheme(self):
        return "coaps"

    @property
    def is_multicast(self):
        return False

    @property
    def is_multicast_locally(self):
        return False

    @property
    def hostinfo_local(self):
        addr = self.conn.address_local
        return f"[{addr[0]}]:{addr[1]}"

    @property
    def hostinfo(self):
        addr = self.conn.address
        return f"[{addr[0]}]:{addr[1]}"

    @property
    def uri_base_local(self):
        return f"{self.scheme}://{self.hostinfo_local}"

    @property
    def uri_base(self):
        return f"{self.scheme}://{self.hostinfo}"

    @property
    def blockwise_key(self):
        return self.conn

    @property
    def device(self):
        return self.conn.extra_data["device"]

    @property
    def authenticated_claims(self):
        return (self.device,)

    def __str__(self):
        return self.uri_base


class CoAPServer:
    def __init__(self, site, transport, *args):
        self.log = logging.getLogger("CoAPServer")
        self.loop = asyncio.get_event_loop()
        self.site = site
        self.tman = aiocoap.tokenmanager.TokenManager(self)
        self.mman = aiocoap.messagemanager.MessageManager(self.tman)
        self.mman.message_interface = transport(self.mman, self.loop, *args)
        self.tman.token_interface = self.mman

    def render_to_pipe(self, pipe):
        pr_that_can_receive_errors = aiocoap.pipe.error_to_message(pipe, self.log)
        aiocoap.pipe.run_driving_pipe(
            pr_that_can_receive_errors,
            self.site.render_to_pipe(pipe),
            name="Rendering for %r" % pipe.request,
        )