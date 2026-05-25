import logging
import secrets
import socket
import typing
import time
import asyncio
import sys
from cffi import FFI

try:
    from asyncio.queues import Queue, QueueShutDown
except ImportError:
    from backports.asyncio.queues import Queue, QueueShutDown

ffi = FFI()
if sys.platform == "darwin":
    ffi.cdef("""
    typedef unsigned char sa_family_t;
    typedef unsigned short in_port_t;
    struct sockaddr_in6 {
        uint8_t         sin6_len;
        sa_family_t     sin6_family;
        in_port_t       sin6_port;
        uint32_t        sin6_flowinfo;
        struct in6_addr sin6_addr;
        uint32_t        sin6_scope_id;
    };
    """)
else:
    ffi.cdef("""
    typedef unsigned short sa_family_t;
    typedef unsigned short in_port_t;
    struct sockaddr_in6 {
        sa_family_t     sin6_family;
        in_port_t       sin6_port;
        uint32_t        sin6_flowinfo;
        struct in6_addr sin6_addr;
        uint32_t        sin6_scope_id;
    };
    """)
ffi.cdef("""
    struct in6_addr {
       unsigned char   s6_addr[16];
    };
    
    typedef struct WOLFSSL_CRYPTO_EX_DATA {
        void* ex_data[5];
    } WOLFSSL_CRYPTO_EX_DATA;
    
    typedef ... WOLFSSL_CTX;
    typedef ... WOLFSSL_METHOD;
    typedef ... WOLFSSL;
    typedef ... WOLFSSL_STACK;
    typedef ... WOLFSSL_X509_VERIFY_PARAM;
    typedef ... WOLFSSL_X509;
    typedef ... WOLFSSL_X509_CHAIN;
    typedef ... WOLFSSL_X509_STORE;
    typedef struct WOLFSSL_X509_STORE_CTX WOLFSSL_X509_STORE_CTX;
    
    typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*);
    typedef int (*WOLFSSL_X509_STORE_CTX_verify_cb)(int, WOLFSSL_X509_STORE_CTX *);
    
    typedef struct WOLFSSL_BUFFER_INFO {
        unsigned char* buffer;
        uint32_t length;
    } WOLFSSL_BUFFER_INFO;
    
    struct WOLFSSL_X509_STORE_CTX {
        WOLFSSL_X509_STORE* store;
        WOLFSSL_X509* current_cert;
        WOLFSSL_X509* current_issuer;
        WOLFSSL_X509_CHAIN* sesChain;
        WOLFSSL_STACK* chain;
        WOLFSSL_X509_VERIFY_PARAM* param;
        char* domain;
        WOLFSSL_CRYPTO_EX_DATA ex_data;
        int depth;
        void* userCtx;
        int error;
        int error_depth;
        int discardSessionCerts;
        int totalCerts;
        WOLFSSL_BUFFER_INFO* certs;
        WOLFSSL_X509_STORE_CTX_verify_cb verify_cb;
        void* heap;
        int flags;
        WOLFSSL_STACK* owned;
        WOLFSSL_STACK* ctxIntermediates;
        WOLFSSL_STACK* setTrustedSk;
    };
    
    WOLFSSL_METHOD* wolfDTLSv1_3_server_method(void);
    
    WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);
    void         wolfSSL_CTX_free(WOLFSSL_CTX*);
    int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX*, const char*, int);
    int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX*, const char *, int);
    int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX*, const char *);
    int wolfSSL_CTX_set_client_cert_type(WOLFSSL_CTX*, const char* buf, int len);
    int wolfSSL_CTX_set_server_cert_type(WOLFSSL_CTX*, const char* buf, int len);
    void wolfSSL_CTX_set_verify(WOLFSSL_CTX*, int, VerifyCallback);
    
    WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);
    void wolfSSL_free(WOLFSSL*);
    int wolfSSL_shutdown(WOLFSSL*);
    int wolfSSL_get_error(WOLFSSL*, int);
    char* wolfSSL_ERR_error_string(int, char*);
    int wolfSSL_set_write_fd(WOLFSSL*, int);
    int wolfSSL_set_read_fd(WOLFSSL*, int);
    int wolfSSL_write(WOLFSSL*, const void*, int);
    int wolfSSL_read(WOLFSSL*, void*, int);
    int wolfSSL_accept(WOLFSSL*);
    int wolfDTLS_accept_stateless(WOLFSSL*);
    int wolfSSL_dtls_set_peer(WOLFSSL*, void*, unsigned int);
    int wolfSSL_dtls_get_peer(WOLFSSL*, void*, unsigned int*);
    int wolfSSL_dtls_set_pending_peer(WOLFSSL*, void*, unsigned int);
    const unsigned char *wolfSSL_dtls_cid_parse(const unsigned char *, unsigned int, unsigned int);
    int wolfSSL_dtls_cid_use(WOLFSSL *);
    int wolfSSL_dtls_cid_set(WOLFSSL *, unsigned char *, unsigned int);
    int wolfSSL_dtls_get_current_timeout(WOLFSSL *);
    int wolfSSL_dtls13_use_quick_timeout(WOLFSSL *);
    int wolfSSL_dtls_got_timeout(WOLFSSL *);
    int wolfSSL_dtls_set_timeout_max(WOLFSSL *, int);
    int wolfSSL_DTLS_SetCookieSecret(WOLFSSL *, const unsigned char *, unsigned int);
    int wolfSSL_inject(WOLFSSL *, const void *, int);
    void wolfSSL_SetIOReadFlags(WOLFSSL*, int flags);
    void wolfSSL_SSLDisableRead(WOLFSSL*);
    int wolfSSL_is_init_finished(WOLFSSL *);
    
    void* wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX*, int);
    int wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);
    
    void wolfSSL_Debugging_ON();
    void wolfSSL_Debugging_OFF();
""")
lib = ffi.dlopen("wolfssl")

WOLFSSL_CERT_TYPE_X509 = 0
WOLFSSL_CERT_TYPE_RPK = 2

WOLFSSL_VERIFY_NONE = 0
WOLFSSL_VERIFY_PEER = 1 << 0
WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT = 1 << 1
WOLFSSL_VERIFY_CLIENT_ONCE = 1 << 2
WOLFSSL_VERIFY_POST_HANDSHAKE = 1 << 3
WOLFSSL_VERIFY_FAIL_EXCEPT_PSK = 1 << 4
WOLFSSL_VERIFY_DEFAULT = 1 << 9

def make_sockaddr_in6(ip: str, port: int, flowinfo: int, scope: int):
    sa6 = ffi.new("struct sockaddr_in6 *")
    if sys.platform == "darwin":
        sa6.sin6_len = ffi.sizeof("struct sockaddr_in6")
    sa6.sin6_family = socket.AF_INET6
    sa6.sin6_port = socket.htons(port)
    sa6.sin6_flowinfo = flowinfo
    packed = socket.inet_pton(socket.AF_INET6, ip)
    ffi.memmove(sa6.sin6_addr.s6_addr, packed, 16)
    sa6.sin6_scope_id = scope
    return sa6, ffi.sizeof("struct sockaddr_in6")

def err_code_to_str(err_code):
    e_buf = ffi.new("unsigned char[255]")
    return ffi.string(lib.wolfSSL_ERR_error_string(err_code, e_buf)).decode()

class DTLSInternalConnection:
    def __init__(self, ssl, cid: bytes):
        self.ssl = ssl
        self.cid = cid
        self.init_done = False
        self.read_queue = Queue()
        self.extra_data = {}

    def __eq__(self, other):
        return self.ssl == other.ssl

    def __del__(self):
        if self.ssl != ffi.NULL:
            lib.wolfSSL_free(self.ssl)

    def error_str(self, ret: int) -> str:
        err_code = lib.wolfSSL_get_error(self.ssl, ret)
        return err_code_to_str(err_code)


class DTLSConnection:
    def __init__(self, server: "DTLSServer", inner: "DTLSInternalConnection"):
        self._server = server
        self._inner = inner

    async def read(self):
        try:
            return await self._inner.read_queue.get()
        except QueueShutDown:
            return None

    async def write(self, data: bytes, loop=None):
        if self._inner.ssl == ffi.NULL:
            return

        await self._server.writable(loop)

        ret = lib.wolfSSL_write(self._inner.ssl, data, len(data))
        if ret == 0:
            self._server.logger.warning(f"Fatal error sending data: {self._inner.error_str(ret)}")
            self._server.remove_connection(self._inner)

    @property
    def address_local(self):
        return self._server.sock.getsockname()

    @property
    def address(self):
        sa_ptr = ffi.new("struct sockaddr_in6 *")
        sa_len = ffi.new("unsigned int *")
        sa_len[0] = ffi.sizeof("struct sockaddr_in6")
        lib.wolfSSL_dtls_get_peer(self._inner.ssl, sa_ptr, sa_len)
        addr = ffi.buffer(sa_ptr[0].sin6_addr.s6_addr, 16)[:]
        return (
            socket.inet_ntop(socket.AF_INET6, addr),
            socket.ntohs(sa_ptr[0].sin6_port),
            socket.ntohs(sa_ptr[0].sin6_flowinfo),
            socket.ntohs(sa_ptr[0].sin6_scope_id),
        )

    @property
    def extra_data(self) -> dict:
        return self._inner.extra_data

class X509StoreContext:
    def __init__(self, ctx, server):
        self._ctx = ctx
        self._server = server

    @property
    def total_certs(self) -> int:
        return self._ctx.totalCerts

    @property
    def depth(self) -> int:
        return self._ctx.depth

    @property
    def domain(self) -> str:
        return ffi.string(self._ctx.domain).decode()

    @property
    def certs(self) -> typing.List[bytes]:
        out = []
        for i in range(self._ctx.totalCerts):
            out.append(ffi.buffer(self._ctx.certs[i].buffer, self._ctx.certs[i].length)[:])
        return out

    @property
    def connection_extra_data(self) -> dict:
        ssl = ffi.cast("WOLFSSL*", lib.wolfSSL_X509_STORE_CTX_get_ex_data(self._ctx, lib.wolfSSL_get_ex_data_X509_STORE_CTX_idx()))
        return self._server.conn_by_ptr[ssl].extra_data


class VerifyCallback:
    def __init__(self, cb, server):
        self._cb = cb
        self._server = server

    @property
    def callback(self):
        return ffi.callback("VerifyCallback", self._process)

    def _process(self, preverify, ctx):
        return int(self._cb(preverify, X509StoreContext(ctx, self._server)) or False)


class DTLSServer:
    def __init__(self, bind: typing.Tuple[str, int]):
        # lib.wolfSSL_Debugging_ON()
        self.logger = logging.getLogger("DTLSServer")
        self.ctx = lib.wolfSSL_CTX_new(lib.wolfDTLSv1_3_server_method())
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind(bind)
        self.conn_by_cid = {}
        self.conn_by_peer = {}
        self.conn_by_ptr = {}
        self.timeouts = []
        self.cookie_secret = secrets.token_bytes(32)
        self.listen_ssl = None
        self.sock_writable_fut = None
        self._verif_cb = None

    def __del__(self):
        lib.wolfSSL_CTX_free(self.ctx)

    def set_certificate_file(self, cert_file, is_pem=True):
        if ret := lib.wolfSSL_CTX_use_certificate_file(self.ctx, str(cert_file).encode(), 1 if is_pem else 2) != 1:
            raise ValueError(f"Failed to set certificate file {cert_file}: {err_code_to_str(ret)}")

    def set_private_key_file(self, private_key_file, is_pem=True):
        if lib.wolfSSL_CTX_use_PrivateKey_file(self.ctx, str(private_key_file).encode(), 1 if is_pem else 2) != 1:
            raise ValueError(f"Failed to use private key file: {private_key_file}")

    def set_client_cert_types(self, cert_types):
        cert_types = bytes(set(cert_types))
        if lib.wolfSSL_CTX_set_client_cert_type(self.ctx, cert_types, len(cert_types)) != 1:
            raise ValueError("Failed to set client cert types")

    def set_server_cert_types(self, cert_types):
        cert_types = bytes(set(cert_types))
        if lib.wolfSSL_CTX_set_server_cert_type(self.ctx, cert_types, len(cert_types)) != 1:
            raise ValueError("Failed to set server cert types")

    def set_verify(self, verify_mode, verify_cb):
        self._verif_cb = VerifyCallback(verify_cb, self).callback if verify_cb else None
        lib.wolfSSL_CTX_set_verify(self.ctx, verify_mode, self._verif_cb)

    def new_ssl(self):
        ssl = lib.wolfSSL_new(self.ctx)
        if ssl == ffi.NULL:
            raise ValueError("Failed to create SSL session")
        lib.wolfSSL_DTLS_SetCookieSecret(ssl, self.cookie_secret, len(self.cookie_secret))
        lib.wolfSSL_dtls_set_timeout_max(ssl, 9)
        lib.wolfSSL_set_write_fd(ssl, self.sock.fileno())
        while True:
            cid = secrets.token_bytes(8)
            if cid not in self.conn_by_cid:
                break
        if lib.wolfSSL_dtls_cid_use(ssl) != 1:
            raise ValueError("Failed to enable connection IDs")
        if lib.wolfSSL_dtls_cid_set(ssl, cid, len(cid)) != 1:
            raise ValueError("Failed to set connection ID")
        lib.wolfSSL_SSLDisableRead(ssl)
        conn = DTLSInternalConnection(ssl, cid)
        self.conn_by_ptr[ssl] = conn
        return conn

    def get_next_timeout(self):
        timeout = next(iter(sorted(self.timeouts, key=lambda t: t[0])), None)
        if not timeout:
            return None, None
        return max(timeout[0] - float(time.monotonic()), 0), timeout[1]

    def remove_connection(self, conn: DTLSInternalConnection):
        if conn.ssl in self.conn_by_ptr:
            del self.conn_by_ptr[conn.ssl]
        self.conn_by_cid = {k: v for k, v in self.conn_by_cid.items() if v != conn}
        self.conn_by_peer = {k: v for k, v in self.conn_by_peer.items() if v != conn}
        self.timeouts = [t for t in self.timeouts if t[1] != conn]
        conn.read_queue.shutdown()

    async def writable(self, loop=None):
        loop = loop or asyncio.get_event_loop()

        if self.sock_writable_fut:
            await self.sock_writable_fut
        else:
            self.sock_writable_fut = loop.create_future()

            def _on_writable():
                if self.sock_writable_fut and not self.sock_writable_fut.done():
                    self.sock_writable_fut.set_result(True)
                self.sock_writable_fut = None
                loop.remove_writer(self.sock.fileno())

            loop.add_writer(self.sock.fileno(), _on_writable)
            await self.sock_writable_fut

    async def run(self, loop=None):
        self.listen_ssl = self.new_ssl()
        loop = loop or asyncio.get_event_loop()
        while True:
            timeout, timeout_conn = self.get_next_timeout()

            readable_fut = loop.create_future()

            def _on_readable():
                if not readable_fut.done():
                    readable_fut.set_result(True)

            loop.add_reader(self.sock.fileno(), _on_readable)

            try:
                try:
                    await asyncio.wait_for(readable_fut, timeout)

                    data, _, _, address = self.sock.recvmsg(4096)
                    if conn := self.find_con(data, address):
                        was_setup = conn.init_done
                        if not await self.despatch_existing_connection(conn, data, address):
                            self.remove_connection(conn)
                        else:
                            self.register_timeout(conn)
                            if conn.init_done and not was_setup:
                                yield DTLSConnection(self, conn)
                    else:
                        self.despatch_new_connection(data, address)
                except asyncio.TimeoutError:
                    if lib.wolfSSL_is_init_finished(timeout_conn.ssl):
                        lib.wolfSSL_shutdown(timeout_conn.ssl)
                    else:
                        ret = lib.wolfSSL_dtls_got_timeout(timeout_conn.ssl)
                        if ret == 1:
                            self.register_timeout(timeout_conn)
                            continue
                    self.remove_connection(timeout_conn)
            finally:
                loop.remove_reader(self.sock.fileno())

    def find_con(self, data: bytes, address: typing.Tuple):
        cid = lib.wolfSSL_dtls_cid_parse(data, len(data), 8)
        if cid:
            cid = ffi.buffer(cid, 8)[:]
            if cid in self.conn_by_cid:
                return self.conn_by_cid[cid]
        if address in self.conn_by_peer:
            return self.conn_by_peer[address]
        return None

    def despatch_new_connection(self, data: bytes, address: typing.Tuple) -> None:
        sa_ptr, sa_len = make_sockaddr_in6(*address)
        lib.wolfSSL_inject(self.listen_ssl.ssl, data, len(data))
        lib.wolfSSL_dtls_set_peer(self.listen_ssl.ssl, sa_ptr, sa_len)
        ret = lib.wolfDTLS_accept_stateless(self.listen_ssl.ssl)
        if ret == 1:
            self.conn_by_cid[self.listen_ssl.cid] = self.listen_ssl
            self.conn_by_peer[address] = self.listen_ssl
            self.listen_ssl = self.new_ssl()
        elif ret == -1:
            self.logger.warning(f"Fatal error accepting connection from {address}: {self.listen_ssl.error_str(ret)}")
            lib.wolfSSL_free(self.listen_ssl.ssl)
            self.listen_ssl.ssl = ffi.NULL
            self.listen_ssl = self.new_ssl()

    async def despatch_existing_connection(self, conn: DTLSInternalConnection, data: bytes, address: typing.Tuple) -> bool:
        sa_ptr, sa_len = make_sockaddr_in6(*address)
        lib.wolfSSL_inject(conn.ssl, data, len(data))
        lib.wolfSSL_dtls_set_pending_peer(conn.ssl, sa_ptr, sa_len)
        if not lib.wolfSSL_is_init_finished(conn.ssl):
            ret = lib.wolfSSL_accept(conn.ssl)
            if ret != 1:
                err = lib.wolfSSL_get_error(conn.ssl, ret)
                if err == 2:
                    return True
                else:
                    self.logger.warning(f"Fatal error negotiating connection: {conn.error_str(ret)}")
                    return False
            else:
                return True
        else:
            conn.init_done = True
            app_data = ffi.new(f"unsigned char[{len(data)}]")
            length = lib.wolfSSL_read(conn.ssl, app_data, len(app_data))
            if length > 0:
                app_data = ffi.buffer(app_data, length)[:]
                await conn.read_queue.put(app_data)
                return True
            else:
                err = lib.wolfSSL_get_error(conn.ssl, length)
                if err == 2:
                    return True
                elif err == 6:  # Connection closed
                    return False
                else:
                    self.logger.warning(f"Fatal error reading application data: {conn.error_str(length)}")
                    return False

    def register_timeout(self, conn: DTLSInternalConnection) -> None:
        self.timeouts = list(filter(lambda t: t[1] != conn, self.timeouts))

        if lib.wolfSSL_is_init_finished(conn.ssl):
            t = 120.0
        else:
            t = lib.wolfSSL_dtls_get_current_timeout(conn.ssl)
            if t == 0:
                return
            t = float(t)

            quick_timeout = lib.wolfSSL_dtls13_use_quick_timeout(conn.ssl)
            if quick_timeout:
                t /= 4

        timeout = float(time.monotonic()) + t
        self.timeouts.append((timeout, conn))