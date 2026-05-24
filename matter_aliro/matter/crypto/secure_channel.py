import dataclasses
import enum
import logging
import time
import typing
import secrets
import random
import hashlib
import cryptography.exceptions
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.ciphers.aead
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.utils
from . import CryptoPBKDFParameterSet, CryptoPAKEValuesResponder, crypto_pb, crypto_tt, crypto_p2, verifier_shared_values, kdf, crypto_hmac, CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES, CRYPTO_AEAD_MIC_LENGTH_BYTES
from . import certs
from .. import device
from ..message.messages import GeneralCode, StatusReport
from ..message import protocol, message_layer
from ..encoding import protocol_messages

logger = logging.getLogger(__name__)


class StatusCode(enum.IntEnum):
    SESSION_ESTABLISHMENT_SUCCESS = 0x0000
    NO_SHARED_TRUST_ROOTS = 0x0001
    INVALID_PARAMETER = 0x0002
    CLOSE_SESSION = 0x0003
    BUSY = 0x0004
    REQUIRED_CAT_MISMATCH = 0x0005

    def general_code(self) -> GeneralCode:
        if self == self.SESSION_ESTABLISHMENT_SUCCESS:
            return GeneralCode.SUCCESS
        elif self == self.NO_SHARED_TRUST_ROOTS:
            return GeneralCode.FAILURE
        elif self == self.INVALID_PARAMETER:
            return GeneralCode.FAILURE
        elif self == self.CLOSE_SESSION:
            return GeneralCode.SUCCESS
        elif self == self.BUSY:
            return GeneralCode.BUSY
        elif self == self.REQUIRED_CAT_MISMATCH:
            return GeneralCode.FAILURE

@dataclasses.dataclass
class PASEState:
    pending_session: message_layer.SecureSessionContext
    pbkdf_param_request: bytes = b""
    pbkdf_param_response: bytes = b""
    ca: bytes = b""
    ke: bytes = b""

@dataclasses.dataclass
class CASEState:
    pending_session: message_layer.SecureSessionContext
    msg1: bytes
    msg2: bytes
    ipk: bytes
    fabric: device.Fabric
    initiator_public_key: bytes
    responder_public_key: bytes

class SecureChannel(protocol_messages.SecureChannelProtocol, protocol.Protocol):
    OPCODE_MSG_COUNTER_SYNC_REQ = 0x00
    OPCODE_MSG_COUNTER_SYNC_RSP = 0x01
    OPCODE_MSG_STANDALONE_ACK = 0x10
    OPCODE_PBKDF_PARAM_REQ = 0x20
    OPCODE_PBKDF_PARAM_RSP = 0x21
    OPCODE_PASE_PAKE_1 = 0x22
    OPCODE_PASE_PAKE_2 = 0x23
    OPCODE_PASE_PAKE_3 = 0x24
    OPCODE_CASE_SIGMA_1 = 0x30
    OPCODE_CASE_SIGMA_2 = 0x31
    OPCODE_CASE_SIGMA_3 = 0x32
    OPCODE_CASE_SIGMA_2_RESUME = 0x33
    OPCODE_STATUS_REPORT = 0x40
    OPCODE_ICD_CHECK_IN = 0x50

    pase_state: typing.Dict[message_layer.Exchange, PASEState]
    case_state: typing.Dict[message_layer.Exchange, CASEState]

    def __init__(self, layer: message_layer.MessageLayer, device_state: device.DeviceState):
        super().__init__(layer)
        self.device_state = device_state
        self.basic_pbkdf_params = CryptoPBKDFParameterSet.new()
        self.pbkdf_params = self.basic_pbkdf_params
        self.basic_pake_values_responder = CryptoPAKEValuesResponder.generate(device_state.passcode, self.pbkdf_params)
        self.pake_values_responder = self.basic_pake_values_responder
        self.pase_state = {}
        self.case_state = {}

    async def handle_message(self, exchange: message_layer.Exchange, opcode: int, message: bytes):
        await self.release_next_message(exchange)
        if opcode == self.OPCODE_MSG_STANDALONE_ACK:
            if len(message) != 0:
                logger.warning("non-empty payload on standalone ack")
            return
        elif opcode == self.OPCODE_STATUS_REPORT:
            if len(message) < 8:
                logger.warning("WARN: payload too short for status report")
                return
            report = StatusReport.decode_from_bytes(message)
            await self._message_layer.status_report(exchange, report)
        elif opcode == self.OPCODE_PBKDF_PARAM_REQ:
            try:
                msg = self.PbkdfparamreqStruct.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"WARN: invalid payload on PBKDF parameter request: {e}")
                await self.send_status_report(exchange=exchange, general_code=GeneralCode.BAD_REQUEST)
                return
            await self.pkbdf_param_request(exchange, msg)
        elif opcode == self.OPCODE_PBKDF_PARAM_RSP:
            logger.warning(f"WARN: PASE initiator not implemented")
        elif opcode == self.OPCODE_PASE_PAKE_1:
            try:
                msg = self.Pake1Struct.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"WARN: invalid payload on PASE PAKE phase 1: {e}")
                await self.send_status_report(exchange=exchange, general_code=GeneralCode.BAD_REQUEST)
                return
            await self.pase_pake_1(exchange, msg)
        elif opcode == self.OPCODE_PASE_PAKE_2:
            logger.warning(f"WARN: PASE initiator not implemented")
        elif opcode == self.OPCODE_PASE_PAKE_3:
            try:
                msg = self.Pake3Struct.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"WARN: invalid payload on PASE PAKE phase 3: {e}")
                await self.send_status_report(exchange=exchange, general_code=GeneralCode.BAD_REQUEST)
                return
            await self.pase_pake_3(exchange, msg)
        elif opcode == self.OPCODE_CASE_SIGMA_1:
            try:
                msg = self.Sigma1Struct.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"WARN: invalid payload on CASE sigma 1: {e}")
                await self.send_status_report(exchange=exchange, general_code=GeneralCode.BAD_REQUEST)
                return
            await self.case_sigma_1(exchange, msg)
        elif opcode == self.OPCODE_CASE_SIGMA_2:
            logger.warning(f"WARN: CASE initiator not implemented")
        elif opcode == self.OPCODE_CASE_SIGMA_3:
            try:
                msg = self.Sigma3Struct.decode_from_bytes(message)
            except ValueError as e:
                logger.warning(f"WARN: invalid payload on CASE sigma 3: {e}")
                await self.send_status_report(exchange=exchange, general_code=GeneralCode.BAD_REQUEST)
                return
            await self.case_sigma_3(exchange, msg)
        else:
            await self.send_status_report(exchange=exchange, general_code=GeneralCode.BAD_REQUEST)
            logger.warning(f"Unknown opcode {opcode:02X}")

    async def handle_status_report(self, exchange: message_layer.Exchange, general_code: GeneralCode, protocol_code: int, protocol_data: bytes):
        logger.warning(f"Received status report: {general_code.name} code={protocol_code}")
        if general_code == GeneralCode.FAILURE:
            if exchange in self.pase_state:
                logger.warning("PASE exchange failed")
                del self.pase_state[exchange]
                await self._message_layer.close_exchange(exchange)
            if exchange in self.case_state:
                logger.warning("CASE exchange failed")
                del self.case_state[exchange]
                await self._message_layer.close_exchange(exchange)

    async def pkbdf_param_request(self, exchange: message_layer.Exchange, msg: protocol_messages.SecureChannelProtocol.PbkdfparamreqStruct):
        if msg.passcode_id != 0:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            await self._message_layer.close_exchange(exchange)
            return

        responder_random = secrets.token_bytes(32)
        session_context = message_layer.SecureSessionContext(
            session_type=message_layer.SecureSessionType.PASE,
            session_role=message_layer.Role.Responder,
            local_session_identifier=self._message_layer.allocate_session_id(),
            peer_session_identifier=msg.initiator_session_id,
            i2r_key=b"",
            r2i_key=b"",
            attestation_challenge=b"",
            shared_secret=b"",
            local_message_counter=random.randint(1, 2 ** 28),
            message_reception_state=message_layer.MessageReceptionState.init(0),
            local_fabric_index=0,
            local_node_id=0,
            peer_node_id=0,
            cats=[],
            resumption_id=b"",
            peer=exchange.context.peer,
        )
        if msg.initiator_session_params:
            if msg.initiator_session_params.SESSION_IDLE_INTERVAL:
                session_context.session_idle_interval = msg.initiator_session_params.SESSION_IDLE_INTERVAL / 1000
            if msg.initiator_session_params.SESSION_ACTIVE_INTERVAL:
                session_context.session_active_interval = msg.initiator_session_params.SESSION_ACTIVE_INTERVAL / 1000
            if msg.initiator_session_params.SESSION_ACTIVE_THRESHOLD:
                session_context.session_active_threshold = msg.initiator_session_params.SESSION_ACTIVE_THRESHOLD / 1000

        resp = self.PbkdfparamrespStruct(
            initiator_random=msg.initiator_random,
            responder_random=responder_random,
            responder_session_id=session_context.local_session_identifier,
            pbkdf_parameters=self.CryptoPBKDFParameterSet(
                iterations=self.pbkdf_params.iterations if not msg.has_pbkdf_parameters else None,
                salt=self.pbkdf_params.salt if not msg.has_pbkdf_parameters else None,
            ),
            responder_session_params=None
        )
        resp = resp.encode_to_bytes()
        self.pase_state[exchange] = PASEState(
            pending_session=session_context,
            pbkdf_param_request=msg.on_the_wire_bytes,
            pbkdf_param_response=resp
        )
        await self.send_message(exchange, self.OPCODE_PBKDF_PARAM_RSP, resp)

    async def pase_pake_1(self, exchange: message_layer.Exchange, msg: protocol_messages.SecureChannelProtocol.Pake1Struct):
        pase_state = self.pase_state.get(exchange)
        if not pase_state:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            await self._message_layer.close_exchange(exchange)
            return

        pb = crypto_pb(self.pake_values_responder)
        shared_values = verifier_shared_values(self.pake_values_responder, pb, msg.p_a)
        tt = crypto_tt(
            values=self.pake_values_responder,
            pbkdf_param_request=pase_state.pbkdf_param_request,
            pbkdf_param_response=pase_state.pbkdf_param_response,
            pa=msg.p_a,
            pb=pb.Y,
            shared_values=shared_values
        )
        p2_output = crypto_p2(tt, msg.p_a, pb.Y)
        resp = self.Pake2Struct(
            p_b=pb.Y,
            c_b=p2_output.cB,
        )
        pase_state.ca = p2_output.cA
        pase_state.ke = p2_output.Ke
        await self.send_message(exchange, self.OPCODE_PASE_PAKE_2, resp)

    async def pase_pake_3(self, exchange: message_layer.Exchange, msg: protocol_messages.SecureChannelProtocol.Pake3Struct):
        pase_state = self.pase_state.get(exchange)
        if not pase_state:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            await self._message_layer.close_exchange(exchange)
            return

        if msg.c_a != pase_state.ca:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            del self.pase_state[exchange]
            await self._message_layer.close_exchange(exchange)
            return

        pase_state.pending_session.session_timestamp = time.time()
        k = kdf(pase_state.ke, None, b"SessionKeys", 3 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES)
        pase_state.pending_session.i2r_key = k[0:CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES]
        pase_state.pending_session.r2i_key = k[CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES:2 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES]
        pase_state.pending_session.attestation_challenge = k[2 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES:3 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES]

        self._message_layer.secure_unicast_session_context[pase_state.pending_session.local_session_identifier] = pase_state.pending_session
        await self.send_status_report(exchange=exchange, general_code=StatusCode.SESSION_ESTABLISHMENT_SUCCESS.general_code(), protocol_code=StatusCode.SESSION_ESTABLISHMENT_SUCCESS.value)
        del self.pase_state[exchange]
        await self._message_layer.close_exchange(exchange)

    async def case_sigma_1(self, exchange: message_layer.Exchange, msg: protocol_messages.SecureChannelProtocol.Sigma1Struct):
        if (msg.resumption_id and not msg.initiator_resume_mic) or (msg.initiator_resume_mic and not msg.resumption_id):
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            await self._message_layer.close_exchange(exchange)
            return

        target_fabric = None
        target_fabric_index = None
        target_ipk = None
        for i, fabric in self.device_state.fabrics.items():
            operational_group_key = kdf(
                input_key=fabric.ipk,
                salt=fabric.compressed_fabric_id,
                info=b"GroupKey v1.0",
                length=CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES,
            )
            root_public_key = fabric.root_public_key.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.X962,
                cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
            )
            destination_message = msg.initiator_random + root_public_key + fabric.fabric_id.to_bytes(8, "little") + fabric.node_id.to_bytes(8, "little")
            destination_identifier = crypto_hmac(key=operational_group_key, message=destination_message)
            if destination_identifier == msg.destination_id:
                target_fabric = fabric
                target_fabric_index = i
                target_ipk = operational_group_key
                break

        if not target_fabric:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.NO_SHARED_TRUST_ROOTS.value)
            await self._message_layer.close_exchange(exchange)
            return

        responder_random = secrets.token_bytes(32)
        resumption_id = secrets.token_bytes(16)
        session_context = message_layer.SecureSessionContext(
            session_type=message_layer.SecureSessionType.CASE,
            session_role=message_layer.Role.Responder,
            local_session_identifier=self._message_layer.allocate_session_id(),
            peer_session_identifier=msg.initiator_session_id,
            i2r_key=b"",
            r2i_key=b"",
            attestation_challenge=b"",
            shared_secret=b"",
            local_message_counter=random.randint(1, 2 ** 28),
            message_reception_state=message_layer.MessageReceptionState.init(0),
            local_fabric_index=target_fabric_index,
            local_node_id=target_fabric.node_id,
            peer_node_id=0,
            cats=[],
            resumption_id=resumption_id,
            peer=exchange.context.peer,
        )
        if msg.initiator_session_params:
            if msg.initiator_session_params.SESSION_IDLE_INTERVAL:
                session_context.session_idle_interval = msg.initiator_session_params.SESSION_IDLE_INTERVAL / 1000
            if msg.initiator_session_params.SESSION_ACTIVE_INTERVAL:
                session_context.session_active_interval = msg.initiator_session_params.SESSION_ACTIVE_INTERVAL / 1000
            if msg.initiator_session_params.SESSION_ACTIVE_THRESHOLD:
                session_context.session_active_threshold = msg.initiator_session_params.SESSION_ACTIVE_THRESHOLD / 1000

        initiator_ephemeral_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
            msg.initiator_eph_pub_key
        )
        responder_ephemeral_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
        )
        responder_ephemeral_public_key = responder_ephemeral_key.public_key().public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.X962,
            cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
        )
        session_context.shared_secret = responder_ephemeral_key.exchange(
            cryptography.hazmat.primitives.asymmetric.ec.ECDH(),
            initiator_ephemeral_key,
        )

        tbs_data = self.Sigma2Tbsdata(
            responder_noc=target_fabric.noc,
            responder_icac=target_fabric.icac,
            responder_eph_pub_key=responder_ephemeral_public_key,
            initiator_eph_pub_key=msg.initiator_eph_pub_key
        )
        tbs_data_signature = target_fabric.operational_private_key.sign(
            tbs_data.encode_to_bytes(),
            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA256()
            )
        )
        r, s = cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature(tbs_data_signature)
        tbs_data_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        tbe_data = self.Sigma2Tbedata(
            responder_noc=target_fabric.noc,
            responder_icac=target_fabric.icac,
            signature=tbs_data_signature,
            resumption_id=resumption_id,
        ).encode_to_bytes()

        transcript_hash = hashlib.sha256(msg.on_the_wire_bytes).digest()
        s2k = kdf(
            input_key=session_context.shared_secret,
            salt=target_ipk + responder_random + responder_ephemeral_public_key + transcript_hash,
            info=b"Sigma2",
            length=CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES,
        )

        cipher = cryptography.hazmat.primitives.ciphers.aead.AESCCM(s2k, tag_length=CRYPTO_AEAD_MIC_LENGTH_BYTES)
        enc_data = cipher.encrypt(
            data=tbe_data,
            associated_data=b"",
            nonce=b"NCASE_Sigma2N"
        )

        resp = self.Sigma2Struct(
            responder_random=responder_random,
            responder_session_id=session_context.local_session_identifier,
            responder_eph_pub_key=responder_ephemeral_public_key,
            encrypted2=enc_data,
            responder_session_params=None
        )
        resp = resp.encode_to_bytes()
        self.case_state[exchange] = CASEState(
            pending_session=session_context,
            msg1=msg.on_the_wire_bytes,
            msg2=resp,
            ipk=target_ipk,
            fabric=target_fabric,
            initiator_public_key=msg.initiator_eph_pub_key,
            responder_public_key=responder_ephemeral_public_key,
        )
        await self.send_message(exchange, self.OPCODE_CASE_SIGMA_2, resp)

    async def case_sigma_3(self, exchange: message_layer.Exchange, msg: protocol_messages.SecureChannelProtocol.Sigma3Struct):
        case_state = self.case_state.get(exchange)
        if not case_state:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            await self._message_layer.close_exchange(exchange)
            return

        transcript_hasher = hashlib.sha256()
        transcript_hasher.update(case_state.msg1)
        transcript_hasher.update(case_state.msg2)
        transcript_hash = transcript_hasher.digest()
        s3k = kdf(
            input_key=case_state.pending_session.shared_secret,
            salt=case_state.ipk + transcript_hash,
            info=b"Sigma3",
            length=CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES,
        )

        cipher = cryptography.hazmat.primitives.ciphers.aead.AESCCM(s3k, tag_length=CRYPTO_AEAD_MIC_LENGTH_BYTES)
        try:
            payload = cipher.decrypt(
                data=msg.encrypted3,
                associated_data=b"",
                nonce=b"NCASE_Sigma3N"
            )
        except cryptography.exceptions.InvalidTag:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            del self.case_state[exchange]
            await self._message_layer.close_exchange(exchange)
            return

        tbe_data = self.Sigma3Tbedata.decode_from_bytes(payload)

        noc_cert = protocol_messages.MatterCertificate.decode_from_bytes(tbe_data.initiator_noc)
        if tbe_data.initiator_icac:
            icac_cert = protocol_messages.MatterCertificate.decode_from_bytes(tbe_data.initiator_icac)
        else:
            icac_cert = None

        if not certs.verify_noc_dn(noc_cert):
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            del self.case_state[exchange]
            await self._message_layer.close_exchange(exchange)
            return

        if icac_cert and not certs.verify_icac_dn(icac_cert):
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            del self.case_state[exchange]
            await self._message_layer.close_exchange(exchange)
            return

        fabric_id = next(filter(lambda a: a.variant == "matter-fabric-id", noc_cert.subject)).value
        node_id = next(filter(lambda a: a.variant == "matter-node-id", noc_cert.subject)).value
        cats = list(map(lambda a: certs.CAT(
            id=a.value >> 16,
            version=a.value & 0xFFFF,
        ), filter(lambda a: a.variant == "matter-noc-cat", noc_cert.subject)))

        if fabric_id != case_state.fabric.fabric_id:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            del self.case_state[exchange]
            await self._message_layer.close_exchange(exchange)
            return

        cert_chain = [noc_cert, icac_cert, case_state.fabric.rcac] if icac_cert else [noc_cert, case_state.fabric.rcac]
        if not certs.verify_chain(cert_chain):
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            del self.case_state[exchange]
            await self._message_layer.close_exchange(exchange)
            return

        noc_public_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
            noc_cert.ec_pub_key
        )
        tbs_data = self.Sigma3Tbsdata(
            initiator_noc=tbe_data.initiator_noc,
            initiator_icac=tbe_data.initiator_icac,
            initiator_eph_pub_key=case_state.initiator_public_key,
            responder_eph_pub_key=case_state.responder_public_key,
        ).encode_to_bytes()
        signature = cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(
            int.from_bytes(tbe_data.signature[0:32], "big"),
            int.from_bytes(tbe_data.signature[32:64], "big"),
        )
        try:
            noc_public_key.verify(
                data=tbs_data,
                signature=signature,
                signature_algorithm=cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA256(),
                )
            )
        except cryptography.exceptions.InvalidSignature:
            await self.send_status_report(exchange=exchange, general_code=StatusCode.INVALID_PARAMETER.general_code(), protocol_code=StatusCode.INVALID_PARAMETER.value)
            del self.case_state[exchange]
            await self._message_layer.close_exchange(exchange)
            return

        transcript_hasher = hashlib.sha256()
        transcript_hasher.update(case_state.msg1)
        transcript_hasher.update(case_state.msg2)
        transcript_hasher.update(msg.on_the_wire_bytes)
        transcript_hash = transcript_hasher.digest()
        k = kdf(
            input_key=case_state.pending_session.shared_secret,
            salt=case_state.ipk + transcript_hash,
            info=b"SessionKeys",
            length=3 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES,
        )
        case_state.pending_session.session_timestamp = time.time()
        case_state.pending_session.i2r_key = k[0:CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES]
        case_state.pending_session.r2i_key = k[CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES:2 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES]
        case_state.pending_session.attestation_challenge = k[2 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES:3 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES]
        case_state.pending_session.peer_node_id = node_id
        case_state.pending_session.cats = cats

        self._message_layer.secure_unicast_session_context[case_state.pending_session.local_session_identifier] = case_state.pending_session
        await self.send_status_report(exchange=exchange, general_code=StatusCode.SESSION_ESTABLISHMENT_SUCCESS.general_code(), protocol_code=StatusCode.SESSION_ESTABLISHMENT_SUCCESS.value)
        del self.case_state[exchange]
        await self._message_layer.close_exchange(exchange)
