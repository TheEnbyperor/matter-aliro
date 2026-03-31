import ber_tlv.tlv
from . import commands, iso7816, util

EXPEDITED_AID = bytes.fromhex("A000000909ACCE5501")
STEP_UP_AID = bytes.fromhex("A000000909ACCE5502")


def select(target: iso7816.Terminal, target_aid: bytes) -> commands.SelectResponse:
    resp = target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x00,
        instruction=0xA4,
        p1=0x04, p2=0x00,
        data=target_aid,
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise RuntimeError("SELECT failed")
    return commands.SelectResponse.decode(resp.data, target_aid)


def control_flow(target: iso7816.Terminal, s1: int, s2: int) -> None:
    resp = target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x80,
        instruction=0x3C,
        p1=0x00, p2=0x00,
        data=ber_tlv.tlv.Tlv.build({
            0x41: bytes([s1]),
            0x42: bytes([s2]),
        }),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise RuntimeError("CONTROL FLOW failed")


def auth0(target: iso7816.Terminal, req: commands.Auth0Request) -> commands.Auth0Response:
    resp = target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x80,
        instruction=0x80,
        p1=0x00, p2=0x00,
        data=req.encode(),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise RuntimeError("AUTH0 failed")
    return commands.Auth0Response.decode(resp.data)


def auth1(self, req: Auth1Request, secure_channel: SecureChannel) -> Auth1Response:
    resp = self.response_chaining(RequestAPDU(
        instruction_class=0x80,
        instruction=0x81,
        p1=0x00, p2=0x00,
        data=req.encode(),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise RuntimeError("AUTH1 failed")
    resp = secure_channel.decrypt_response(resp.data)
    if not resp:
        raise RuntimeError("Secure channel failed")
    return Auth1Response.decode(resp)


def exchange(self, req: ExchangeRequest, secure_channel: SecureChannel) -> ExchangeResponse:
    resp = self.response_chaining(RequestAPDU(
        instruction_class=0x80,
        instruction=0xC9,
        p1=0x00, p2=0x00,
        data=secure_channel.encrypt_command(req.encode()),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise RuntimeError("EXCHANGE failed")
    resp = secure_channel.decrypt_response(resp.data)
    if not resp:
        raise RuntimeError("Secure channel failed")
    return ExchangeResponse.decode(resp)


def notify_status(self, status: ReaderStatus, secure_channel: SecureChannel):
    exc_resp = self.exchange(ExchangeRequest(
        reader_status=status,
    ), secure_channel)
    if not exc_resp.is_success:
        print("Reader status notify failed")