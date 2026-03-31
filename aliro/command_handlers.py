import ber_tlv.tlv
from . import commands, crypto, iso7816, util

def select(target: iso7816.Terminal, target_aid: bytes) -> commands.SelectResponse:
    resp = target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x00,
        instruction=0xA4,
        p1=0x04, p2=0x00,
        data=target_aid,
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise util.ISO7816Exception("SELECT failed", resp.sw1, resp.sw2)
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
        raise util.ISO7816Exception("CONTROL FLOW failed", resp.sw1, resp.sw2)

def auth0(target: iso7816.Terminal, req: commands.Auth0Request) -> commands.Auth0Response:
    resp = target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x80,
        instruction=0x80,
        p1=0x00, p2=0x00,
        data=req.encode(),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise util.ISO7816Exception("AUTH0 failed", resp.sw1, resp.sw2)
    return commands.Auth0Response.decode(resp.data)

def auth1(target: iso7816.Terminal, req: commands.Auth1Request, secure_channel: crypto.SecureChannel) -> commands.Auth1Response:
    resp = target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x80,
        instruction=0x81,
        p1=0x00, p2=0x00,
        data=req.encode(),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise util.ISO7816Exception("AUTH1 failed", resp.sw1, resp.sw2)
    resp = secure_channel.decrypt_response(resp.data)
    if not resp:
        raise util.CryptoException("Secure channel failed")
    return commands.Auth1Response.decode(resp)

def exchange(target: iso7816.Terminal, req: commands.ExchangeRequest, secure_channel: crypto.SecureChannel) -> commands.ExchangeResponse:
    resp = target.response_chaining(iso7816.RequestAPDU(
        instruction_class=0x80,
        instruction=0xC9,
        p1=0x00, p2=0x00,
        data=secure_channel.encrypt_command(req.encode()),
        expected_response_length=256,
    ))
    if not resp.is_success():
        raise util.ISO7816Exception("EXCHANGE failed", resp.sw1, resp.sw2)
    resp = secure_channel.decrypt_response(resp.data)
    if not resp:
        raise util.CryptoException("Secure channel failed")
    return commands.ExchangeResponse.decode(resp)