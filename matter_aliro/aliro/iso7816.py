import abc


class RequestAPDU:
    instruction_class: int
    instruction: int
    p1: int
    p2: int
    data: bytes
    expected_response_length: int

    def __init__(
            self, instruction_class: int, instruction: int, p1: int, p2: int,
            data: bytes, expected_response_length: int
    ):
        self.instruction_class = instruction_class
        self.instruction = instruction
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expected_response_length = expected_response_length

    def __str__(self):
        return (f"RequestAPDU(class={self.instruction_class:02X}, "
                f"instruction={self.instruction:02X}, "
                f"p1={self.p1:02X}, p2={self.p2:02X}, "
                f"data={self.data.hex().upper()}), "
                f"expected_response_length={self.expected_response_length})")

    def __repr__(self):
        return str(self)

    def encode(self):
        data_len = len(self.data)

        if self.expected_response_length == 0 and data_len == 0:
            raise ValueError("Expected response length cannot be 0 with no command data")

        out = bytearray([
            self.instruction_class,
            self.instruction,
            self.p1,
            self.p2,
        ])

        if data_len == 0:
            pass
        elif data_len < 256:
            out.append(data_len)
        elif data_len < 65536:
            out.append(0)
            out.extend(data_len.to_bytes(2, "big"))
        else:
            raise ValueError("Data length too long")
        out.extend(self.data)

        if self.expected_response_length == 0:
            pass
        else:
            if data_len >= 256:
                if self.expected_response_length == 65536:
                    out.append(0)
                    out.append(0)
                elif self.expected_response_length < 65536:
                    out.extend(self.expected_response_length.to_bytes(2, "big"))
                else:
                    raise ValueError("Invalid expected response length")
            else:
                if self.expected_response_length == 256:
                    out.append(0)
                elif self.expected_response_length == 65536:
                    out.append(0)
                    out.append(0)
                    out.append(0)
                elif self.expected_response_length < 256:
                    out.append(self.expected_response_length)
                elif self.expected_response_length < 65536:
                    out.append(0)
                    out.extend(self.expected_response_length.to_bytes(2, "big"))
                else:
                    raise ValueError("Invalid expected response length")
        return bytes(out)

class ResponseAPDU:
    sw1: int
    sw2: int
    data: bytes

    def __init__(self, sw1: int, sw2: int, data: bytes):
        self.sw1 = sw1
        self.sw2 = sw2
        self.data = data

    @classmethod
    def decode(cls, data: bytes):
        return cls(
            data=data[:-2],
            sw1=data[-2],
            sw2=data[-1],
        )

    def __str__(self):
        return (f"ResponseAPDU(data={self.data.hex().upper()}, "
                f"sw1={self.sw1:02X}, sw2={self.sw2:02X})")

    def __repr__(self):
        return str(self)

    def is_success(self):
        return self.sw1 == 0x90 and self.sw2 == 0x00

class Terminal(metaclass=abc.ABCMeta):
    async def transmit(self, request: RequestAPDU) -> ResponseAPDU:
        raise NotImplementedError()

    async def response_chaining(self, request: RequestAPDU) -> ResponseAPDU:
        resp = await self.transmit(request)
        if resp.sw1 == 0x61:
            data = bytearray(resp.data)
            while resp.sw1 == 0x61:
                resp = self.transmit(RequestAPDU(
                    instruction_class=request.instruction_class,
                    instruction=0xC0,
                    p1=0x00, p2=0x00,
                    data=b"",
                    expected_response_length=256 if resp.sw2 == 0 else resp.sw2,
                ))
                data.extend(resp.data)
            return ResponseAPDU(
                data=data,
                sw1=resp.sw1,
                sw2=resp.sw2,
            )
        else:
            return resp