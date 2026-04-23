import dataclasses

@dataclasses.dataclass
class ECPv2:
    terminal_info: int
    terminal_type: bytes
    tci: bytes
    reader_identifier: bytes

    def encode(self) -> bytes:
        return bytes([0x6A, 0x02, self.terminal_info]) + self.terminal_type + self.tci + self.reader_identifier

    @classmethod
    def aliro(cls, identifier: bytes, user_auth_required: bool = False):
        return cls(
            terminal_info=0x8B if user_auth_required else 0xCB,
            terminal_type=b"\x02\x04",
            tci=b"\x20\x42\x20",
            reader_identifier=identifier[0:8],
        )
