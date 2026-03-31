import dataclasses

@dataclasses.dataclass
class ECPv2:
    terminal_type: int
    terminal_subtype: int
    flag_1: bool
    flag_2: bool
    flag_3: bool
    flag_4: bool
    payload: bytes

    def encode(self) -> bytes:
        terminal_info = (int(self.flag_1) << 7) + (int(self.flag_2) << 6) + \
                        (int(self.flag_3) << 5) + (int(self.flag_4) << 4) + len(self.payload)
        return bytes([0x6A, 0x02, terminal_info, self.terminal_type, self.terminal_subtype]) + self.payload

    @classmethod
    def aliro(cls, identifier: bytes, express: bool = True):
        return cls(
            terminal_type=0x02, # ACCESS,
            terminal_subtype=0x06, # HomeKey,
            flag_1=True,
            flag_2=express,
            flag_3=False,
            flag_4=False,
            payload=b"\x20\x42\x20" + identifier[0:8],
        )
