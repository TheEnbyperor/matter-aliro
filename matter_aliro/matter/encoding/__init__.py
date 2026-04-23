import abc
import enum
import dataclasses
import struct
import typing
import collections


class Encodable(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def encode_to_bytes(self) -> bytes:
        raise NotImplementedError()


class Decodable(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def decode_from_bytes(cls, data: bytes) -> "Decodable":
        raise NotImplementedError()


class BitStruct(Encodable, Decodable):
    Meta: object

    def encode_to_bytes(self) -> bytes:
        pos = 0
        out = bytearray()
        cur_byte = 0
        for width, v in self.Meta.fields:
            if v is None:
                value = 0
            elif callable(v):
                value = v()
            elif hasattr(self, f"get_{v}"):
                value = getattr(self, f"get_{v}")()
            else:
                value = getattr(self, v)
            b_count = (width + 7) // 8
            if isinstance(value, Encodable):
                value = value.encode_to_bytes()[:b_count]
            elif isinstance(value, int):
                value = value.to_bytes(b_count, "little")
            elif isinstance(value, enum.Enum):
                value = value.value.to_bytes(b_count, "little")
            for byte in value:
                r = min(8, width)
                while r:
                    next_width = min(r, 8 - pos)
                    cur_byte |= ((byte & (2 ** next_width - 1)) << pos)
                    byte >>= next_width
                    pos += next_width
                    if pos == 8:
                        out.append(cur_byte)
                        cur_byte = 0
                        pos = 0
                    r -= next_width
                    width -= next_width
        if pos != 0:
            out.append(cur_byte)
        return bytes(out)

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "BitStruct":
        needed_len = (sum(w for w, _ in cls.Meta.fields) + 7) // 8
        if len(data) < needed_len:
            raise ValueError("Not enough data")
        pos = 0
        values = {}
        for width, v in cls.Meta.fields:
            decoded_value = bytearray()
            if v is None:
                pos += width
                continue
            cur_byte = 0
            byte_pos = 0
            while width:
                next_width = min(width, 8 - (pos % 8), 8 - byte_pos)
                shift = pos % 8
                cur_byte |= ((data[pos // 8] >> shift) & (2 ** next_width - 1)) << byte_pos
                width -= next_width
                pos += next_width
                byte_pos += next_width
                if byte_pos == 8:
                    decoded_value.append(cur_byte)
                    cur_byte = 0
                    byte_pos = 0
            if byte_pos != 0:
                decoded_value.append(cur_byte)

            target_type = cls.__annotations__[v]
            if issubclass(target_type, int):
                values[v] = target_type(int.from_bytes(decoded_value, "little"))
            elif issubclass(target_type, bool):
                values[v] = target_type(decoded_value[0])
            elif issubclass(target_type, enum.Enum):
                values[v] = target_type(int.from_bytes(decoded_value, "little"))
            elif issubclass(target_type, Decodable):
                values[v] = target_type.decode_from_bytes(decoded_value)
            else:
                values[v] = decoded_value

        return cls(**values)


class BitMask(Encodable, Decodable):
    Meta: object

    def encode_to_bytes(self) -> bytes:
        out = bytearray(self.Meta.size)
        for pos, v in self.Meta.fields:
            if callable(v):
                value = v()
            elif hasattr(self, f"get_{v}"):
                value = getattr(self, f"get_{v}")()
            else:
                value = getattr(self, v)

            b = pos // 8
            i = pos % 8

            if value:
                out[b] |= 1 << i
            else:
                out[b] &= ~(1 << i)

        return bytes(out)

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "BitMask":
        if len(data) < cls.Meta.size:
            raise ValueError("Not enough data")
        values = {}
        for pos, v in cls.Meta.fields:
            b = pos // 8
            i = pos % 8

            if data[b] & (1 << i):
                values[v] = True
            else:
                values[v] = False

        return cls(**values)

@dataclasses.dataclass
class TLVControlOctet(BitStruct):
    element_type: int
    tag_control: int

    class Meta:
        fields = (
            (5, "element_type"),
            (3, "tag_control"),
        )

    TYPE_INT8 = 0
    TYPE_INT16 = 1
    TYPE_INT32 = 2
    TYPE_INT64 = 3
    TYPE_UINT8 = 4
    TYPE_UINT16 = 5
    TYPE_UINT32 = 6
    TYPE_UINT64 = 7
    TYPE_BOOL_FALSE = 8
    TYPE_BOOL_TRUE = 9
    TYPE_FLOAT = 10
    TYPE_DOUBLE = 11
    TYPE_UTF8_LEN_1 = 12
    TYPE_UTF8_LEN_2 = 13
    TYPE_UTF8_LEN_4 = 14
    TYPE_UTF8_LEN_8 = 15
    TYPE_BYTES_LEN_1 = 16
    TYPE_BYTES_LEN_2 = 17
    TYPE_BYTES_LEN_4 = 18
    TYPE_BYTES_LEN_8 = 19
    TYPE_NULL = 20
    TYPE_STRUCT = 21
    TYPE_ARRAY = 22
    TYPE_LIST = 23
    TYPE_END_OF_CONTAINER = 24

    FORM_ANONYMOUS = 0
    FORM_CONTEXT_SPECIFIC = 1
    FORM_COMMON_SHORT = 2
    FORM_COMMON_LONG = 3
    FORM_IMPLICIT_SHORT = 4
    FORM_IMPLICIT_LONG = 5
    FORM_FULLY_QUALIFIED_SHORT = 6
    FORM_FULLY_QUALIFIED_LONG = 7

@dataclasses.dataclass(frozen=True)
class TLVFullyQualifiedTag:
    vendor_id: int
    profile: int
    tag: int

@dataclasses.dataclass(frozen=True)
class TLVImplicitTag:
    tag: int

@dataclasses.dataclass(frozen=True)
class TLVCommonTag:
    tag: int

@dataclasses.dataclass(frozen=True)
class TLVContextSpecificTag:
    tag: int

TLVTag = typing.Union[TLVFullyQualifiedTag, TLVImplicitTag, TLVCommonTag, TLVContextSpecificTag]
TLVUInt = collections.namedtuple("TLVUInt", ["value"])
TLVInt = collections.namedtuple("TLVInt", ["value"])
TLVFloat = collections.namedtuple("TLVFloat", ["value"])
TLVDouble = collections.namedtuple("TLVDouble", ["value"])
TLVList = collections.namedtuple("TLVList", ["values"])
TLVArray = collections.namedtuple("TLVArray", ["values"])
TLVStructure = typing.Dict[TLVTag, "TLVData"]
TLVData = typing.Union[TLVUInt, TLVInt, TLVFloat, TLVDouble, bool, str, bytes, None, TLVArray, TLVList, TLVStructure]

@dataclasses.dataclass
class TLVElement(Encodable, Decodable):
    tag: typing.Optional[TLVTag]
    data: TLVData

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "TLVElement":
        return cls._decode_from_bytes(data)[0]

    @classmethod
    def _decode_from_bytes(cls, data: bytes) -> typing.Tuple["TLVElement", int]:
        control = TLVControlOctet.decode_from_bytes(data[0:1])
        i = 1
        if control.tag_control == TLVControlOctet.FORM_ANONYMOUS:
            tag = None
        elif control.tag_control == TLVControlOctet.FORM_CONTEXT_SPECIFIC:
            tag = TLVContextSpecificTag(tag=data[i])
            i += 1
        elif control.tag_control == TLVControlOctet.FORM_COMMON_SHORT:
            tag = TLVCommonTag(tag=int.from_bytes(data[i:i+2], byteorder="little"))
            i += 2
        elif control.tag_control == TLVControlOctet.FORM_COMMON_LONG:
            tag = TLVCommonTag(tag=int.from_bytes(data[i:i+4], byteorder="little"))
            i += 4
        elif control.tag_control == TLVControlOctet.FORM_IMPLICIT_SHORT:
            tag = TLVImplicitTag(tag=int.from_bytes(data[i:i+2], byteorder="little"))
            i += 2
        elif control.tag_control == TLVControlOctet.FORM_IMPLICIT_LONG:
            tag = TLVImplicitTag(tag=int.from_bytes(data[i:i+4], byteorder="little"))
            i += 4
        elif control.tag_control == TLVControlOctet.FORM_FULLY_QUALIFIED_SHORT:
            tag = TLVFullyQualifiedTag(
                vendor_id=int.from_bytes(data[i:i+2], byteorder="little"),
                profile=int.from_bytes(data[i+2:i+4], byteorder="little"),
                tag=int.from_bytes(data[i+4:i+6], byteorder="little"),
            )
            i += 6
        elif control.tag_control == TLVControlOctet.FORM_FULLY_QUALIFIED_LONG:
            tag = TLVFullyQualifiedTag(
                vendor_id=int.from_bytes(data[i:i+2], byteorder="little"),
                profile=int.from_bytes(data[i+2:i+4], byteorder="little"),
                tag=int.from_bytes(data[i+4:i+8], byteorder="little"),
            )
            i += 8
        else:
            raise ValueError("Unknown TLV tag control type")

        if control.element_type == TLVControlOctet.TYPE_INT8:
            value = TLVInt(int.from_bytes(data[i:i+1], "little", signed=True))
            i += 1
        elif control.element_type == TLVControlOctet.TYPE_INT16:
            value = TLVInt(int.from_bytes(data[i:i+2], "little", signed=True))
            i += 2
        elif control.element_type == TLVControlOctet.TYPE_INT32:
            value = TLVInt(int.from_bytes(data[i:i+4], "little", signed=True))
            i += 4
        elif control.element_type == TLVControlOctet.TYPE_INT64:
            value = TLVInt(int.from_bytes(data[i:i+8], "little", signed=True))
            i += 8
        elif control.element_type == TLVControlOctet.TYPE_UINT8:
            value = TLVUInt(int.from_bytes(data[i:i+1], "little", signed=False))
            i += 1
        elif control.element_type == TLVControlOctet.TYPE_UINT16:
            value = TLVUInt(int.from_bytes(data[i:i+2], "little", signed=False))
            i += 2
        elif control.element_type == TLVControlOctet.TYPE_UINT32:
            value = TLVUInt(int.from_bytes(data[i:i+4], "little", signed=False))
            i += 4
        elif control.element_type == TLVControlOctet.TYPE_UINT64:
            value = TLVUInt(int.from_bytes(data[i:i+8], "little", signed=False))
            i += 8
        elif control.element_type == TLVControlOctet.TYPE_BOOL_TRUE:
            value = True
        elif control.element_type == TLVControlOctet.TYPE_BOOL_FALSE:
            value = False
        elif control.element_type == TLVControlOctet.TYPE_FLOAT:
            value = TLVFloat(struct.unpack("<f", data[i:i+4])[0])
            i += 4
        elif control.element_type == TLVControlOctet.TYPE_DOUBLE:
            value = TLVDouble(struct.unpack("<d", data[i:i+8])[0])
            i += 8
        elif control.element_type == TLVControlOctet.TYPE_UTF8_LEN_1:
            str_len = int.from_bytes(data[i:i+1], "little", signed=False)
            value = data[i+1:i+str_len+1].decode("utf-8")
            i += str_len + 1
        elif control.element_type == TLVControlOctet.TYPE_UTF8_LEN_2:
            str_len = int.from_bytes(data[i:i+2], "little", signed=False)
            value = data[i+2:i+str_len+2].decode("utf-8")
            i += str_len + 2
        elif control.element_type == TLVControlOctet.TYPE_UTF8_LEN_4:
            str_len = int.from_bytes(data[i:i+4], "little", signed=False)
            value = data[i+4:i+str_len+4].decode("utf-8")
            i += str_len + 4
        elif control.element_type == TLVControlOctet.TYPE_UTF8_LEN_8:
            str_len = int.from_bytes(data[i:i+8], "little", signed=False)
            value = data[i+8:i+str_len+8].decode("utf-8")
            i += str_len + 8
        elif control.element_type == TLVControlOctet.TYPE_BYTES_LEN_1:
            str_len = int.from_bytes(data[i:i+1], "little", signed=False)
            value = data[i+1:i+str_len+1]
            i += str_len + 1
        elif control.element_type == TLVControlOctet.TYPE_BYTES_LEN_2:
            str_len = int.from_bytes(data[i:i+2], "little", signed=False)
            value = data[i+2:i+str_len+2]
            i += str_len + 2
        elif control.element_type == TLVControlOctet.TYPE_BYTES_LEN_4:
            str_len = int.from_bytes(data[i:i+4], "little", signed=False)
            value = data[i+4:i+str_len+4]
            i += str_len + 4
        elif control.element_type == TLVControlOctet.TYPE_BYTES_LEN_8:
            str_len = int.from_bytes(data[i:i+8], "little", signed=False)
            value = data[i+8:i+str_len+8]
            i += str_len + 8
        elif control.element_type == TLVControlOctet.TYPE_NULL:
            value = None
        elif control.element_type == TLVControlOctet.TYPE_STRUCT:
            value = {}
            while data[i] != 0x18:
                item, o = cls._decode_from_bytes(data[i:])
                value[item.tag] = item.data
                i += o
            i += 1
        elif control.element_type == TLVControlOctet.TYPE_ARRAY:
            value = []
            while data[i] != 0x18:
                item, o = cls._decode_from_bytes(data[i:])
                if item.tag is not None:
                    raise ValueError("Array containing non-anonymous tag")
                value.append(item.data)
                i += o
            value = TLVArray(value)
            i += 1
        elif control.element_type == TLVControlOctet.TYPE_LIST:
            value = []
            while data[i] != 0x18:
                item, o = cls._decode_from_bytes(data[i:])
                value.append(item)
                i += o
            value = TLVList(value)
            i += 1
        elif control.element_type == TLVControlOctet.TYPE_END_OF_CONTAINER:
            raise ValueError("Unexpected end of container")
        else:
            raise ValueError("Unexpected element type")

        return cls(tag=tag, data=value), i

    def encode_to_bytes(self) -> bytes:
        out = bytearray()
        if self.tag is None:
            tag_control = TLVControlOctet.FORM_ANONYMOUS
        elif isinstance(self.tag, TLVContextSpecificTag):
            tag_control = TLVControlOctet.FORM_CONTEXT_SPECIFIC
            out.append(self.tag.tag)
        elif isinstance(self.tag, TLVCommonTag):
            if self.tag.tag <= 65535:
                tag_control = TLVControlOctet.FORM_COMMON_SHORT
                out.extend(self.tag.tag.to_bytes(2, "little"))
            else:
                tag_control = TLVControlOctet.FORM_COMMON_LONG
                out.extend(self.tag.tag.to_bytes(4, "little"))
        elif isinstance(self.tag, TLVImplicitTag):
            if self.tag.tag <= 65535:
                tag_control = TLVControlOctet.FORM_IMPLICIT_SHORT
                out.extend(self.tag.tag.to_bytes(2, "little"))
            else:
                tag_control = TLVControlOctet.FORM_IMPLICIT_LONG
                out.extend(self.tag.tag.to_bytes(4, "little"))
        elif isinstance(self.tag, TLVFullyQualifiedTag):
            out.extend(self.tag.vendor_id.to_bytes(2, "little"))
            out.extend(self.tag.profile.to_bytes(2, "little"))
            if self.tag.tag <= 65535:
                tag_control = TLVControlOctet.FORM_FULLY_QUALIFIED_SHORT
                out.extend(self.tag.tag.to_bytes(2, "little"))
            else:
                tag_control = TLVControlOctet.FORM_FULLY_QUALIFIED_LONG
                out.extend(self.tag.tag.to_bytes(4, "little"))

        if self.data is None:
            element_type = TLVControlOctet.TYPE_NULL
        elif self.data is True:
            element_type = TLVControlOctet.TYPE_BOOL_TRUE
        elif self.data is False:
            element_type = TLVControlOctet.TYPE_BOOL_FALSE
        elif isinstance(self.data, str):
            data = self.data.encode("utf-8")
            l = len(data)
            if l <= 255:
                element_type = TLVControlOctet.TYPE_UTF8_LEN_1
                out.append(l)
                out.extend(data)
            elif l <= 65535:
                element_type = TLVControlOctet.TYPE_UTF8_LEN_2
                out.extend(l.to_bytes(2, "little"))
                out.extend(data)
            elif l <= 4294967295:
                element_type = TLVControlOctet.TYPE_UTF8_LEN_4
                out.extend(l.to_bytes(4, "little"))
                out.extend(data)
            else:
                element_type = TLVControlOctet.TYPE_UTF8_LEN_8
                out.extend(l.to_bytes(8, "little"))
                out.extend(data)
        elif isinstance(self.data, bytes):
            l = len(self.data)
            if l <= 255:
                element_type = TLVControlOctet.TYPE_BYTES_LEN_1
                out.append(l)
                out.extend(self.data)
            elif l <= 65535:
                element_type = TLVControlOctet.TYPE_BYTES_LEN_2
                out.extend(l.to_bytes(2, "little"))
                out.extend(self.data)
            elif l <= 4294967295:
                element_type = TLVControlOctet.TYPE_BYTES_LEN_4
                out.extend(l.to_bytes(4, "little"))
                out.extend(self.data)
            else:
                element_type = TLVControlOctet.TYPE_BYTES_LEN_8
                out.extend(l.to_bytes(8, "little"))
                out.extend(self.data)
        elif isinstance(self.data, TLVInt):
            if -2 ** 7 <= self.data.value <= 2 ** 7 - 1:
                element_type = TLVControlOctet.TYPE_INT8
                out.extend(self.data.value.to_bytes(1, "little", signed=True))
            elif -2 ** 15 <= self.data.value <= 2 ** 15 - 1:
                element_type = TLVControlOctet.TYPE_INT16
                out.extend(self.data.value.to_bytes(2, "little", signed=True))
            elif -2 ** 31 <= self.data.value <= 2 ** 31 - 1:
                element_type = TLVControlOctet.TYPE_INT32
                out.extend(self.data.value.to_bytes(4, "little", signed=True))
            else:
                element_type = TLVControlOctet.TYPE_INT64
                out.extend(self.data.value.to_bytes(8, "little", signed=True))
        elif isinstance(self.data, TLVUInt):
            if self.data.value <= 2 ** 8 - 1:
                element_type = TLVControlOctet.TYPE_UINT8
                out.extend(self.data.value.to_bytes(1, "little", signed=False))
            elif self.data.value <= 2 ** 16 - 1:
                element_type = TLVControlOctet.TYPE_UINT16
                out.extend(self.data.value.to_bytes(2, "little", signed=False))
            elif self.data.value <= 2 ** 32 - 1:
                element_type = TLVControlOctet.TYPE_UINT32
                out.extend(self.data.value.to_bytes(4, "little", signed=False))
            else:
                element_type = TLVControlOctet.TYPE_UINT64
                out.extend(self.data.value.to_bytes(8, "little", signed=False))
        elif isinstance(self.data, dict):
            element_type = TLVControlOctet.TYPE_STRUCT
            for k, v in self.data.items():
                out.extend(TLVElement(
                    tag=k,
                    data=v,
                ).encode_to_bytes())
            out.append(0x18)
        elif isinstance(self.data, TLVArray):
            element_type = TLVControlOctet.TYPE_ARRAY
            for v in self.data.values:
                out.extend(TLVElement(
                    tag=None,
                    data=v,
                ).encode_to_bytes())
            out.append(0x18)
        elif isinstance(self.data, TLVList):
            element_type = TLVControlOctet.TYPE_LIST
            for v in self.data.values:
                out.extend(v.encode_to_bytes())
            out.append(0x18)
        else:
            raise ValueError(f"Unsupported element type: {type(self.data)}")

        control_byte = TLVControlOctet(
            tag_control=tag_control,
            element_type=element_type
        )
        return control_byte.encode_to_bytes() + bytes(out)
