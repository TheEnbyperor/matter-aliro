import dataclasses
import functools
import collections
import sys
import types
import typing
import typing_extensions

from . import Encodable, Decodable, TLVTag, TLVCommonTag, TLVContextSpecificTag, TLVImplicitTag, TLVFullyQualifiedTag, TLVList, TLVArray, TLVInt, TLVUInt, TLVElement

if sys.version_info >= (3, 10):
    _UNION_TYPES = {typing.Union, types.UnionType}
else:
    _UNION_TYPES = {typing.Union}

class Null:
    def __bool__(self):
        return False

    def __eq__(self, other):
        return isinstance(other, self.__class__)

class AnyTag(typing.NamedTuple):
    pass

class AnonymousTag(typing.NamedTuple):
    pass


class ContextSpecificTag(typing.NamedTuple):
    tag: int


class ProfileSpecificTag(typing.NamedTuple):
    vendor: int
    profile: int
    tag: int

Tag = typing.Union[AnonymousTag, ContextSpecificTag, ProfileSpecificTag]

class Field(typing.NamedTuple):
    tag: Tag
    source: str
    optional: bool

class ChoiceField(typing.NamedTuple):
    tag: Tag
    name: str
    type: type
    annotation: dict

class UnsignedInteger(int):
    def __init__(self, *args, min: typing.Optional[int] = None, max: typing.Optional[int] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._min = min
        self._max = max


class OctetString(bytes):
    def __init__(self, *args, min_length: typing.Optional[int] = None, max_length: typing.Optional[int] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._min_length = min_length
        self._max_length = max_length


class TaggedFields:
    @staticmethod
    def _tag_cmp(left: Field, right: Field) -> int:
        left = left.tag
        right = right.tag
        if isinstance(left, AnonymousTag):
            if isinstance(right, AnonymousTag):
                return 0
            else:
                return -1
        elif isinstance(right, AnonymousTag):
            if isinstance(left, AnonymousTag):
                return 0
            else:
                return 1
        elif isinstance(left, ContextSpecificTag):
            if isinstance(right, ContextSpecificTag):
                return left.tag - right.tag
            else:
                return -1
        elif isinstance(right, ContextSpecificTag):
            if isinstance(left, ContextSpecificTag):
                return left.tag - right.tag
            else:
                return 1
        else:
            if left.vendor != right.vendor:
                return left.vendor - right.vendor
            elif left.profile != right.profile:
                return left.profile - right.profile
            else:
                return left.tag - right.tag

    @classmethod
    def _tag_matches(cls, want: Tag, have: typing.Optional[TLVTag]) -> bool:
        if isinstance(want, AnyTag):
            return True
        elif isinstance(want, AnonymousTag):
            return have is None
        else:
            if have is None:
                return False

            if isinstance(want, ContextSpecificTag):
                if isinstance(have, TLVContextSpecificTag):
                    return want.tag == have.tag
                else:
                    return False
            elif isinstance(want, ProfileSpecificTag):
                if isinstance(have, TLVCommonTag):
                    return want.vendor == 0 and want.profile == 0 and want.tag == have.tag
                elif isinstance(have, TLVImplicitTag):
                    if not hasattr(cls.Meta, "implicit_vendor") or not hasattr(cls.Meta, "implicit_profile"):
                        return False
                    return want.vendor == cls.Meta.implicit_vendor and want.profile == cls.Meta.implicit_profile and want.tag == have.tag
                elif isinstance(have, TLVFullyQualifiedTag):
                    return want.vendor == have.vendor_id and want.profile == have.profile and want.tag == have.tag
                else:
                    return False

    @classmethod
    def decode_type(cls, source: str, v, ft_type, metadata: dict):
        if isinstance(ft_type, typing.ForwardRef):
            ft_type = typing_extensions.evaluate_forward_ref(ft_type, owner=cls)

        ft_type_origin = typing.get_origin(ft_type)
        ft_type_args = typing.get_args(ft_type)

        if ft_type_origin in _UNION_TYPES:
            nullable = any(isinstance(a, type) and issubclass(a, Null) for a in ft_type_args)
            ft_type = ft_type_args[0]
            ft_type_origin = typing.get_origin(ft_type)
            ft_type_args = typing.get_args(ft_type)
        else:
            nullable = False

        if v is None:
            if nullable:
                return Null()
            else:
                raise ValueError(f"Field {source} is not nullable")

        if ft_type_origin and issubclass(ft_type_origin, list):
            inner_ft_type = ft_type_args[0]
            base_meta = metadata.get("base_meta", {})

            if metadata["is_list"]:
                if not isinstance(v, TLVList):
                    raise ValueError(f"Expected list for {source}, got {type(v)}")
            else:
                if not isinstance(v, TLVArray):
                    raise ValueError(f"Expected array for {source}, got {type(v)}")

            out = []
            for item in v.values:
                out.append(cls.decode_type(source, item, inner_ft_type, base_meta))
            return out

        elif ft_type == typing.Any:
            return v

        elif isinstance(ft_type, type):
            if issubclass(ft_type, bytes):
                if not isinstance(v, bytes):
                    raise ValueError(f"Expected bytes for {source}, got {type(v)}")

                if (min_len := metadata.get("min_len")) is not None:
                    if len(v) < min_len:
                        raise ValueError(f"Value too short for {source}")
                if (max_len := metadata.get("max_len")) is not None:
                    if len(v) > max_len:
                        raise ValueError(f"Value too long for {source}")

                return v

            elif issubclass(ft_type, str):
                if not isinstance(v, str):
                    raise ValueError(f"Expected string for {source}, got {type(v)}")

                if (min_len := metadata.get("min_len")) is not None:
                    if len(v) < min_len:
                        raise ValueError(f"Value too short for {source}")
                if (max_len := metadata.get("max_len")) is not None:
                    if len(v) > max_len:
                        raise ValueError(f"Value too long for {source}")

                return v

            elif issubclass(ft_type, bool):
                if not isinstance(v, bool):
                    raise ValueError(f"Expected bool for {source}, got {type(v)}")

                return v

            elif issubclass(ft_type, int):
                signed_int = metadata.get("signed")
                if signed_int and not isinstance(v, TLVInt):
                    raise ValueError(f"Expected signed integer for {source}, got {type(v)}")
                if not signed_int and not isinstance(v, TLVUInt):
                    raise ValueError(f"Expected unsigned integer for {source}, got {type(v)}")

                if (min_v := metadata.get("min")) is not None:
                    if v.value < min_v:
                        raise ValueError(f"Value too small for {source}")
                if (max_v := metadata.get("max")) is not None:
                    if v.value > max_v:
                        raise ValueError(f"Value too large for {source}")

                return v.value

            elif issubclass(ft_type, Structure):
                if not isinstance(v, dict):
                    raise ValueError(f"Expected structure for {source}, got {type(v)}")

                return ft_type._decode_from_dict(v)

            elif issubclass(ft_type, List):
                if not isinstance(v, TLVList):
                    raise ValueError(f"Expected list for {source}, got {type(v)}")

                return ft_type._decode_from_list(v)

            elif issubclass(ft_type, ChoiceOf):
                return ft_type._decode_from_value(v)

            else:
                raise ValueError(f"Unsupported type for {source}: type {type(ft_type)}")
        else:
            raise ValueError(f"Unsupported type for {source}: type {type(ft_type)}")

    def _make_tag(self, tag):
        if isinstance(tag, AnonymousTag) or isinstance(tag, AnyTag):
            return None
        elif isinstance(tag, ContextSpecificTag):
            return TLVContextSpecificTag(tag=tag.tag)
        elif isinstance(tag, ProfileSpecificTag):
            if tag.vendor == 0 and tag.profile == 0:
                return TLVCommonTag(tag=tag.tag)
            elif hasattr(self.Meta, "implicit_vendor") or not hasattr(self.Meta, "implicit_profile"):
                if tag.vendor == self.Meta.implicit_vendor and tag.profile == self.Meta.implicit_profile:
                    return TLVImplicitTag(tag=tag.tag)
                else:
                    return TLVFullyQualifiedTag(vendor_id=tag.vendor, profile=tag.vendor, tag=tag.tag)
            else:
                return TLVFullyQualifiedTag(vendor_id=tag.vendor, profile=tag.vendor, tag=tag.tag)
        else:
            raise ValueError(f"Unsupported tag type {tag}")

    @staticmethod
    def encode_type(value, metadata):
        if isinstance(value, Null):
            return None
        elif isinstance(value, bool):
            return value
        elif isinstance(value, list):
            base_meta = metadata.get("base_meta", {})
            if metadata.get("is_list"):
                return TLVList([TaggedFields.encode_type(i, base_meta) for i in value])
            else:
                return TLVArray([TaggedFields.encode_type(i, base_meta) for i in value])
        elif isinstance(value, int):
            signed_int = metadata.get("signed")
            if signed_int:
                return TLVInt(value)
            else:
                return TLVUInt(value)
        elif isinstance(value, Structure):
            return value._encode_to_dict()
        elif isinstance(value, List):
            return TLVList(value._encode_to_list())
        elif isinstance(value, ChoiceOf):
            return value._encode_to_value()
        elif isinstance(value, Encodable):
            return value.encode_to_bytes()
        else:
            return value


class Structure(Decodable, Encodable, TaggedFields):
    def __init__(self):
        self._raw_bytes = None

    @classmethod
    def _decode_from_dict(cls, data: dict) -> "Structure":
        fields = []
        if cls.Meta.order == "schema":
            fields = cls.Meta.fields
        elif cls.Meta.order == "tag":
            fields = list(cls.Meta.fields)
            fields.sort(key=functools.cmp_to_key(cls._tag_cmp))
        elif cls.Meta.order == "any":
            raise NotImplementedError("Any order structures not yet implemented")

        values = collections.OrderedDict()
        for (gt, gv) in data.items():
            matching_field = next(filter(lambda f: cls._tag_matches(f.tag, gt), fields), None)
            if not matching_field and not cls.Meta.extensible:
                raise ValueError(f"Field {gt} not found in {cls.__name__}")

            if matching_field not in values:
                values[matching_field] = gv
            else:
                raise ValueError(f"Duplicate field {matching_field.source} for {cls.__name__}")

        out = {}
        have_fields = list(values.keys())
        i = 0
        for f in have_fields:
            while f != fields[i]:
                if fields[i].optional:
                    out[fields[i].source] = None
                    i += 1
                else:
                    raise ValueError(f"Missing field {fields[i].source} for {cls.__name__}")
            i += 1
        while i != len(fields):
            if fields[i].optional:
                out[fields[i].source] = None
                i += 1
            else:
                raise ValueError(f"Missing field {fields[i].source} for {cls.__name__}")


        dc_fields = dataclasses.fields(cls)
        type_hints = typing.get_type_hints(cls)
        for k, v in values.items():
            ft = next(filter(lambda f: f.name == k.source, dc_fields))

            out[k.source] = cls.decode_type(k, v, type_hints[k.source], ft.metadata)

        return cls(**out)

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "Structure":
        tlv_elm = TLVElement.decode_from_bytes(data)
        if tlv_elm.tag is not None:
            raise ValueError("Outer element is not the anonymous element")
        if not isinstance(tlv_elm.data, dict):
            raise ValueError("Outer element is not a structure")

        r = cls._decode_from_dict(tlv_elm.data)
        r._raw_bytes = data
        return r

    def _encode_to_dict(self) -> dict:
        if self.Meta.order == "schema" or self.Meta.order == "any":
            fields = self.Meta.fields
        elif self.Meta.order == "tag":
            fields = list(self.Meta.fields)
            fields.sort(key=functools.cmp_to_key(self._tag_cmp))
        else:
            raise NotImplementedError("Invalid field order")

        out = {}
        dc_fields = dataclasses.fields(self)
        for f in fields:
            ft = next(filter(lambda e: e.name == f.source, dc_fields))

            tag = self._make_tag(f.tag)
            value = getattr(self, f.source)

            if f.optional:
                if value is None:
                    continue
                if isinstance(value, list) and len(value) == 0:
                    continue

            out[tag] = self.encode_type(value, ft.metadata)

        return out

    def encode_to_bytes(self) -> bytes:
        fields = self._encode_to_dict()
        tlv_elm = TLVElement(
            tag=None,
            data=fields,
        )
        return tlv_elm.encode_to_bytes()

    @property
    def on_the_wire_bytes(self) -> typing.Optional[bytes]:
        return self._raw_bytes


class List(Decodable, Encodable, TaggedFields):
    def __init__(self):
        self._raw_bytes = None

    @classmethod
    def _decode_from_list(cls, data: TLVList) -> "List":
        dc_fields = dataclasses.fields(cls)
        type_hints = typing.get_type_hints(cls)
        i = 0
        out = {}
        for field in cls.Meta.fields:
            ft = next(filter(lambda f: f.name == field.source, dc_fields))

            values = []
            while i < len(data.values) and cls._tag_matches(field.tag, data.values[i].tag):
                values.append(cls.decode_type(field, data.values[i].data, type_hints[field.source], ft.metadata))
                i += 1

            if ft.metadata["min_count"] is not None and len(values) < ft.metadata["min_count"]:
                raise ValueError(f"Too few values for field {field.source}")
            if ft.metadata["max_count"] is not None and len(values) > ft.metadata["max_count"]:
                raise ValueError(f"Too many values for field {field.source}")

            if field.optional:
                if values:
                    values = values[0]
                else:
                    values = None

            out[field.source] = values

        return cls(**out)

    def _encode_to_list(self) -> typing.List[TLVElement]:
        dc_fields = dataclasses.fields(self)
        out = []
        for field in self.Meta.fields:
            ft = next(filter(lambda f: f.name == field.source, dc_fields))
            tag = self._make_tag(field.tag)
            value = getattr(self, field.source)

            if field.optional and value is None:
                continue

            out.append(TLVElement(
                tag=tag,
                data=self.encode_type(value, ft.metadata)
            ))

        return out

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "List":
        tlv_elm = TLVElement.decode_from_bytes(data)
        if tlv_elm.tag is not None:
            raise ValueError("Outer element is not the anonymous element")
        if not isinstance(tlv_elm.data, TLVList):
            raise ValueError("Outer element is not a list")

        r = cls._decode_from_list(tlv_elm.data)
        r._raw_bytes = data
        return r

    @property
    def on_the_wire_bytes(self) -> typing.Optional[bytes]:
        return self._raw_bytes

    def encode_to_bytes(self) -> bytes:
        fields = self._encode_to_list()
        tlv_elm = TLVElement(
            tag=None,
            data=TLVList(fields),
        )
        return tlv_elm.encode_to_bytes()

class ChoiceOf(Decodable, Encodable, TaggedFields):
    variant: str
    value: typing.Any

    def __init__(self):
        self._raw_bytes = None

    @classmethod
    def _decode_from_value(cls, data: TLVElement) -> "ChoiceOf":
        possible_options = []
        for field in cls.Meta.options:
            if cls._tag_matches(field.tag, data.tag):
                possible_options.append(field)

        if len(possible_options) == 0:
            raise ValueError(f"{data.tag} is not a valid choice variant")

        option = possible_options.pop()
        value = cls.decode_type(option.name, data.data, option.type, option.annotation)
        return cls(
            variant=option.name,
            value=value
        )

    def _encode_to_value(self) -> TLVElement:
        field = next(filter(lambda o: o.name == self.variant, self.Meta.options))
        if field is None:
            raise ValueError(f"Invalid choice variant {self.variant}")
        return TLVElement(
            tag=self._make_tag(field.tag),
            data=self.encode_type(self.value, field.annotation)
        )

    @classmethod
    def decode_from_bytes(cls, data: bytes) -> "ChoiceOf":
        tlv_elm = TLVElement.decode_from_bytes(data)
        r = cls._decode_from_value(tlv_elm.data)
        r._raw_bytes = data
        return r

    @property
    def on_the_wire_bytes(self) -> typing.Optional[bytes]:
        return self._raw_bytes

    def encode_to_bytes(self) -> bytes:
        return self._encode_to_value().encode_to_bytes()