import os
import pyparsing as pp
import pyparsing.common as ppc
import humps
import typing
import pathlib


def make_schema():
    LBRACE, RBRACE, LBRACK, RBRACK, COLON, COMMA, DOT, EQUAL = map(pp.Suppress, "{}[]:,.=")
    ARROW = pp.Suppress("=>")

    ident_start = pp.alphas + "_"
    ident_body = pp.alphanums + "_-"
    identifier = pp.Word(ident_start, ident_body).set_name("identifier")

    scoped_name = pp.Combine(identifier + pp.ZeroOrMore(pp.Literal(".") + identifier)).set_name("scoped_name")

    hex_uint = pp.Suppress(pp.CaselessLiteral("0x")) + ppc.hex_integer
    uint_value = (ppc.integer ^ hex_uint)

    sign = pp.Optional(pp.one_of("+ -"))
    int_value = pp.Combine(sign + uint_value).set_name("int_value")

    star = pp.Literal("*")
    plus = pp.Literal("*")

    tag_prefix = (star | uint_value | scoped_name)  # '*' | protocol-id | protocol-name
    tag_spec = (
            (pp.CaselessKeyword("anonymous")("anonymous"))
            ^ (tag_prefix("protocol") + COLON + uint_value("tag_num"))("protocol_specific")
            ^ (uint_value("tag_num"))("context_specific")
    ).set_name("tag")
    tag_qual = (LBRACK + tag_spec + RBRACK).set_name("tag-qualifier")

    protocol_id = (pp.Suppress(pp.CaselessKeyword("id")) + (
            uint_value("long_protocol_id") ^
            (uint_value("vendor_id") + COLON + uint_value("protocol_id"))("vendor_id_protocol_id") ^
            (scoped_name("vendor_name") + COLON + uint_value("protocol_id"))("vendor_name_protocol_id")
    ))
    vendor_id = (pp.Suppress(pp.CaselessKeyword("id")) + uint_value("vendor_id")).set_name("vendor_id")

    type_or_ref = pp.Forward().set_name("type_or_ref")
    scoped_def = pp.Forward().set_name("scoped_def")

    type_name = pp.Group(identifier("name") + pp.Optional(tag_qual))
    type_def = pp.Group(
        type_name("type_name") + ARROW + type_or_ref("type")
    ).set_name("type_def")

    nullable_kw = pp.CaselessKeyword("nullable")("nullable")

    dots = pp.Literal("..")
    length_rhs = (
            (uint_value("min") + dots + uint_value("max")) ^
            (uint_value("min") + dots) ^
            uint_value("exact_length")
    )
    length_qualifier = (pp.Keyword("length") + length_rhs)

    range_bits = pp.one_of("8-bits 16-bits 32-bits 64-bits", as_keyword=True)("bit_qualifier")
    range_rhs = (range_bits ^ (int_value("min") + dots + int_value("max"))("range_qualifier"))
    range_qualifier = (pp.Keyword("range") + range_rhs)

    boolean_qualifier_list = (LBRACK + pp.DelimitedList(nullable_kw, delim=",") + RBRACK).set_name("qualifier list")
    boolean_type = pp.Group(pp.Keyword("BOOLEAN")("kind") + pp.Optional(boolean_qualifier_list))

    string_qualifier = pp.Or([nullable_kw, length_qualifier])
    string_qualifier_list = (LBRACK + pp.DelimitedList(string_qualifier, delim=",") + RBRACK)("qualifier")
    string_type = pp.Group(pp.Keyword("STRING")("kind") + pp.Optional(string_qualifier_list))
    octet_string_type = pp.Group(pp.Keyword("OCTET STRING")("kind") + pp.Optional(string_qualifier_list))

    integer_qualifier = pp.Or([nullable_kw, range_qualifier])
    integer_qualifier_list = (LBRACK + pp.DelimitedList(integer_qualifier, delim=",") + RBRACK)("qualifier")

    integer_enum = pp.Group(identifier("enum_name") + EQUAL + uint_value("enum_value"))
    integer_enum_list = pp.Group(LBRACE + pp.DelimitedList(integer_enum, delim=",") + RBRACE)("enum")

    signed_integer_type = pp.Group(pp.CaselessKeyword("SIGNED INTEGER")("kind") + pp.Optional(integer_qualifier_list) + pp.Optional(integer_enum_list))
    unsigned_integer_type = pp.Group(
        pp.CaselessKeyword("UNSIGNED INTEGER")("kind") + pp.Optional(integer_qualifier_list) + pp.Optional(integer_enum_list))

    array_qualifier = pp.Or([nullable_kw, length_qualifier])
    array_qualifier_list = (LBRACK + pp.DelimitedList(array_qualifier, delim=",") + RBRACK)("qualifier")
    array_of_type = pp.Group(pp.CaselessKeyword("ARRAY")("kind") + pp.Optional(array_qualifier_list) + pp.CaselessKeyword("OF") + type_or_ref("type"))

    id_qualifier = pp.Group(LBRACK + tag_spec + RBRACK)

    list_quantifier = (star | plus | pp.Group(LBRACE + length_rhs + RBRACE))
    list_field = pp.Group(
        identifier("field_name") + pp.Optional(id_qualifier)("qualifier") + COLON + type_or_ref("type") + pp.Optional(list_quantifier)("quantifier")
    )
    list_members = pp.DelimitedList(list_field, delim=",", allow_trailing_delim=True)("members")
    list_pattern_type = pp.Group(
        pp.CaselessKeyword("LIST")("kind") +
        pp.Optional(array_qualifier_list) +
        LBRACE + pp.Optional(list_members) + RBRACE
    )

    list_of_type = pp.Group(pp.CaselessKeyword("LIST")("kind") + pp.Optional(array_qualifier_list) + pp.CaselessKeyword("OF") + type_or_ref("type"))

    choice_of_field = pp.Group(
        identifier("field_name") + pp.Optional(id_qualifier)("qualifier") + COLON + type_or_ref("type")
    )
    choice_of_members = pp.DelimitedList(choice_of_field, delim=",", allow_trailing_delim=True)("members")

    choice_qualifier = pp.Or([nullable_kw])
    choice_qualifier_list = (LBRACK + pp.DelimitedList(choice_qualifier, delim=",") + RBRACK)("qualifier")
    choice_of_type = pp.Group(
        pp.CaselessKeyword("CHOICE")("kind") +
        pp.Optional(choice_qualifier_list) +
        pp.CaselessKeyword("OF") +
        LBRACE + pp.Optional(choice_of_members) + RBRACE
    )

    structure_kw = pp.CaselessKeyword("STRUCTURE")
    includes_kw = pp.Keyword("includes")

    structure_extensible_kw = pp.CaselessKeyword("extensible")("extensible_qualifier")
    structure_nullable_kw = pp.CaselessKeyword("nullable")
    structure_any_order_kw = pp.CaselessKeyword("any-order")
    structure_schema_order_kw = pp.CaselessKeyword("schema-order")
    structure_tag_order_kw = pp.CaselessKeyword("tag-order")
    structure_order_kw = (structure_any_order_kw ^ structure_schema_order_kw ^ structure_tag_order_kw)(
        "order_qualifier")
    structure_qualifier = pp.Or([structure_extensible_kw, structure_nullable_kw, structure_order_kw])
    structure_qualifier_list = pp.Group((LBRACK + pp.DelimitedList(structure_qualifier, delim=",") + RBRACK))(
        "qualifiers")

    id_optional_kw = pp.CaselessKeyword("optional")("optional")
    id_qualifier = pp.Or([tag_spec, id_optional_kw]).set_name("id-qualifier")
    id_qualifier_list = (LBRACK + pp.DelimitedList(id_qualifier, delim=",") + RBRACK).set_name("id-qualifier list")

    struct_field = pp.Group(
        identifier("field_name") + id_qualifier_list + COLON + type_or_ref("type")
    )
    struct_include = pp.Group(includes_kw + scoped_name("field-group-name"))
    struct_member = (struct_include | struct_field).set_name("struct_member")
    struct_members = pp.DelimitedList(struct_member, delim=",", allow_trailing_delim=True)("members")

    structure_type = pp.Group(
        structure_kw("kind")
        + pp.Optional(structure_qualifier_list)
        + LBRACE + pp.Optional(struct_members) + RBRACE
    ).set_name("structure_type")

    any_kw = pp.CaselessKeyword("ANY")
    any_type = pp.Group(
        any_kw("kind")
    ).set_name("any_type")

    protocol_kw = pp.Keyword("PROTOCOL")
    protocol_scoped_defs = pp.ZeroOrMore(scoped_def)
    protocol_def = pp.Group(
        identifier("name")
        + ARROW
        + protocol_kw("kind")
        + LBRACK + protocol_id + RBRACK
        + LBRACE + pp.Optional(protocol_scoped_defs)("defs") + RBRACE
    ).set_name("protocol_def")

    scoped_def <<= pp.Or([type_def])

    ref_qualifier = pp.Or([nullable_kw])
    ref_qualifier_list = (LBRACK + pp.DelimitedList(ref_qualifier, delim=",") + RBRACK)("qualifier")
    ref = pp.Group(scoped_name("name") + pp.Optional(ref_qualifier_list))

    type_or_ref <<= pp.Or([
        structure_type,
        list_pattern_type,
        boolean_type,
        string_type,
        octet_string_type,
        signed_integer_type,
        unsigned_integer_type,
        array_of_type,
        list_of_type,
        choice_of_type,
        any_type
    ]) | ref

    schema = pp.OneOrMore(pp.Or([protocol_def, type_def])).set_name("schema")
    schema = schema.ignore(pp.c_style_comment).ignore(pp.dbl_slash_comment)
    return schema


class Types:
    def __init__(self, parent: typing.Optional["Types"]):
        self.parent = parent
        self.types = {}

    def add_type(self, name: str, elm_type: str, annotation: typing.Optional[str]):
        self.types[name] = (elm_type, annotation)

    def __getitem__(self, item):
        if item in self.types:
            return self.types[item]
        elif self.parent:
            return self.parent[item]
        else:
            return None


class Renderer:
    def __init__(self):
        self.out = [
            "import typing",
            "import dataclasses",
            "import enum",
            "from . import tlv",
            ""
        ]
        self.ns = []
        self.types = Types(None)
        self.implicit_vendor_id = None
        self.implicit_profile = None
        self.indent = 0

    def write(self, s: str = ""):
        if s:
            self.out.append(self.indent * "  " + s)
        else:
            self.out.append("")

    def render_type(self, t: typing.Union[str, pp.ParseResults]) -> typing.Tuple[str, typing.Optional[str]]:
        if t.name:
            elm_type = self.types[t.name]
            if not elm_type:
                elm_type = f"typing.ForwardRef(\"{'.'.join(self.ns)}{'.' if self.ns else ''}{humps.pascalize(t.name)}\")", None

            if t.nullable:
                elm_type = f"{elm_type} | tlv.Null", elm_type[1]

            return elm_type
        else:
            annotation = None
            if t.kind == "BOOLEAN":
                elm_type = "bool"
            elif t.kind == "UNSIGNED INTEGER":
                annotation = {
                    "signed": False,
                }
                if t.bit_qualifier == "8-bits":
                    annotation["min"] = 0
                    annotation["max"] = 2 ** 8 - 1
                elif t.bit_qualifier == "16-bits":
                    annotation["min"] = 0
                    annotation["max"] = 2 ** 16 - 1
                elif t.bit_qualifier == "32-bits":
                    annotation["min"] = 0
                    annotation["max"] = 2 ** 32 - 1
                elif t.bit_qualifier == "64-bits":
                    annotation["min"] = 0
                    annotation["max"] = 2 ** 64 - 1
                elif t.range_qualifier:
                    annotation["min"] = int(t.min)
                    annotation["max"] = int(t.max)
                elm_type = "int"
            elif t.kind == "SIGNED INTEGER":
                annotation = {
                    "signed": True,
                }
                if t.bit_qualifier == "8-bits":
                    annotation["min"] = -2 ** 7
                    annotation["max"] = 2 ** 7 - 1
                elif t.bit_qualifier == "16-bits":
                    annotation["min"] = -2 ** 15
                    annotation["max"] = 2 ** 15 - 1
                elif t.bit_qualifier == "32-bits":
                    annotation["min"] = -2 ** 31
                    annotation["max"] = 2 ** 31 - 1
                elif t.bit_qualifier == "64-bits":
                    annotation["min"] = -2 ** 63
                    annotation["max"] = 2 ** 63 - 1
                elif t.range_qualifier:
                    annotation["min"] = int(t.min)
                    annotation["max"] = int(t.max)
                elm_type = "int"
            elif t.kind == "STRING" or t.kind == "OCTET STRING":
                if t.kind == "STRING":
                    elm_type = "str"
                elif t.kind == "OCTET STRING":
                    elm_type = "bytes"
                if t.exact_length:
                    annotation = {
                        "min_len": t.exact_length[0],
                        "max_len": t.exact_length[0]
                    }
                elif t.max and t.min:
                    annotation = {
                        "min_len": t.min[0],
                        "max_len": t.max[0]
                    }
                elif t.min:
                    annotation = {
                        "min_len": t.min[0],
                        "max_len": None
                    }
            elif t.kind == "ARRAY":
                base_type, base_annotation = self.render_type(t.type)
                annotation = {
                    "is_list": False
                }
                if base_annotation:
                    annotation["base_meta"] = base_annotation
                if t.exact_length:
                    annotation["min_len"] = t.exact_length[0]
                    annotation["max_len"] = t.exact_length[0]
                elif t.max and t.min:
                    annotation["min_len"] = t.min[0]
                    annotation["max_len"] = t.max[0]
                elif t.min:
                    annotation["min_len"] = t.min[0]
                elm_type = f"typing.List[{base_type}]"
            elif t.kind == "LIST":
                base_type, base_annotation = self.render_type(t.type)
                annotation = {
                    "is_list": True,
                }
                if base_annotation:
                    annotation["base_meta"] = base_annotation
                if t.exact_length:
                    annotation["min_len"] = t.exact_length[0]
                    annotation["max_len"] = t.exact_length[0]
                elif t.max and t.min:
                    annotation["min_len"] = t.min[0]
                    annotation["max_len"] = t.max[0]
                elif t.min:
                    annotation["min_len"] = t.min[0]
                elm_type = f"typing.List[{base_type}]"
            elif t.kind == "ANY":
                elm_type = "typing.Any"
            else:
                elm_type = "UNKNOWN"

            if t.nullable:
                elm_type = f"{elm_type} | tlv.Null"

            return elm_type, annotation

    def render_structure(self, d: pp.ParseResults):
        self.write("@dataclasses.dataclass")
        self.write(f"class {humps.pascalize(d.type_name.name)}(tlv.Structure):")
        self.indent += 1

        for m in d.type.members:
            elm_type, annotation = self.render_type(m.type)
            if m.optional:
                elm_type = f"typing.Optional[{elm_type}]"

            if annotation:
                self.write(f"{humps.decamelize(m.field_name).replace('-', '_')}: {elm_type} = dataclasses.field(metadata={annotation})")
            else:
                self.write(f"{humps.decamelize(m.field_name).replace('-', '_')}: {elm_type}")
        self.write("")

        self.write("class Meta:")
        self.indent += 1
        if self.implicit_vendor_id is not None:
            self.write(f"implicit_vendor_id = {self.implicit_vendor_id}")
        if self.implicit_profile is not None:
            self.write(f"implicit_profile = {self.implicit_profile}")
        if d.type.qualifiers.order_qualifier == "any-order":
            self.write("order = \"any\"")
        elif d.type.qualifiers.order_qualifier == "schema-order":
            self.write("order = \"schema\"")
        elif d.type.qualifiers.order_qualifier == "tag-order":
            self.write("order = \"tag\"")
        else:
            self.write("order = \"any\"")

        if d.type.qualifiers.extensible_qualifier:
            self.write("extensible = True")
        else:
            self.write("extensible = False")

        self.write("fields = (")
        self.indent += 1
        for m in d.type.members:
            if m.anonymous:
                self.write(f"tlv.Field(tag=tlv.AnonymousTag(), source=\"{humps.decamelize(m.field_name).replace("-", "_")}\", optional={'True' if m.optional else 'False'}),")
            elif m.context_specific:
                self.write(
                    f"tlv.Field(tag=tlv.ContextSpecificTag({m.context_specific[0]}), source=\"{humps.decamelize(m.field_name).replace("-", "_")}\", optional={'True' if m.optional else 'False'}),")
        self.indent -= 1
        self.write(")")
        self.indent -= 2
        self.write()

    def render_list(self, d: pp.ParseResults):
        self.write("@dataclasses.dataclass")
        self.write(f"class {humps.pascalize(d.type_name.name)}(tlv.List):")
        self.indent += 1

        members = []
        for m in d.type.members:
            is_optional = False
            is_list = False
            max_count = 1
            min_count = 1
            if m.quantifier:
                if m.quantifier.exact_length:
                    if m.quantifier.exact_length[0] == 1:
                        pass
                    else:
                        is_list = True
                        max_count = m.quantifier.exact_length[0]
                        min_count = m.quantifier.exact_length[0]
                elif m.quantifier.min is not None:
                    if m.quantifier.max is not None:
                        if m.quantifier.min[0] == 0 and m.quantifier.max[0] == 1:
                            is_optional = True
                            min_count = 0
                        else:
                            is_list = True
                            min_count = m.quantifier.min[0]
                            max_count = m.quantifier.max[0]
                    else:
                        is_list = True
                        min_count = m.quantifier.min[0]
                        max_count = None

            members.append({
                "member": m,
                "is_optional": is_optional,
                "is_list": is_list,
                "min_count": min_count,
                "max_count": max_count,
            })

        for m in members:
            elm_type, annotation = self.render_type(m["member"].type)

            if m["is_optional"]:
                elm_type = f"typing.Optional[{elm_type}]"
            if m["is_list"]:
                elm_type = f"typing.List[{elm_type}]"

            if not annotation:
                annotation = {}

            annotation["min_count"] = m["min_count"]
            annotation["max_count"] = m["max_count"]

            self.write(f"{humps.decamelize(m["member"].field_name)}: {elm_type} = dataclasses.field(metadata={annotation})")

        self.write("")

        self.write("class Meta:")
        self.indent += 1
        if self.implicit_vendor_id is not None:
            self.write(f"implicit_vendor_id = {self.implicit_vendor_id}")
        if self.implicit_profile is not None:
            self.write(f"implicit_profile = {self.implicit_profile}")

        self.write("fields = (")
        self.indent += 1
        for m in members:
            if m["member"].qualifier:
                if m["member"].qualifier[0].anonymous:
                    self.write(f"tlv.Field(tag=tlv.AnonymousTag(), source=\"{humps.decamelize(m["member"].field_name).replace("-", "_")}\", optional={'True' if m['min_count'] == 0 else 'False'}),")
                elif m["member"].qualifier[0].context_specific:
                    self.write(f"tlv.Field(tag=tlv.ContextSpecificTag({m["member"].qualifier[0].context_specific[0]}), source=\"{humps.decamelize(m["member"].field_name).replace("-", "_")}\", optional={'True' if m['min_count'] == 0 else 'False'}),")
            else:
                self.write(f"tlv.Field(tag=tlv.AnyTag(), source=\"{humps.decamelize(m["member"].field_name).replace("-", "_")}\", optional={'True' if m['min_count'] == 0 else 'False'}),")

        self.indent -= 1
        self.write(")")
        self.indent -= 2
        self.write()

    def render_choice_of(self, d: pp.ParseResults):
        self.write("@dataclasses.dataclass")
        self.write(f"class {humps.pascalize(d.type_name.name)}(tlv.ChoiceOf):")
        self.indent += 1

        self.write("variant: str")
        types = set()
        members = []
        for m in d.type.members:
            elm_type, annotation = self.render_type(m.type)
            types.add(elm_type)
            members.append({
                "name": m.field_name,
                "qualifier": m.qualifier[0] if m.qualifier else None,
                "annotation": annotation or {},
                "type": elm_type,
            })
        self.write(f"value: typing.Union[{', '.join(types)}]")
        self.write()

        self.write("class Meta:")
        self.indent += 1
        if self.implicit_vendor_id is not None:
            self.write(f"implicit_vendor_id = {self.implicit_vendor_id}")
        if self.implicit_profile is not None:
            self.write(f"implicit_profile = {self.implicit_profile}")

        self.write("options = (")
        self.indent += 1

        for m in members:
            if m["qualifier"]:
                if m["qualifier"].anonymous:
                    self.write(f"tlv.ChoiceField(tag=tlv.AnonymousTag(), name=\"{m['name']}\", type={m['type']}, annotation={m['annotation']}),")
                elif m["qualifier"].context_specific:
                    self.write(f"tlv.ChoiceField(tag=tlv.ContextSpecificTag({m['qualifier'].context_specific[0]}), name=\"{m['name']}\", type={m['type']}, annotation={m['annotation']}),")
            else:
                self.write(f"tlv.ChoiceField(tag=tlv.AnyTag(), name=\"{m['name']}\", type={m['type']}, annotation={m['annotation']}),")

        self.indent -= 1
        self.write(")")
        self.indent -= 2
        self.write()

    def render_enum(self, name: str, d: pp.ParseResults):
        self.write(f"class {humps.pascalize(name)}Enum(enum.IntEnum):")
        self.indent += 1
        for v in d:
            self.write(f"{humps.pascalize(v.enum_name)} = {v.enum_value[0]}")
        self.indent -= 1
        self.write()

    def render_protocol(self, d: pp.ParseResults):
        self.write(f"class {humps.pascalize(d.name)}Protocol:")
        self.ns.append(f"{humps.pascalize(d.name)}Protocol")
        self.indent += 1
        self.types = Types(self.types)
        if d.long_protocol_id:
            self.write(f"protocol_vendor_id = {d.long_protocol_id >> 16}")
            self.write(f"protocol_id = {d.long_protocol_id & 0xFFFF}")
            self.implicit_vendor_id = d.long_protocol_id >> 16
            self.implicit_profile = d.long_protocol_id & 0xFFFF
        elif d.vendor_id_protocol_id:
            self.write(f"protocol_vendor_id = {d.vendor_id_protocol_id[0]}")
            self.write(f"protocol_id = {d.vendor_id_protocol_id[1]}")
            self.implicit_vendor_id = d.vendor_id_protocol_id[0]
            self.implicit_profile = d.vendor_id_protocol_id[1]
        self.write()

        for pd in d.defs:
            self.render_scoped(pd)

        self.types = self.types.parent
        self.indent -= 1
        self.implicit_vendor_id = None
        self.implicit_profile = None
        self.ns.pop()

    def render_scoped(self, d: pp.ParseResults):
        if d.type.kind == "STRUCTURE":
            if d.type.members:
                self.render_structure(d)
        elif d.type.kind == "LIST" and d.type.members:
            self.render_list(d)
        elif d.type.kind == "CHOICE":
            self.render_choice_of(d)
        else:
            if d.type.enum:
                self.render_enum(d.type_name.name, d.type.enum)

            self.types.add_type(d.type_name.name, *self.render_type(d.type))

    def render(self, parse: pp.ParseResults):
        for d in parse:
            if d.kind == "PROTOCOL":
                self.render_protocol(d)
            elif d.type:
                self.render_scoped(d)

        self.write()


def main():
    renderer = Renderer()

    source_dir = pathlib.Path(os.path.dirname(__file__))
    for file in (source_dir / "schemas").glob("*.matter"):
        schema = make_schema()
        with open(file, "r") as f:
            parse = schema.parse_file(f, parse_all=True)
        renderer.render(parse)

    with open(source_dir / "matter" / "encoding" / "protocol_messages.py", "w") as f:
        for l in renderer.out:
            f.write(f"{l}\n")


if __name__ == "__main__":
    main()
