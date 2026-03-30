import datetime
import math
import typing
import cryptography.x509
import cryptography.exceptions
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.hashes
import ber_tlv.tlv
from ..encoding import protocol_messages

ECDSA_WITH_SHA256 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
EC_PUB_KEY = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
EC_PRIME256V1 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])

EKU_SERVER_AUTH = bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])
EKU_CLIENT_AUTH = bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])
EKU_CODE_SIGNING = bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03])
EKU_EMAIL_PRODUCTION = bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04])
EKU_TIME_STAMPING = bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08])
EKU_OCSP_SIGNING = bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09])

MATTER_NODE_ID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x01])
MATTER_FIRMWARE_SIGNING = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x02])
MATTER_ICAC_ID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x03])
MATTER_RCAC_ID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x04])
MATTER_FABRIC_ID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x05])
MATTER_CASE_AUTHENTICATED_TAG = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x06])
MATTER_VVS_ID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x07])

BASIC_CONSTRAINTS = bytes([0x55, 0x1D, 0x13])
KEY_USAGE = bytes([0x55, 0x1D, 0x0F])
SKI = bytes([0x55, 0x1D, 0x0E])
AKI = bytes([0x55, 0x1D, 0x23])
EKU = bytes([0x55, 0x1D, 0x25])

EPOCH = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)

def encode_asn1_int(v: int):
    bits_needed = int(math.ceil(math.log2(v)))
    bytes_needed = (bits_needed + 7) // 8
    value = v.to_bytes(bytes_needed, byteorder="big")
    if value[0] & 0x80:
        return b"\x00" + value
    else:
        return value

def encode_x509_name(name: protocol_messages.DnAttribute):
    if name.variant == "matter-node-id":
        return (0x30, [
            (0x06, MATTER_NODE_ID),
            (0x0C, f"{name.value:016X}".encode("ascii")),
        ])
    elif name.variant == "matter-firmware-signing-id":
        return (0x30, [
            (0x06, MATTER_FIRMWARE_SIGNING),
            (0x0C, f"{name.value:016X}".encode("ascii")),
        ])
    elif name.variant == "matter-icac-id":
        return (0x30, [
            (0x06, MATTER_ICAC_ID),
            (0x0C, f"{name.value:016X}".encode("ascii")),
        ])
    elif name.variant == "matter-rcac-id":
        return (0x30, [
            (0x06, MATTER_RCAC_ID),
            (0x0C, f"{name.value:016X}".encode("ascii")),
        ])
    elif name.variant == "matter-fabric-id":
        return (0x30, [
            (0x06, MATTER_FABRIC_ID),
            (0x0C, f"{name.value:016X}".encode("ascii")),
        ])
    elif name.variant == "matter-noc-cat":
        return (0x30, [
            (0x06, MATTER_CASE_AUTHENTICATED_TAG),
            (0x0C, f"{name.value:06X}".encode("ascii")),
        ])
    elif name.variant == "matter-vvs-id":
        return (0x30, [
            (0x06, MATTER_VVS_ID),
            (0x0C, f"{name.value:016X}".encode("ascii")),
        ])
    else:
        raise Exception(f"Unsupported name attribute {name.variant}")


def encode_x509_extensions(extension: protocol_messages.Extension):
    if extension.variant == "basic-cnstr":
        vals = []
        if extension.value.is_ca:
            vals.append((0x01, b"\xff"))
        if extension.value.path_len_constraint is not None:
            vals.append((0x02, encode_asn1_int(extension.value.path_len_constraint)))
        return (0x30, [
            (0x06, BASIC_CONSTRAINTS),
            (0x01, b"\xff"),
            (0x04, ber_tlv.tlv.Tlv.build({
                0x30: vals
            })),
        ])
    elif extension.variant == "key-usage":
        highest_bit = -1
        for i in range(16):
            if extension.value & (1 << i):
                highest_bit = i

        if highest_bit == -1:
            data = b"\x00"
        else:
            num_bits = highest_bit + 1
            num_bytes = (num_bits + 7) // 8
            unused_bits = num_bytes * 8 - num_bits

            content = bytearray(num_bytes)

            for bit_index in range(num_bits):
                if extension.value & (1 << bit_index):
                    byte_index = bit_index // 8
                    bit_in_byte = bit_index % 8
                    content[byte_index] |= 1 << (7 - bit_in_byte)

            data = bytes([unused_bits, *content])

        return (0x30, [
            (0x06, KEY_USAGE),
            (0x01, b"\xff"),
            (0x04, ber_tlv.tlv.Tlv.build({
                0x03: data,
            })),
        ])
    elif extension.variant == "extended-key-usage":
        oids = []
        for i in extension.value:
            if i == 1:
                oids.append(EKU_SERVER_AUTH)
            elif i == 2:
                oids.append(EKU_CLIENT_AUTH)
            elif i == 3:
                oids.append(EKU_CODE_SIGNING)
            elif i == 4:
                oids.append(EKU_EMAIL_PRODUCTION)
            elif i == 5:
                oids.append(EKU_TIME_STAMPING)
            elif i == 6:
                oids.append(EKU_OCSP_SIGNING)
            else:
                raise Exception(f"Unsupported EKU {i}")

        return (0x30, [
            (0x06, EKU),
            (0x01, b"\xff"),
            (0x04, ber_tlv.tlv.Tlv.build({
                0x30: [(0x06, o) for o in oids]
            })),
        ])
    elif extension.variant == "subject-key-id":
        return (0x30, [
            (0x06, SKI),
            (0x04, ber_tlv.tlv.Tlv.build({
                0x04: extension.value
            })),
        ])
    elif extension.variant == "authority-key-id":
        return (0x30, [
            (0x06, AKI),
            (0x04, ber_tlv.tlv.Tlv.build({
                0x30: [
                    (0x80, extension.value),
                ]
            })),
        ])
    elif extension.variant == "future-extension":
        return ber_tlv.tlv.Tlv.parse(extension.value, True)
    else:
        raise Exception(f"Unsupported extension {extension.variant}")


def matter_cert_to_x509(cert: protocol_messages.MatterCertificate) -> bytes:
    tbs_cert: typing.List[typing.Tuple[int, typing.Union[bytes, list]]] = [
        (0xA0, b"\x02\x01\x02"),
        (0x02, (b"\x00" + cert.serial_num) if cert.serial_num[0] & 0x80 else cert.serial_num),
    ]

    if cert.sig_algo == protocol_messages.SignatureAlgorithmEnum.EcdsaWithSha256.value:
        tbs_cert.append((0x30, [
            (0x06, ECDSA_WITH_SHA256),
        ]))
    else:
        raise ValueError(f"Unsupported certificate signature algorithm: {cert.sig_algo}")

    tbs_cert.append((0x30, [
        (0x31, [encode_x509_name(n)]) for n in cert.issuer
    ]))

    validity = [
        (0x17, (EPOCH + datetime.timedelta(seconds=cert.not_before)).strftime("%y%m%d%H%M%SZ").encode("ascii")),
    ]
    if cert.not_after == 0:
        validity.append((0x18, b"99991231235959Z"))
    else:
        validity.append((0x17, (EPOCH + datetime.timedelta(seconds=cert.not_after)).strftime("%y%m%d%H%M%SZ").encode("ascii")))
    tbs_cert.append((0x30, validity))

    tbs_cert.append((0x30, [
        (0x31, [encode_x509_name(n)]) for n in cert.subject
    ]))

    if cert.pub_key_algo == protocol_messages.PublicKeyAlgorithmEnum.EcPubKey.value:
        if cert.ec_curve_id == protocol_messages.EllipticCurveIdEnum.Prime256v1.value:
            curve = EC_PRIME256V1
        else:
            raise ValueError(f"Unsupported EC curve ID: {cert.ec_curve_id}")

        tbs_cert.append((0x30, [
            (0x30, [
                (0x06, EC_PUB_KEY),
                (0x06, curve),
            ]),
            (0x03, b"\x00" + cert.ec_pub_key),
        ]))
    else:
        raise ValueError(f"Unsupported certificate public key algorithm: {cert.sig_algo}")

    tbs_cert.append((0xA3, ber_tlv.tlv.Tlv.build({
        0x30: [encode_x509_extensions(e) for e in cert.extensions]
    })))

    if cert.sig_algo == protocol_messages.SignatureAlgorithmEnum.EcdsaWithSha256.value:
        out_cert = {
            0x30: [
                (0x30, tbs_cert),
                (0x30, [
                    (0x06, ECDSA_WITH_SHA256),
                ]),
                (0x03, b"\x00" + cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(
                    int.from_bytes(cert.signature[0:32]), int.from_bytes(cert.signature[32:64])
                )),
            ]
        }
    else:
        raise ValueError(f"Unsupported certificate signature algorithm: {cert.sig_algo}")

    return ber_tlv.tlv.Tlv.build(out_cert)

def verify_chain(chain: typing.List[protocol_messages.MatterCertificate]) -> bool:
    now = datetime.datetime.now(datetime.timezone.utc)
    chain_x509 = [matter_cert_to_x509(cert) for cert in chain]
    chain_certs = [cryptography.x509.load_der_x509_certificate(cert) for cert in chain_x509]
    chain_certs.reverse()

    prev_cert = chain_certs[0]
    fabric_id = None
    fabric_id_oid = cryptography.x509.oid.ObjectIdentifier("1.3.6.1.4.1.37244.1.5")
    for i, cert in enumerate(chain_certs):
        try:
            cert.verify_directly_issued_by(prev_cert)
        except (ValueError, cryptography.exceptions.InvalidSignature):
            return False

        if cert.not_valid_before_utc > now:
            return False
        if cert.not_valid_after_utc < now:
            return False

        if fabric_id_attr := cert.subject.get_attributes_for_oid(fabric_id_oid):
            fabric_id_attr = fabric_id_attr[0]
            if fabric_id:
                if fabric_id_attr.value != fabric_id:
                    return False
            else:
                fabric_id = fabric_id_attr.value

        ee_cert = i == len(chain_certs) - 1
        try:
            bc = cert.extensions.get_extension_for_class(cryptography.x509.BasicConstraints)
            if not bc.critical:
                return False
        except cryptography.x509.ExtensionNotFound:
            return False
        try:
            ku = cert.extensions.get_extension_for_class(cryptography.x509.KeyUsage)
            if not ku.critical:
                return False
        except cryptography.x509.ExtensionNotFound:
            return False
        if not ee_cert:
            if not bc.value.ca:
                return False
            if bc.value.path_length is not None:
                if bc.value.path_length < len(chain) - 1:
                    return False
            if not ku.value.key_cert_sign:
                return False
        else:
            if bc.value.ca:
                return False
            if bc.value.path_length is not None:
                return False
            if not ku.value.digital_signature:
                return False

        prev_cert = cert

    return True

def verify_noc_dn(cert: protocol_messages.MatterCertificate) -> bool:
    if len(cert.subject) > 5:
        return False
    node_id_attrs = list(filter(lambda a: a.variant == "matter-node-id", cert.subject))
    fabric_id_attrs = list(filter(lambda a: a.variant == "matter-fabric-id", cert.subject))
    icac_id_attrs = list(filter(lambda a: a.variant == "matter-icac-id", cert.subject))
    rcac_id_attrs = list(filter(lambda a: a.variant == "matter-rcac-id", cert.subject))
    noc_cat_attrs = list(filter(lambda a: a.variant == "matter-noc-cat", cert.subject))
    vvs_id_attrs = list(filter(lambda a: a.variant == "matter-vvs-id", cert.subject))

    if len(node_id_attrs) != 1:
        return False
    if len(fabric_id_attrs) != 1:
        return False
    if len(icac_id_attrs) != 0:
        return False
    if len(rcac_id_attrs) != 0:
        return False
    if len(noc_cat_attrs) > 3:
        return False
    if len(vvs_id_attrs) != 0:
        return False

    node_id_attr = node_id_attrs[0]
    fabric_id_attr = fabric_id_attrs[0]

    if not (0x0000_0000_0000_0001 <= node_id_attr.value <= 0xFFFF_FFEF_FFFF_FFFF):
        return False
    if fabric_id_attr.value == 0:
        return False

    seen_cat_id = set()
    for noc_cat in noc_cat_attrs:
        tag = noc_cat.value >> 8
        if tag in seen_cat_id:
            return False
        seen_cat_id.add(tag)

    return True

def verify_icac_dn(cert: protocol_messages.MatterCertificate) -> bool:
    if len(cert.subject) > 5:
        return False
    node_id_attrs = list(filter(lambda a: a.variant == "matter-node-id", cert.subject))
    fabric_id_attrs = list(filter(lambda a: a.variant == "matter-fabric-id", cert.subject))
    icac_id_attrs = list(filter(lambda a: a.variant == "matter-icac-id", cert.subject))
    rcac_id_attrs = list(filter(lambda a: a.variant == "matter-rcac-id", cert.subject))
    noc_cat_attrs = list(filter(lambda a: a.variant == "matter-noc-cat", cert.subject))
    vvs_id_attrs = list(filter(lambda a: a.variant == "matter-vvs-id", cert.subject))

    if len(node_id_attrs) != 0:
        return False
    if len(fabric_id_attrs) > 1:
        return False
    if len(icac_id_attrs) != 1:
        return False
    if len(rcac_id_attrs) != 0:
        return False
    if len(noc_cat_attrs) != 0:
        return False
    if len(vvs_id_attrs) != 0:
        return False

    if fabric_id_attrs and fabric_id_attrs[0].value == 0:
        return False

    return True

def verify_rcac_dn(cert: protocol_messages.MatterCertificate) -> bool:
    if len(cert.subject) > 5:
        return False
    node_id_attrs = list(filter(lambda a: a.variant == "matter-node-id", cert.subject))
    fabric_id_attrs = list(filter(lambda a: a.variant == "matter-fabric-id", cert.subject))
    icac_id_attrs = list(filter(lambda a: a.variant == "matter-icac-id", cert.subject))
    rcac_id_attrs = list(filter(lambda a: a.variant == "matter-rcac-id", cert.subject))
    noc_cat_attrs = list(filter(lambda a: a.variant == "matter-noc-cat", cert.subject))
    vvs_id_attrs = list(filter(lambda a: a.variant == "matter-vvs-id", cert.subject))

    if len(node_id_attrs) != 0:
        return False
    if len(fabric_id_attrs) > 1:
        return False
    if len(icac_id_attrs) != 0:
        return False
    if len(rcac_id_attrs) != 1:
        return False
    if len(noc_cat_attrs) != 0:
        return False
    if len(vvs_id_attrs) != 0:
        return False

    if fabric_id_attrs and fabric_id_attrs[0].value == 0:
        return False

    return True

def verify_vvsc_dn(cert: protocol_messages.MatterCertificate) -> bool:
    if len(cert.subject) > 5:
        return False
    node_id_attrs = list(filter(lambda a: a.variant == "matter-node-id", cert.subject))
    fabric_id_attrs = list(filter(lambda a: a.variant == "matter-fabric-id", cert.subject))
    noc_cat_attrs = list(filter(lambda a: a.variant == "matter-noc-cat", cert.subject))
    vvs_id_attrs = list(filter(lambda a: a.variant == "matter-vvs-id", cert.subject))

    if len(node_id_attrs) != 0:
        return False
    if len(fabric_id_attrs) != 0:
        return False
    if len(noc_cat_attrs) != 0:
        return False
    if len(vvs_id_attrs) != 1:
        return False

    return True