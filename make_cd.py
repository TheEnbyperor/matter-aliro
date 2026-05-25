import pathlib
import os.path
import string
import random
import typing
import cryptography.x509
import cryptography.x509.oid
import cryptography.hazmat.asn1
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
import matter_aliro.matter.encoding.protocol_messages

VENDOR_ID = 0xFFF1
PRODUCT_ID = 0x8000
DEVICE_TYPE = 0x000A

SHA256_OID = cryptography.x509.oid.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
ECDSA_WITH_SHA256_OID = cryptography.x509.oid.ObjectIdentifier("1.2.840.10045.4.3.2")
PKCS7_DATA_OID = cryptography.x509.oid.ObjectIdentifier("1.2.840.113549.1.7.1")
SIGNED_DATA_OID = cryptography.x509.oid.ObjectIdentifier("1.2.840.113549.1.7.2")


@cryptography.hazmat.asn1.sequence
class DigestAlgorithmIdentifier:
    oid: cryptography.x509.oid.ObjectIdentifier

@cryptography.hazmat.asn1.sequence
class SignatureAlgorithmIdentifier:
    oid: cryptography.x509.oid.ObjectIdentifier

@cryptography.hazmat.asn1.sequence
class EncapsulatedContentInfo:
    e_content_type: cryptography.x509.oid.ObjectIdentifier
    e_content: typing.Annotated[bytes, cryptography.hazmat.asn1.Explicit(0)]


@cryptography.hazmat.asn1.sequence
class SignerInfo:
    version: int
    subject_key_identifier: typing.Annotated[bytes, cryptography.hazmat.asn1.Implicit(0)]
    digest_algorithm: DigestAlgorithmIdentifier
    signature_algorithm: SignatureAlgorithmIdentifier
    signature: bytes


@cryptography.hazmat.asn1.sequence
class CertificationDeclaration:
    version: int
    digest_algorithm: cryptography.hazmat.asn1.SetOf[DigestAlgorithmIdentifier]
    encap_content_info: EncapsulatedContentInfo
    signer_info: cryptography.hazmat.asn1.SetOf[SignerInfo]


@cryptography.hazmat.asn1.sequence
class ContentInfo:
    content_type: cryptography.x509.oid.ObjectIdentifier
    content: typing.Annotated[CertificationDeclaration, cryptography.hazmat.asn1.Explicit(0)]


def main():
    source_dir = pathlib.Path(os.path.dirname(__file__))
    certs_dir = source_dir / "certs"

    if not certs_dir.is_dir():
        certs_dir.mkdir(exist_ok=True)

    with open(source_dir / "cd-signer-cert.pem", "rb") as f:
        signer_cert = cryptography.x509.load_pem_x509_certificate(f.read())
    with open(source_dir / "cd-signer-key.pem", "rb") as f:
        signer_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(f.read(), None)

    cd_elements = matter_aliro.matter.encoding.protocol_messages.CertificationElements(
        format_version=1,
        vendor_id=VENDOR_ID,
        product_id_array=[PRODUCT_ID],
        device_type_id=DEVICE_TYPE,
        certificate_id="".join(random.choices(string.ascii_uppercase + string.digits, k=19)),
        security_level=0,
        security_information=0,
        version_number=1,
        certification_type=0,
        dac_origin_vendor_id=None,
        dac_origin_product_id=None,
        authorized_paa_list=None,
    ).encode_to_bytes()

    cd = ContentInfo(
        content_type=SIGNED_DATA_OID,
        content=CertificationDeclaration(
            version=3,
            digest_algorithm=cryptography.hazmat.asn1.SetOf([DigestAlgorithmIdentifier(
                oid=SHA256_OID
            )]),
            encap_content_info=EncapsulatedContentInfo(
                e_content_type=PKCS7_DATA_OID,
                e_content=cd_elements,
            ),
            signer_info=cryptography.hazmat.asn1.SetOf([SignerInfo(
                version=3,
                subject_key_identifier=signer_cert.extensions.get_extension_for_class(
                    cryptography.x509.SubjectKeyIdentifier).value.key_identifier,
                digest_algorithm=DigestAlgorithmIdentifier(
                    oid=SHA256_OID
                ),
                signature_algorithm=SignatureAlgorithmIdentifier(
                    oid=ECDSA_WITH_SHA256_OID
                ),
                signature=signer_key.sign(cd_elements, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA256()
                )),
            )])
        )
    )

    with open(certs_dir / "cd.der", "wb") as f:
        f.write(cryptography.hazmat.asn1.encode_der(cd))


if __name__ == "__main__":
    main()
