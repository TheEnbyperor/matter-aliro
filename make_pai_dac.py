import pathlib
import os.path
import datetime
import cryptography.x509
import cryptography.x509.oid
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec

VENDOR_ID = 0xFFF1
PRODUCT_ID = 0x8000

VENDOR_ID_OID = cryptography.x509.oid.ObjectIdentifier("1.3.6.1.4.1.37244.2.1")
PRODUCT_ID_OID = cryptography.x509.oid.ObjectIdentifier("1.3.6.1.4.1.37244.2.2")


def main():
    source_dir = pathlib.Path(os.path.dirname(__file__))
    certs_dir = source_dir / "certs"

    if not certs_dir.is_dir():
        certs_dir.mkdir(exist_ok=True)

    with open(source_dir / "paa-cert.pem", "rb") as f:
        paa_cert = cryptography.x509.load_pem_x509_certificate(f.read())
    with open(source_dir / "paa-key.pem", "rb") as f:
        paa_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(f.read(), None)

    pai_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
    )
    pai_public_key = pai_key.public_key()
    pai_ski = cryptography.x509.SubjectKeyIdentifier.from_public_key(pai_public_key)

    pai_builder = cryptography.x509.CertificateBuilder()
    pai_builder = pai_builder.serial_number(cryptography.x509.random_serial_number())
    pai_builder = pai_builder.issuer_name(paa_cert.subject)
    pai_builder = pai_builder.subject_name(cryptography.x509.Name([
        cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, "Matter Aliro PAI"),
        cryptography.x509.NameAttribute(VENDOR_ID_OID, f"{VENDOR_ID:04X}"),
    ]))
    pai_builder = pai_builder.not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=30))
    pai_builder = pai_builder.not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59))
    pai_builder = pai_builder.public_key(pai_public_key)
    pai_builder = pai_builder.add_extension(cryptography.x509.BasicConstraints(
        ca=True, path_length=0
    ), critical=True)
    pai_builder = pai_builder.add_extension(cryptography.x509.KeyUsage(
        key_cert_sign=True,
        crl_sign=True,
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    ), critical=True)
    pai_builder = pai_builder.add_extension(pai_ski, critical=False)
    pai_builder = pai_builder.add_extension(cryptography.x509.AuthorityKeyIdentifier(
        key_identifier=paa_cert.extensions.get_extension_for_class(cryptography.x509.SubjectKeyIdentifier).value.key_identifier,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    ), critical=False)
    pai_cert = pai_builder.sign(
        private_key=paa_key,
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        ecdsa_deterministic=True
    )

    with open(certs_dir / "pai-key.pem", "wb") as f:
        f.write(pai_key.private_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM,
            cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
            cryptography.hazmat.primitives.serialization.NoEncryption()
        ))
    with open(certs_dir / "pai-cert.pem", "wb") as f:
        f.write(pai_cert.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM,
        ))

    dac_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
    )
    dac_public_key = dac_key.public_key()
    dac_ski = cryptography.x509.SubjectKeyIdentifier.from_public_key(dac_public_key)

    dac_builder = cryptography.x509.CertificateBuilder()
    dac_builder = dac_builder.serial_number(cryptography.x509.random_serial_number())
    dac_builder = dac_builder.issuer_name(pai_cert.subject)
    dac_builder = dac_builder.subject_name(cryptography.x509.Name([
        cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, "Matter Aliro DAC"),
        cryptography.x509.NameAttribute(VENDOR_ID_OID, f"{VENDOR_ID:04X}"),
        cryptography.x509.NameAttribute(PRODUCT_ID_OID, f"{PRODUCT_ID:04X}"),
    ]))
    dac_builder = dac_builder.not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=30))
    dac_builder = dac_builder.not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59))
    dac_builder = dac_builder.public_key(dac_public_key)
    dac_builder = dac_builder.add_extension(cryptography.x509.BasicConstraints(
        ca=False, path_length=None
    ), critical=True)
    dac_builder = dac_builder.add_extension(cryptography.x509.KeyUsage(
        key_cert_sign=False,
        crl_sign=False,
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    ), critical=True)
    dac_builder = dac_builder.add_extension(dac_ski, critical=False)
    dac_builder = dac_builder.add_extension(cryptography.x509.AuthorityKeyIdentifier(
        key_identifier=pai_ski.key_identifier,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    ), critical=False)
    dac_cert = dac_builder.sign(
        private_key=pai_key,
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        ecdsa_deterministic=True
    )

    with open(certs_dir / "dac-key.pem", "wb") as f:
        f.write(dac_key.private_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM,
            cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
            cryptography.hazmat.primitives.serialization.NoEncryption()
        ))
    with open(certs_dir / "dac-cert.pem", "wb") as f:
        f.write(dac_cert.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM,
        ))

if __name__ == "__main__":
    main()