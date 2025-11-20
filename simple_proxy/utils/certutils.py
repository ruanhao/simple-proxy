import os
import logging
import tempfile
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat._oid import NameOID  # noqa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


def _generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def _generate_self_signed_cert(private_key, subject_name, valid_days=365):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Simple Proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    issuer = subject

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=valid_days)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(subject_name),
        ]),
        critical=False,
    ).sign(
        private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return cert


def _save_key_and_cert(private_key, cert, key_file_path, cert_file_path):
    # Save private key
    with open(key_file_path, 'wb') as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save certificate
    with open(cert_file_path, 'wb') as cert_file:
        cert_file.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )


def _create_temp_file(filename):
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, filename)
    with open(file_path, 'w'):
        pass
    return file_path


def create_temp_key_cert():
    kf_obj = _generate_private_key()
    cf_obj = _generate_self_signed_cert(kf_obj, 'localhost')
    kf = _create_temp_file('key.pem')
    cf = _create_temp_file('cert.pem')
    logger.debug(f"Generated key and cert: {kf}, {cf}")
    _save_key_and_cert(kf_obj, cf_obj, kf, cf)
    return kf, cf
