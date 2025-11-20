from simple_proxy.utils import create_temp_key_cert
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone, timedelta


def test_create_temp_key_cert():
    kf, cf = create_temp_key_cert()
    assert kf
    assert cf
    with open(kf, 'rb') as kf_file:
        key_data = kf_file.read()
        assert b'BEGIN RSA PRIVATE KEY' in key_data
    with open(cf, 'rb') as cf_file:
        cert_data = cf_file.read()
        assert b'BEGIN CERTIFICATE' in cert_data
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        not_before_utc = cert.not_valid_before_utc
        not_after_utc = cert.not_valid_after_utc
        current_utc = datetime.now(timezone.utc)
        assert not_before_utc <= current_utc <= not_after_utc
        print("Certificate validity period:", not_before_utc, "to", not_after_utc)
        print((not_after_utc - current_utc) > timedelta(days=364))
