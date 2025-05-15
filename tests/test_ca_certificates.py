"""Tests for CA certificate generation."""

import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def test_ca_certificate_creation(cert_generator, ca_attrs):
    """Test that CA certificates are created with correct attributes."""
    cert, key = cert_generator.create_ca_certificate(ca_attrs)
    
    # Verify certificate type and attributes
    assert isinstance(cert, x509.Certificate)
    assert isinstance(key, rsa.RSAPrivateKey)
    
    # Check subject fields were set correctly
    subject = cert.subject
    assert get_name_attr(subject, x509.NameOID.COMMON_NAME) == ca_attrs['common_name']
    assert get_name_attr(subject, x509.NameOID.ORGANIZATION_NAME) == ca_attrs['organization']
    assert get_name_attr(subject, x509.NameOID.COUNTRY_NAME) == ca_attrs['country']
    
    # Check basic constraints
    bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc_ext.critical
    assert bc_ext.value.ca is True
    
    # Check key usage
    ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku_ext.critical
    assert ku_ext.value.key_cert_sign is True
    assert ku_ext.value.crl_sign is True
    assert ku_ext.value.digital_signature is True


def test_ca_certificate_with_ec_key(ec_cert_generator, ca_attrs):
    """Test CA certificate creation with EC key."""
    cert, key = ec_cert_generator.create_ca_certificate(ca_attrs)
    
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    # Verify the curve is as expected (default is SECP256R1)
    assert key.curve.name == 'secp256r1'


def test_ca_certificate_validity_period(cert_generator, ca_attrs):
    """Test that CA certificates have the correct validity period."""
    # Test with 10 days validity
    test_days = 10
    cert, _ = cert_generator.create_ca_certificate(ca_attrs, valid_days=test_days)
    
    # Check that dates are within 5 minutes of expected
    now = datetime.datetime.utcnow()
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    
    assert abs((not_before - now).total_seconds()) < 300  # Within 5 minutes
    expected_expiry = now + datetime.timedelta(days=test_days)
    assert abs((not_after - expected_expiry).total_seconds()) < 300


def test_self_signed_ca_verification(cert_generator, ca_attrs):
    """Test that the CA certificate is correctly self-signed and verifiable."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    
    cert, key = cert_generator.create_ca_certificate(ca_attrs)
    
    # Verify that subject and issuer match
    assert cert.subject == cert.issuer
    
    # Verify the certificate against its own public key
    public_key = cert.public_key()
    hash_alg = cert.signature_hash_algorithm
    
    # Properly verify based on key type
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hash_alg)
            )
        verification_succeeded = True
    except Exception as e:
        print(f"Verification failed: {e}")
        verification_succeeded = False
    
    assert verification_succeeded, "Self-signed CA certificate verification failed"


# Helper function
def get_name_attr(name, oid):
    """Extract an attribute from an X.509 name by OID."""
    for attr in name:
        if attr.oid == oid:
            return attr.value
    return None