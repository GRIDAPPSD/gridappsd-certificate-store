"""Tests for device certificate generation."""

import uuid
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


def test_device_certificate_creation(cert_generator, ca_certificate, device_attrs):
    """Test that device certificates are created with correct attributes."""
    ca_cert, ca_key = ca_certificate
    device_cert, device_key = cert_generator.create_device_certificate(
        device_attrs, ca_cert, ca_key
    )
    
    # Verify certificate type and attributes
    assert isinstance(device_cert, x509.Certificate)
    assert isinstance(device_key, rsa.RSAPrivateKey)
    
    # Check subject fields were set correctly
    subject = device_cert.subject
    assert get_name_attr(subject, x509.NameOID.COMMON_NAME) == device_attrs['common_name']
    assert get_name_attr(subject, x509.NameOID.SERIAL_NUMBER) == device_attrs['serial_number']
    
    # Check that certificate is not a CA
    bc_ext = device_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc_ext.critical
    assert bc_ext.value.ca is False
    
    # Check key usage
    ku_ext = device_cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku_ext.critical
    assert ku_ext.value.digital_signature is True
    assert ku_ext.value.key_encipherment is True
    assert ku_ext.value.key_cert_sign is False  # Not a CA
    
    # Check extended key usage for client and server auth
    eku_ext = device_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert eku_ext.critical
    assert x509.ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value
    assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku_ext.value


def test_device_certificate_with_device_id(cert_generator, ca_certificate, device_attrs):
    """Test device certificate with a specific device ID in SAN."""
    ca_cert, ca_key = ca_certificate
    test_uuid = str(uuid.uuid4())
    
    device_cert, _ = cert_generator.create_device_certificate(
        device_attrs, ca_cert, ca_key, device_id=test_uuid
    )
    
    # Check that the UUID was included as a URI in SAN
    san_ext = device_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert any(isinstance(name, x509.UniformResourceIdentifier) and 
               f"urn:uuid:{test_uuid}" in name.value 
               for name in san_ext.value)


def test_device_certificate_validation_against_ca(cert_generator, ca_certificate, device_attrs):
    """Test that device certificates validate against their CA."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    
    ca_cert, ca_key = ca_certificate
    device_cert, _ = cert_generator.create_device_certificate(
        device_attrs, ca_cert, ca_key
    )
    
    # Verify that issuer matches CA's subject
    assert device_cert.issuer == ca_cert.subject
    
    # Get the CA's public key
    ca_public_key = ca_cert.public_key()
    hash_alg = device_cert.signature_hash_algorithm
    
    # Properly verify based on key type
    try:
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                device_cert.signature,
                device_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg
            )
        elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                device_cert.signature,
                device_cert.tbs_certificate_bytes,
                ec.ECDSA(hash_alg)
            )
        verification_succeeded = True
    except Exception as e:
        print(f"Verification failed: {e}")
        verification_succeeded = False
    
    assert verification_succeeded, "Device certificate verification against CA failed"


def test_self_signed_device_certificate(cert_generator, device_attrs):
    """Test creation of a self-signed device certificate."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography import x509
    
    device_cert, device_key = cert_generator.create_self_signed_device_cert(device_attrs)
    
    # Verify that subject and issuer match
    assert device_cert.subject == device_cert.issuer
    
    # Check that it's not a CA
    bc_ext = device_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc_ext.value.ca is False
    
    # Get public key for verification
    public_key = device_cert.public_key()  # Use the certificate's public key for verification
    hash_alg = device_cert.signature_hash_algorithm
    
    # Properly verify based on key type
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                device_cert.signature,
                device_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                device_cert.signature,
                device_cert.tbs_certificate_bytes,
                ec.ECDSA(hash_alg)
            )
        verification_succeeded = True
    except Exception as e:
        print(f"Self-signed device certificate verification failed: {e}")
        verification_succeeded = False
    
    assert verification_succeeded, "Self-signed device certificate verification failed"
    
    # Additional check: the public key in the certificate should match the generated private key
    cert_public_key = device_cert.public_key()
    private_key_public = device_key.public_key()
    
    if isinstance(cert_public_key, rsa.RSAPublicKey):
        assert cert_public_key.public_numbers().n == private_key_public.public_numbers().n
        assert cert_public_key.public_numbers().e == private_key_public.public_numbers().e
    elif isinstance(cert_public_key, ec.EllipticCurvePublicKey):
        assert cert_public_key.public_numbers().x == private_key_public.public_numbers().x
        assert cert_public_key.public_numbers().y == private_key_public.public_numbers().y

# Helper function
def get_name_attr(name, oid):
    """Extract an attribute from an X.509 name by OID."""
    for attr in name:
        if attr.oid == oid:
            return attr.value
    return None