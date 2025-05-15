"""Tests for web server certificate generation."""

from cryptography import x509


def test_web_certificate_creation(cert_generator, ca_certificate, web_attrs):
    """Test that web certificates are created with correct attributes."""
    ca_cert, ca_key = ca_certificate
    domains = ['example.com', 'www.example.com']
    
    web_cert, web_key = cert_generator.create_web_certificate(
        web_attrs, ca_cert, ca_key, domains=domains
    )
    
    # Check subject fields were set correctly
    subject = web_cert.subject
    assert get_name_attr(subject, x509.NameOID.COMMON_NAME) == web_attrs['common_name']
    
    # Check that the SAN extension includes all the domains
    san_ext = web_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
    
    for domain in domains:
        assert domain in dns_names
        
    # Extended Key Usage should include serverAuth
    eku_ext = web_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku_ext.value


def test_web_certificate_validation_against_ca(cert_generator, ca_certificate, web_attrs):
    """Test that web certificates validate against their CA."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    
    ca_cert, ca_key = ca_certificate
    web_cert, _ = cert_generator.create_web_certificate(
        web_attrs, ca_cert, ca_key, domains=['example.com']
    )
    
    # Verify that issuer matches CA's subject
    assert web_cert.issuer == ca_cert.subject
    
    # Get the CA's public key
    ca_public_key = ca_cert.public_key()
    hash_alg = web_cert.signature_hash_algorithm
    
    # Properly verify based on key type
    try:
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                web_cert.signature,
                web_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg
            )
        elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                web_cert.signature,
                web_cert.tbs_certificate_bytes,
                ec.ECDSA(hash_alg)
            )
        verification_succeeded = True
    except Exception as e:
        print(f"Verification failed: {e}")
        verification_succeeded = False
    
    assert verification_succeeded, "Web certificate verification against CA failed"


# Helper function
def get_name_attr(name, oid):
    """Extract an attribute from an X.509 name by OID."""
    for attr in name:
        if attr.oid == oid:
            return attr.value
    return None