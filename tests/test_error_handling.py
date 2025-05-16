"""Tests for error handling in the certificate generator."""

import pytest
from cryptography import x509


def test_invalid_key_type_raises_error():
    """Test that an invalid key type raises a ValueError."""
    from gridappsd_certs.generator import DeviceCertificateGenerator
    
    with pytest.raises(ValueError, match="Invalid key type"):
        DeviceCertificateGenerator(key_type='invalid_type')


def test_creating_device_cert_without_ca_key_raises_error(cert_generator, ca_certificate, device_attrs):
    """Test that trying to create a device certificate without a CA key raises an error."""
    ca_cert, _ = ca_certificate  # Only use the certificate, not the key
    
    # Attempt to create a device certificate without the CA key
    with pytest.raises(TypeError, match="Issuer private key cannot be None"):
        cert_generator.create_device_certificate(device_attrs, ca_cert, None)


def test_missing_required_subject_fields(cert_generator):
    """Test handling of missing required fields."""
    # Empty subject attributes
    empty_attrs = {}
    
    # This should work, but create a certificate with default attributes
    cert, _ = cert_generator.create_ca_certificate(empty_attrs)
    
    # The subject should have the default CN we added
    assert len(cert.subject) > 0
    
    # Extract the CN to make sure it follows our expected pattern
    cn = None
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            cn = attr.value
            break
    
    assert cn is not None
    assert cn.startswith("Certificate-") or cn == "Default-Certificate"


def test_nonexistent_file_for_loading(cert_generator, temp_dir):
    """Test that attempting to load a non-existent file raises FileNotFoundError."""
    non_existent_path = f"{temp_dir}/nonexistent_file.pem"
    
    with pytest.raises(FileNotFoundError):
        cert_generator.load_certificate(non_existent_path)
        
    with pytest.raises(FileNotFoundError):
        cert_generator.load_private_key(non_existent_path)