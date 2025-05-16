"""Tests for certificate store functionality."""

import pytest
import os
from cryptography.x509.oid import NameOID

from gridappsd_certs.store import CertificateStore

def test_certificate_store_init_empty():
    """Test initializing an empty certificate store."""
    store = CertificateStore()
    assert len(store.certificates) == 0

def test_add_certificate(device_cert):
    """Test adding a certificate to the store."""
    store = CertificateStore()
    cert, key = device_cert
    
    fingerprint = store.add_certificate(cert, key)
    assert fingerprint in store.certificates
    assert fingerprint in store.private_keys
    
    # Check indexing
    common_name = None
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            common_name = attr.value
            break
    
    assert common_name in store.common_name_index
    assert fingerprint in store.common_name_index[common_name]

def test_get_certificate_by_fingerprint(device_cert):
    """Test retrieving a certificate by fingerprint."""
    store = CertificateStore()
    cert, _ = device_cert
    
    fingerprint = store.add_certificate(cert)
    retrieved_cert = store.get_certificate_by_fingerprint(fingerprint)
    
    assert retrieved_cert is not None
    assert retrieved_cert.subject == cert.subject

def test_get_certificate_by_common_name(device_cert):
    """Test retrieving certificates by common name."""
    store = CertificateStore()
    cert, _ = device_cert
    
    store.add_certificate(cert)
    common_name = None
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            common_name = attr.value
            break
    
    certs = store.get_certificate_by_common_name(common_name)
    assert len(certs) > 0
    assert certs[0].subject == cert.subject

def test_get_certificate_by_san(cert_generator, ca_cert):
    """Test retrieving a certificate by Subject Alternative Name."""
    ca_cert_obj, ca_key = ca_cert
    device_attrs = {
        'common_name': 'Test Device With SAN',
        'organization': 'Test Organization',
        'country': 'US',
    }
    
    # Create cert with DNS SAN
    cert, _ = cert_generator.create_device_certificate(
        device_attrs, ca_cert_obj, ca_key,
        san_type='dns', san_values=['test.example.com']
    )
    
    store = CertificateStore()
    store.add_certificate(cert)
    
    retrieved_cert = store.get_certificate_by_san('DNS:test.example.com')
    assert retrieved_cert is not None
    assert retrieved_cert.subject == cert.subject

def test_get_private_key(device_cert):
    """Test retrieving a private key for a certificate."""
    store = CertificateStore()
    cert, key = device_cert
    
    fingerprint = store.add_certificate(cert, key)
    retrieved_key = store.get_private_key(fingerprint)
    
    assert retrieved_key is not None
    # Compare public key numbers to verify it's the same key
    assert retrieved_key.public_key().public_numbers().n == key.public_key().public_numbers().n
    assert retrieved_key.public_key().public_numbers().e == key.public_key().public_numbers().e

def test_list_certificates(device_cert):
    """Test listing all certificates in the store."""
    store = CertificateStore()
    cert, _ = device_cert
    
    store.add_certificate(cert)
    cert_list = store.list_certificates()
    
    assert len(cert_list) == 1
    assert len(cert_list[0]) == 4  # (fingerprint, subject, not_before, not_after)

def test_save_and_load_certificates(device_cert, temp_dir):
    """Test saving and loading certificates to/from storage."""
    store_path = os.path.join(temp_dir, "cert_store")
    
    # Create and populate store
    store = CertificateStore(storage_path=store_path)
    cert, key = device_cert
    
    fingerprint = store.add_certificate(cert, key, alias="test-device")
    
    # Create a new store pointing to the same path
    new_store = CertificateStore(storage_path=store_path)
    new_store.load_certificates()
    
    # Check that certificate was loaded
    assert fingerprint in new_store.certificates
    assert new_store.certificates[fingerprint].subject == cert.subject