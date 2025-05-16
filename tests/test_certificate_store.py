"""Tests for the CertificateStore."""
import os
import uuid
import pytest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from gridappsd_certs import (
    CertificateStore,
    DeviceCertificateGenerator,
    calculate_lfdi_from_certificate,
    calculate_sfdi_from_lfdi
)

@pytest.fixture
def certificate_store(temp_dir):
    """Create a certificate store using a temporary directory."""
    return CertificateStore(storage_path=temp_dir)

@pytest.fixture
def populated_store(certificate_store, cert_generator, ca_certificate, device_attrs):
    """Create a certificate store with some certificates."""
    ca_cert, ca_key = ca_certificate
    
    # Add CA certificate
    ca_fingerprint = certificate_store.add_certificate(
        ca_cert, ca_key, alias="ca"
    )
    
    # Add device certificate with specific ID
    device_id = "FDA4B46E-A834-401B-8F6F-6D1B606D6F74"
    device_cert, device_key = cert_generator.create_device_certificate(
        device_attrs, ca_cert, ca_key, device_id=device_id
    )
    device_fingerprint = certificate_store.add_certificate(
        device_cert, device_key, alias=f"device_{device_id}"
    )
    
    # Add a server certificate
    server_attrs = {
        'common_name': 'test.example.com',
        'organization': 'Test Org',
        'country': 'US'
    }
    server_cert, server_key = cert_generator.create_web_certificate(
        server_attrs, ca_cert, ca_key, domains=['test.example.com']
    )
    server_fingerprint = certificate_store.add_certificate(
        server_cert, server_key, alias="server"
    )
    
    return {
        'store': certificate_store,
        'ca': {
            'cert': ca_cert,
            'key': ca_key,
            'fingerprint': ca_fingerprint
        },
        'device': {
            'cert': device_cert,
            'key': device_key,
            'fingerprint': device_fingerprint,
            'id': device_id
        },
        'server': {
            'cert': server_cert,
            'key': server_key,
            'fingerprint': server_fingerprint,
            'domain': 'test.example.com'
        }
    }

def test_add_certificate(certificate_store, ca_certificate):
    """Test adding a certificate to the store."""
    ca_cert, ca_key = ca_certificate
    
    # Add certificate to store
    fingerprint = certificate_store.add_certificate(ca_cert, ca_key, alias="Test CA")
    
    # Check that certificate was added
    assert fingerprint in certificate_store.certificates
    assert fingerprint in certificate_store.private_keys
    
    # Verify we can retrieve it
    retrieved_cert = certificate_store.get_certificate_by_fingerprint(fingerprint)
    assert retrieved_cert is not None
    assert retrieved_cert.subject == ca_cert.subject

def test_get_certificate_by_fingerprint(populated_store):
    """Test retrieving certificates by fingerprint."""
    device_fingerprint = populated_store['device']['fingerprint']
    device_cert = populated_store['device']['cert']
    
    # Get certificate by fingerprint
    retrieved_cert = populated_store['store'].get_certificate_by_fingerprint(device_fingerprint)
    
    # Verify it's the correct certificate
    assert retrieved_cert is not None
    assert retrieved_cert.subject == device_cert.subject

def test_get_certificate_by_common_name(populated_store):
    """Test retrieving certificates by common name."""
    server_cert = populated_store['server']['cert']
    server_cn = None
    
    # Extract common name
    for attr in server_cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            server_cn = attr.value
            break
    
    assert server_cn is not None
    
    # Get certificate by common name
    retrieved_certs = populated_store['store'].get_certificate_by_common_name(server_cn)
    
    # Verify it's the correct certificate
    assert len(retrieved_certs) > 0
    assert retrieved_certs[0].subject == server_cert.subject

def test_get_certificate_by_san(populated_store):
    """Test retrieving certificates by Subject Alternative Name."""
    server_cert = populated_store['server']['cert']
    server_domain = populated_store['server']['domain']
    
    # Get certificate by SAN
    retrieved_cert = populated_store['store'].get_certificate_by_san(f"DNS:{server_domain}")
    
    # Verify it's the correct certificate
    assert retrieved_cert is not None
    assert retrieved_cert.subject == server_cert.subject

def test_get_certificate_by_lfdi(populated_store):
    """Test retrieving device certificates by LFDI."""
    device_cert = populated_store['device']['cert']
    
    # Calculate LFDI
    lfdi = calculate_lfdi_from_certificate(device_cert)
    assert lfdi is not None
    
    # Get certificate by LFDI
    retrieved_cert = populated_store['store'].get_certificate_by_lfdi(lfdi)
    
    # Verify it's the correct certificate
    assert retrieved_cert is not None
    assert retrieved_cert.subject == device_cert.subject

def test_get_certificate_by_sfdi(populated_store):
    """Test retrieving device certificates by SFDI."""
    device_cert = populated_store['device']['cert']
    
    # Calculate LFDI and SFDI
    lfdi = calculate_lfdi_from_certificate(device_cert)
    sfdi = calculate_sfdi_from_lfdi(lfdi)
    assert sfdi is not None
    
    # Get certificate by SFDI
    retrieved_cert = populated_store['store'].get_certificate_by_sfdi(sfdi)
    
    # Verify it's the correct certificate
    assert retrieved_cert is not None
    assert retrieved_cert.subject == device_cert.subject

def test_get_private_key(populated_store):
    """Test retrieving private keys for certificates."""
    device_fingerprint = populated_store['device']['fingerprint']
    device_key = populated_store['device']['key']
    
    # Get private key
    retrieved_key = populated_store['store'].get_private_key(device_fingerprint)
    
    # Verify it's the correct key by comparing public key components
    assert retrieved_key is not None
    assert retrieved_key.public_key().public_numbers().n == device_key.public_key().public_numbers().n
    assert retrieved_key.public_key().public_numbers().e == device_key.public_key().public_numbers().e

def test_list_certificates(populated_store):
    """Test listing all certificates in the store."""
    # Get list of certificates
    cert_list = populated_store['store'].list_certificates()
    
    # Verify all three certificates are in the list
    assert len(cert_list) == 3
    
    # Verify format of returned data
    for fingerprint, subject, not_before, not_after in cert_list:
        assert isinstance(fingerprint, str)
        assert isinstance(subject, str)
        assert isinstance(not_before, int)
        assert isinstance(not_after, int)
        assert not_after > not_before

def test_load_certificates(temp_dir, ca_certificate, cert_generator, device_attrs):
    """Test loading certificates from storage."""
    # Create a store and add certificates
    store1 = CertificateStore(storage_path=temp_dir)
    ca_cert, ca_key = ca_certificate
    
    # Add CA certificate
    store1.add_certificate(ca_cert, ca_key, alias="ca")
    
    # Add device certificate with ID
    device_id = "FDA4B46E-A834-401B-8F6F-6D1B606D6F74"
    device_cert, device_key = cert_generator.create_device_certificate(
        device_attrs, ca_cert, ca_key, device_id=device_id
    )
    store1.add_certificate(device_cert, device_key, alias=f"device_{device_id}")
    
    # Create a new store that loads from the same path
    store2 = CertificateStore(storage_path=temp_dir)
    
    # Verify certificates were loaded
    assert len(store2.certificates) == 2
    
    # Calculate LFDI to check if indexing works
    lfdi = calculate_lfdi_from_certificate(device_cert)
    sfdi = calculate_sfdi_from_lfdi(lfdi)
    
    # Verify we can look up by various attributes
    assert store2.get_certificate_by_lfdi(lfdi) is not None
    assert store2.get_certificate_by_sfdi(sfdi) is not None

def test_certificate_storage_filenames(temp_dir, ca_certificate, cert_generator, device_attrs):
    """Test that certificates are stored with the correct filenames."""
    # Create a store and add certificates
    store = CertificateStore(storage_path=temp_dir)
    ca_cert, ca_key = ca_certificate
    
    # Add CA certificate
    ca_fingerprint = store.add_certificate(ca_cert, ca_key, alias="ca")
    
    # Add device certificate with ID
    device_id = "FDA4B46E-A834-401B-8F6F-6D1B606D6F74"
    device_cert, device_key = cert_generator.create_device_certificate(
        device_attrs, ca_cert, ca_key, device_id=device_id
    )
    device_fingerprint = store.add_certificate(device_cert, device_key, alias=f"device_{device_id}")
    
    # Add web server certificate
    server_attrs = {'common_name': 'www.example.com', 'organization': 'Test'}
    server_cert, server_key = cert_generator.create_web_certificate(
        server_attrs, ca_cert, ca_key, domains=['www.example.com']
    )
    server_fingerprint = store.add_certificate(server_cert, server_key, alias="server")
    
    # Check files were created with correct names
    assert Path(temp_dir, "ca.cert.pem").exists()
    assert Path(temp_dir, "ca.key.pem").exists()
    
    assert Path(temp_dir, f"device_{device_id}.cert.pem").exists() or \
           Path(temp_dir, "device_FDA4B46E-A834-401B-8F6F-6D1B606D6F74.cert.pem").exists()
    
    assert Path(temp_dir, "server_www.example.com.cert.pem").exists()
    assert Path(temp_dir, "server_www.example.com.key.pem").exists()

def test_saving_certificate_without_storage_path():
    """Test that adding a certificate without a storage path works."""
    # Create in-memory store
    store = CertificateStore()
    
    # Create a simple self-signed certificate
    gen = DeviceCertificateGenerator()
    cert, key = gen.create_ca_certificate({'common_name': 'Test CA'})
    
    # Add to store
    fingerprint = store.add_certificate(cert, key)
    
    # Verify it's in the store
    assert fingerprint in store.certificates
    assert fingerprint in store.private_keys

def test_determine_certificate_type(temp_dir):
    """Test the certificate type detection logic."""
    store = CertificateStore(storage_path=temp_dir)
    gen = DeviceCertificateGenerator()
    
    # Create certificates of different types
    ca_cert, ca_key = gen.create_ca_certificate({'common_name': 'Test CA'})
    
    device_attrs = {'common_name': 'Device 123', 'serial_number': 'DEV123'}
    device_id = "FDA4B46E-A834-401B-8F6F-6D1B606D6F74"
    device_cert, device_key = gen.create_device_certificate(
        device_attrs, ca_cert, ca_key, device_id=device_id
    )
    
    server_attrs = {'common_name': 'www.example.com'}
    server_cert, server_key = gen.create_web_certificate(
        server_attrs, ca_cert, ca_key, domains=['www.example.com']
    )
    
    # Use non-public method to check type detection
    ca_type, ca_id = store._determine_certificate_type(ca_cert, "ca")
    device_type, device_id_result = store._determine_certificate_type(device_cert, f"device_{device_id}")
    server_type, server_id = store._determine_certificate_type(server_cert, "server")
    
    # Verify correct type detection
    assert ca_type == "ca"
    assert device_type == "device"
    assert server_type == "server"

def test_extract_device_id(temp_dir):
    """Test extracting device ID from certificate."""
    store = CertificateStore(storage_path=temp_dir)
    gen = DeviceCertificateGenerator()
    
    # Create a CA
    ca_cert, ca_key = gen.create_ca_certificate({'common_name': 'Test CA'})
    
    # Create a device certificate with device ID
    device_attrs = {'common_name': 'Device 123', 'serial_number': 'DEV123'}
    device_id = "FDA4B46E-A834-401B-8F6F-6D1B606D6F74"
    device_cert, _ = gen.create_device_certificate(
        device_attrs, ca_cert, ca_key, device_id=device_id
    )
    
    # Extract device ID from URI SAN
    extracted_id = store._extract_device_id_from_certificate(device_cert)
    
    # Check if extracted correctly (may come from SAN or serial number)
    assert extracted_id is not None
    # The extraction might give us either the full UUID or the serial number
    assert extracted_id == device_id or extracted_id == "DEV123"