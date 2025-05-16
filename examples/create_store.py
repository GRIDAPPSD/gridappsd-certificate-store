from gridappsd_certs import (
    CertificateStore,
    calculate_lfdi_from_certificate,
    calculate_sfdi_from_lfdi,
    DeviceCertificateGenerator
)

# Create a certificate store with persistent storage
store = CertificateStore(storage_path="my_store")

# Initialize the generator
cert_gen = DeviceCertificateGenerator(key_type='rsa', key_size=2048)

# Create a CA certificate
ca_attrs = {
    'common_name': 'GridAPPSD Root CA',
    'organization': 'GridAPPSD',
    'country': 'US',
    'organizational_unit': 'Security'
}

ca_cert, ca_key = cert_gen.create_ca_certificate(ca_attrs, valid_days=3652)

# Create a device certificate for IEEE 2030.5
device_attrs = {
    #'common_name': 'Smart Meter 101',
    'organization': 'GridAPPSD',
    'country': 'US',
    'organizational_unit': 'Smart Meters',
    'serial_number': 'SM101-12345'
}

device_cert, device_key = cert_gen.create_device_certificate(
    device_attrs,
    ca_cert,
    ca_key,
    device_id="FDA4B46E-A834-401B-8F6F-6D1B606D6F74"
)

# Add certificates to the store
ca_fingerprint = store.add_certificate(ca_cert, ca_key, alias="Root CA")
device_fingerprint = store.add_certificate(device_cert, device_key, alias="Device 101")

# Look up certificates by various attributes
cert_by_fingerprint = store.get_certificate_by_fingerprint(device_fingerprint)
certs_by_common_name = store.get_certificate_by_common_name("Smart Meter 101")

# Get IEEE 2030.5 identifiers
lfdi = calculate_lfdi_from_certificate(device_cert)
sfdi = calculate_sfdi_from_lfdi(lfdi)
print(f"Device LFDI: {lfdi}")
print(f"Device SFDI: {sfdi}")

# Get private key for a certificate
device_key = store.get_private_key(device_fingerprint)