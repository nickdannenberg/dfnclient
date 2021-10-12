from subprocess import run, CalledProcessError
from sys import exit

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from termcolor import cprint

import re
import ipaddress

def gen_csr_with_new_cert(fqdn, subject, password, altnames=None):
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=4096,
                                   backend=default_backend())
    with open('{}.key'.format(fqdn), 'wb') as f:
        if password:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        password.encode()),
                ))
        else:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

    return generate_csr(key, fqdn, subject, altnames)


def gen_csr_with_existing_cert(key_path,
                               fqdn,
                               subject,
                               additional=None,
                               password=None):
    key = None
    with open(key_path, 'rb') as f:
        key = serialization.load_pem_private_key(f.read(), password,
                                                 default_backend())
    return generate_csr(key, fqdn, subject, additional)


# Helper function


def generate_csr(key, fqdn, subject, altnames=None):
    subj = []
    subj.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject['country']))
    subj.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject['state']))
    subj.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject['city']))
    subj.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject['org']))
    if 'unit' in subject:
        subj.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject['unit']))
    subj.append(x509.NameAttribute(NameOID.COMMON_NAME, subject['cn']))

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subj))
    if altnames != None:
        # build altnames (IP or DNS), email and uri aren't allowed
        alts = []
        for alt in altnames:
            if re.match('^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', alt) or re.match('^[0-9a-fA-F:]+$', alt):
                ip = ipaddress.ip_address(alt)
                alts.append(x509.IPAddress(ip))
            else:
                alts.append(x509.DNSName(alt))
        csr = csr.add_extension(
            x509.SubjectAlternativeName(alts),
            critical=False,
        )
    csr = csr.sign(key, hashes.SHA256(), default_backend())
    with open('{}.req'.format(fqdn), 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return csr.public_bytes(serialization.Encoding.PEM).decode()

# extract data from PKCS10 CSR
def data_from_csr(csr_path):
    "Read fqdn and altnames from CSR"
    with open(csr_path, 'rb') as f:
         request = x509.load_pem_x509_csr(f.read(), default_backend())
         if not(request):
             raise Exception('could not read CSR')
         fqdn = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
         ext_altname = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
         altnames = [f'DNS:{n}' for n in ext_altname.get_values_for_type(x509.DNSName)]
         altnames.extend( [f'IP:{n}' for n in ext_altname.get_values_for_type(x509.IPAddress)])

         return (fqdn, altnames, request.public_bytes(serialization.Encoding.PEM).decode())

def data_from_cert(cert_path):
    "Read fqdn, altnames and enddate from certificate"
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    if not(cert):
        raise Exception(f'could not read certificate from file "{cert_path}"')

    fqdn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ext_altname = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    altnames = [f'DNS:{n}' for n in ext_altname.get_values_for_type(x509.DNSName)]
    altnames.extend( [f'IP:{n}' for n in ext_altname.get_values_for_type(x509.IPAddress)])
    start = cert.not_valid_before
    end = cert.not_valid_after
    return { 'fqdn': fqdn,
             'additional': altnames,
             'not_valid_before': start,
             'not_valid_after': end
            }
