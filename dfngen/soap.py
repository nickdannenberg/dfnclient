from suds.client import Client
from suds import null
from hashlib import sha1

from base64 import b64decode

def soap_client(testserver, soap_url):
    if testserver:
        soap_url = 'https://pki.pca.dfn.de/test-eins-ca/cgi-bin/pub/soap?wsdl=1'
    else:
        if not(soap_url):
            soap_url = 'https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/soap?wsdl=1'
    return Client(soap_url)

def submit_request(req,
                   fqdn,
                   altnames,
                   profile,
                   pin,
                   applicant,
                   mail,
                   unit,
                   raid,
                   testserver,
                   onlyreqnumber=False,
                   soap_url=None,
                   **kwargs):
    pin_hashed = sha1(str(pin).encode()).hexdigest()
    cl = soap_client(testserver, soap_url)
    alt_type = cl.factory.create('ArrayOfString')
    alt_type._arrayType = "ns0:string[1]"
    alt_type.item = altnames
    req_number = cl.service.newRequest(
        RaID=raid,
        PKCS10=req,  # Certificate Signing Request
        AltNames=alt_type,  # Altnames
        Role=profile,
        Pin=pin_hashed,
        AddName=applicant,
        AddEMail=mail,
        AddOrgUnit=unit,
        Publish=True,  # publish cert
    )
    print('The request number is: {}'.format(req_number))
    if onlyreqnumber:
        return req_number
    pdf = cl.service.getRequestPrintout(RaID=raid,
                                        Serial=req_number,
                                        Format='application/pdf',
                                        Pin=pin_hashed)
    with open('{}.pdf'.format(fqdn), 'wb') as f:
        f.write(b64decode(pdf))
    return req_number


def download_certificate(fqdn, serial, pin, raid, testserver, soap_url = None, **args):
    pin_hashed = sha1(str(pin).encode()).hexdigest()
    cl = soap_client(testserver, soap_url)
    cert_data = cl.service.getCertificateByRequestSerial(RaID=raid,
                                                         Serial=serial,
                                                         Pin=pin_hashed)
    return cert_data


