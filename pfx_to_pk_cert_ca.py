ote: This code also work with normal SSL PFX certificate bundles. The CAs are put into a separate file.

'''
Convert a Google P12 (PFX) service account into private key and certificate.
Convert an SSL Certifcate (PFX) into private key, certificate and CAs.
'''

import os
import OpenSSL.crypto

def write_CAs(filename, p12):
    ''' Write the Certificate Authorities, if any, to filename '''

    ca = p12.get_ca_certificates()

    if ca is None:
        return

    if os.path.exists(filename):
        os.remove(filename)

    print('Creating Certificate CA File:', filename)

    with open(filename, 'wb') as f:
        for cert in ca:
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))

def pfx_to_pem(pfx_path, pfx_password, pkey_path, pem_path, pem_ca_path):
    '''
    Decrypt the P12 (PFX) file and create a private key file and certificate file.

    Input:
        pfx_path    INPUT: This is the Google P12 file or SSL PFX certificate file
        pfx_password    INPUT: Password used to protect P12 (PFX)
        pkey_path   INPUT: File name to write the Private Key to
        pem_path    INPUT: File name to write the Certificate to
        pem_ca_path INPUT: File name to write the Certificate Authorities to
    '''

    print('Opening:', pfx_path)
    with open(pfx_path, 'rb') as f_pfx:
        pfx = f_pfx.read()

    print('Loading P12 (PFX) contents:')
    p12 = OpenSSL.crypto.load_pkcs12(pfx, pfx_password)

    print('Creating Private Key File:', pkey_path)
    with open(pkey_path, 'wb') as f:
        # Write Private Key
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))

    print('Creating Certificate File:', pem_path)
    with open(pem_path, 'wb') as f:
        # Write Certificate
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))

    # Google P12 does not have certifiate authorities but SSL PFX certificates do
    write_CAs(pem_ca_path, p12)

# Start here

pfx_to_pem(
    'compute-engine.p12',   # Google Service Account P12 file
    'notasecret',       # P12 file password
    'compute-engine.key',   # Filename to write private key
    'compute-engine.pem',   # Filename to write certificate
    'compute-engine_ca.pem')# Filename to write CAs if present
