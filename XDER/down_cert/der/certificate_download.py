# -*- coding: utf-8 -*-
import sys
import ssl
import socket
import OpenSSL.crypto as crypto
import time
import os


def mailsmsPoC(url, target_folder):
    # Create a TCP connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)

    # Connect to port 443 of the target URL (HTTPS)
    s.connect((url, 443))

    # Create SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Wrap socket with SSL context
    s = context.wrap_socket(s, server_hostname=url)

    # Get peer certificate
    cert = s.getpeercert(True)

    # Load certificate as OpenSSL.crypto.X509 object
    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

    # Save certificate in DER format
    with open(target_folder + url + '.der', 'wb') as f:
        f.write(cert)

    # Close socket connection
    s.close()


if __name__ == "__main__":
    filepath = './ips.csv'
    target_folder = './der/'

    # Create target folder if not exists
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    file = open(filepath, 'r')
    for f in file.readlines():
        url = f.strip('\r\n')
        try:
            url = f.strip('\r\n')
            mailsmsPoC(url, target_folder)
            time.sleep(0.01)
        except:
            print("Connection timeout or error")
            continue