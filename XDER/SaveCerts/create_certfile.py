import XDER.ParseCerts.get_file
from OpenSSL import crypto
import binascii
import os
import base64

def bin_toHex(path_file, bin_list):
    """
    Convert binary to hexadecimal
    :param path_file:   # If param1 is valid (path exists), parse the certificate file at the path (param path_file)
    :param bin_list:    # If param1 is invalid (path does not exist), automatically parse param2 (binary string list of the certificate)
    :return: Hexadecimal string
    """
    try:
        list = XDER.ParseCerts.get_file.get_filebindata(path_file)
        print("get_filebindat YES, parse certificate from path", list)
    except:
        list = bin_list
        # print("Successfully parse data from list parameter:", list)

    # Read binary list of certificate and convert to hex list
    hex_list = []
    for binary in list:
        if len(binary) == 2:
            for i in binary:
                decimal = int(i, 2)
                hexadecimal = hex(decimal)[2:].zfill(2)
                hex_list.append(hexadecimal)
        else:
            decimal = int(binary, 2)
            hexadecimal = hex(decimal)[2:].zfill(2)
            hex_list.append(hexadecimal)
    # Convert hex list to hex string
    hex_string = ' '.join(hex_list)
    # print("strlist_bin—to—hex:", hex_string)
    return hex_string

def hex_toDER(hex_string, floder):
    """
    Convert hex string to DER certificate
    @param hex_string: Hexadecimal string
    @param floder: Save path
    @return: Byte type of hexadecimal
    """
    byte_obj = bytes.fromhex(hex_string)
    # print(byte_obj)  # Output: b'Hello'
    der_bytes = byte_obj
    with open(floder, 'wb') as f:
        f.write(der_bytes)
    # print("hex-to-byte:", byte_obj)
    return byte_obj

def der_to_pem(der_bytes, floder):
    """
    Convert DER certificate to PEM certificate
    @param der_bytes: Byte type data of DER certificate
    @param floder: Save path
    @return: PEM data of certificate
    """
    base64_data = base64.b64encode(der_bytes).decode('utf-8')
    CHUNK_SIZE = 64
    pem_cert = "-----BEGIN CERTIFICATE-----\n"
    for i in range(0, len(base64_data), CHUNK_SIZE):
        pem_cert += base64_data[i:i+CHUNK_SIZE] + "\n"
    pem_cert += "-----END CERTIFICATE-----\n"
    with open(floder, 'w') as file:
        file.write(pem_cert)
    return pem_cert

def hex_pem(hex_str, output):
    """
    Convert hex string to PEM certificate
    @param hex_str: Hexadecimal string
    @param output: Save path
    @return: PEM data of certificate
    """
    hex_str = hex_str.replace(" ", "")
    # Convert hex string to binary data
    der_data = binascii.unhexlify(hex_str)
    # Load DER encoded certificate
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_data)
    # Convert certificate to PEM encoding
    pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    # Save PEM encoded certificate to file
    if output != None:
        with open('../../format_conversion/' + output + '.crt', 'wb') as f:
            f.write(pem_data)
    return pem_data

def formatfactory(mode, path):
    """
    Format conversion
    @param mode: Mode
    @param path: Save path
    @return:
    """
    if mode == 'pem_toder':
        # Read certificate file
        cert_file_path = os.path.join(path)
        with open(cert_file_path, "rb") as f:
            cert_data = f.read()
        print(cert_data)
        if cert_data.startswith(b"-----BEGIN CERTIFICATE-----"):
            # Convert PEM format certificate to DER format
            cert_data = cert_data.decode("utf-8")
            cert_data = cert_data.replace("-----BEGIN CERTIFICATE-----", ""). \
                replace("-----END CERTIFICATE-----", "").replace("\n", "")
            cert_data = base64.b64decode(cert_data)

        path_split = path.split('\\')
        output = path_split[len(path_split) - 1].replace(".crt", '')
        with open('../../format_conversion/' + output + '.der', 'wb') as f:
            f.write(cert_data)
        print('pem converted to der')
    if mode == 'der_topem':
        der_hex = bin_toHex(path, [])
        path_split = path.split('\\')
        output = path_split[len(path_split) - 1]
        hex_pem(der_hex, output)
        print('der converted to pem')

def CAhex_toDER(hex_string, floder):
    """
    Same as the hex_toDER function above
    @param hex_string:
    @param floder:
    @return:
    """
    byte_obj = bytes.fromhex(hex_string)
    # print(byte_obj)  # Output: b'Hello'
    der_bytes = byte_obj
    with open(floder, 'wb') as f:
        f.write(der_bytes)
    # print("hex-to-byte:", byte_obj)
    return byte_obj

def CAder_to_pem(der_bytes, floder):
    """
    Same as der_to_pem above
    @param der_bytes:
    @param floder:
    @return:
    """
    base64_data = base64.b64encode(der_bytes).decode('utf-8')
    CHUNK_SIZE = 64
    pem_cert = "-----BEGIN CERTIFICATE-----\n"
    for i in range(0, len(base64_data), CHUNK_SIZE):
        pem_cert += base64_data[i:i+CHUNK_SIZE] + "\n"
    pem_cert += "-----END CERTIFICATE-----\n"
    with open(floder, 'w') as file:
        file.write(pem_cert)
    return pem_cert

# Batch conversion
# def get_filenames_in_directory(directory_path):
#     # List all files and folders in the directory using os.listdir
#     filenames = os.listdir(directory_path)
#
#     # If you only want to get file names instead of folders, filter with os.path.isfile
#     filenames = [f for f in filenames if os.path.isfile(os.path.join(directory_path, f))]
#
#     return filenames
# a = get_filenames_in_directory('E:\\work\\my_project\\AutoBrowCertDetailExtractor\\temp\\cycle_435c27de1732031531\\ca')
# for i in a:
#     formatfactory('der_topem', 'E:\\work\\my_project\\AutoBrowCertDetailExtractor\\temp\\cycle_435c27de1732031531\\ca\\' + i)

# Double backslash format
# path = 'E:\work\my_project\AutoBrowCertDetailExtractor\XDER\ca_suite\RSA3072\ca.crt'.replace('\\', '\\\\')
# formatfactory('pem_toder', path)
# hex_toDER('30 82 03 6c 30 82 02 54 a0 03 02 01 02 02 14 17 3c d6 92 f6 4d 3d 94 8e 95 7f b8 8d 87 38 c1 7e 39 b8 e9 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 81 ba 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 16 30 14 06 03 55 04 0a 13 0d 45 6e 74 72 75 73 74 2c 20 49 6e 63 2e 31 28 30 26 06 03 55 04 0b 13 1f 53 65 65 20 77 77 77 2e 65 6e 74 72 75 73 74 2e 6e 65 74 2f 6c 65 67 61 6c 2d 74 65 72 6d 73 31 39 30 37 06 03 55 04 0b 13 30 28 63 29 20 32 30 31 32 20 45 6e 74 72 75 73 74 2c 20 49 6e 63 2e 20 2d 20 66 6f 72 20 61 75 74 68 6f 72 69 7a 65 64 20 75 73 65 20 6f 6e 6c 79 31 2e 30 2c 06 03 55 04 03 13 25 45 6e 74 72 75 73 74 20 43 65 72 74 69 66 69 63 61 74 69 6f 6e 20 41 75 74 68 6f 72 69 74 79 20 2d 20 4c 31 4b 30 1e 17 0d 32 34 30 31 31 36 32 30 33 31 31 34 5a 17 0d 32 34 31 32 33 31 30 30 30 30 30 30 5a 30 10 31 0e 30 0c 06 03 55 04 03 0c 05 4d 79 20 43 41 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 b7 c2 f3 64 c0 74 09 6c 1e bb db 44 3b f0 ee 4d 97 65 5c aa 2f 85 4c e2 cc 64 cb aa 33 eb ba 5a 3b e4 bc b4 d2 03 35 93 62 41 4b cc fe f1 e4 2e cf 0b 40 62 39 93 6d 8f 4d ad 5f 14 ac 8b 6f 3a 2e 4a 75 6a ea 3c 5a d6 38 a2 30 d1 04 7f b5 5b da 02 87 9a e3 17 3d 09 35 9b 7f 3f 43 e6 84 cb 00 d0 23 c2 6b c6 c5 df 48 ca df 38 bb b2 14 71 19 e6 0a 1e 45 08 1a e8 2d d6 e2 e5 53 e3 8a 50 38 0f 01 70 30 82 9c e8 53 71 f5 cd 21 2f 88 f6 c9 15 11 95 2b d6 cf 36 f5 a5 8b 0a 2a 78 d1 4a 03 f0 f3 9e a1 a1 33 3c da 6a 58 82 25 d3 bf 43 46 3e 54 a2 f4 24 a7 92 2c 2d 18 17 17 9d ed 9f 8a d0 c1 a5 aa ca a5 56 b0 51 20 f1 5a 42 b3 c6 91 e8 a0 4d e2 24 54 73 2f e6 1f 70 de c6 88 0a ef 4c 9a 46 16 6c 35 fa 08 ae b4 1b 2f b9 72 13 8d bc bb 81 0b 30 f4 95 9a 46 b2 a7 1e 62 29 b3 02 03 01 00 01 a3 13 30 11 30 0f 06 03 55 1d 13 01 01 ff 04 05 30 03 01 01 ff 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 35 8f 9e f8 1e b0 6f 76 e7 a7 d2 f1 0a a5 78 1a 40 57 a5 4b 18 9f 8c 57 5c e2 ef 24 0b 4c df 86 6d 8c 00 11 0b 4a 9c 3d e8 08 3b 69 0b de 2d b1 3e a1 b1 5d a0 51 e4 3a 2c 45 ce 69 a6 86 1c 96 0f 69 27 14 3f 26 1a 4b ce ba cd e7 fe 50 6a 73 ff 13 c6 b6 e9 bc 9b f6 c4 97 0e 85 86 7f 35 8d a0 72 9d 10 83 69 fe 18 c2 93 ef 64 de cc 1f 47 10 91 56 8d f7 dd 68 e9 45 e4 a6 3e cb 6c ae f2 d0 59 9b b0 5e b5 2e 03 83 33 ac e9 92 38 d7 9c 98 dd 4c a9 ae 44 56 c7 70 44 3c 69 62 b5 25 3a 69 c0 f0 aa 6a df 2c 69 a7 90 f6 36 da d4 2c c1 bb 26 09 3c a3 9d 7b 27 fb fc 9b b2 f9 ae b4 3c cc ff ea df 7d 2f 45 9f e6 d5 78 9e 34 63 4f 0b b8 69 7b 34 93 93 8e 25 38 1b 14 2f e0 1c b1 a1 13 d1 12 c1 eb 33 91 b8 c8 2c 31 54 93 f6 87 1b b0 a7 10 d6 b6 2b e4 2e 79 7b 7d 8c 8e 23 ec aa','C:\\Users\\fisher\\Desktop\\hex.der' )