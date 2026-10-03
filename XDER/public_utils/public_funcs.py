import base64
import ctypes
import os
import random
from collections import Counter
import shutil

# Load Crypt32.dll library
crypt32 = ctypes.windll.crypt32

def find_keyalgorithm(path):
    """
    Identify certificate key and signature algorithm information
    @param path: Certificate path
    @return: Signature algorithm OID (e.g., 1.2.840.113549.1.1.1), public key length (e.g., 2048), signature algorithm name (e.g., sha256RSA)
    """
    class CertContext(ctypes.Structure):
        _fields_ = [("dwCertEncodingType", ctypes.c_ulong),
                    ("pbCertEncoded", ctypes.POINTER(ctypes.c_byte)),
                    ("cbCertEncoded", ctypes.c_ulong),
                    ("pCertInfo", ctypes.c_void_p),
                    ("hCertStore", ctypes.c_void_p)]

    class CRYPT_INTEGER_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbdata", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    class CRYPT_OBJID_BLOB(ctypes.Structure):
        _fields_ = [
            ('cbData', ctypes.c_ulong),
            ('pbData', ctypes.POINTER(ctypes.c_ubyte)),
        ]

    class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
        _fields_ = [
            ("pszObjId", ctypes.c_char_p),
            ("Parameters", CRYPT_OBJID_BLOB),
        ]

    class CERT_NAME_Blob(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", ctypes.c_ulong),
            ("dwHighDateTime", ctypes.c_ulong),
        ]

    class CRYPT_BIT_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ("cUnusedBits", ctypes.c_ulong),
        ]

    class CERT_EXTENSION(ctypes.Structure):
        _fields_ = [
            ("pszObjId", ctypes.c_wchar_p),
            ("fCritical", ctypes.c_bool),
            ("Value", CRYPT_INTEGER_BLOB),
        ]

    class PCERT_EXTENSION(ctypes.POINTER(CERT_EXTENSION)):
        pass

    class CERT_PUBLIC_KEY_INFO(ctypes.Structure):
        _fields_ = [
            ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("PublicKey", CRYPT_BIT_BLOB),
        ]

    class CertInfo(ctypes.Structure):
        _fields_ = [
            ("dwVersion", ctypes.c_ulong),
            ("SerialNumber", CRYPT_INTEGER_BLOB),
            ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("Issuer", CERT_NAME_Blob),
            ("NotBefore", FILETIME),
            ("NotAfter", FILETIME),
            ("Subject", CERT_NAME_Blob),
            ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
            ("IssuerUniqueId", CRYPT_BIT_BLOB),
            ("SubjectUniqueId", CRYPT_BIT_BLOB),
            ("cExtension", ctypes.c_ulong),
            ("rgExtension", PCERT_EXTENSION),
        ]

    class CRYPT_OID_INFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("pszOID", ctypes.c_char_p),
            ("pwszName", ctypes.c_wchar_p),
            ("dwGroupId", ctypes.c_ulong),
            ("u", ctypes.c_ulonglong),
            ("ExtraInfo", CRYPT_INTEGER_BLOB),
        ]

    PCERT_CONTEXT = ctypes.POINTER(CertContext)
    PCERT_INFO = ctypes.POINTER(CertInfo)
    X509_ASN_ENCODING = 0x00000001
    PCRYPT_OID_INFO = ctypes.POINTER(CRYPT_OID_INFO)

    # Define function prototypes
    CertCreateCertificateContext = crypt32.CertCreateCertificateContext
    CertCreateCertificateContext.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_byte), ctypes.c_ulong]
    CertCreateCertificateContext.restype = PCERT_CONTEXT

    GetLastError = ctypes.windll.kernel32.GetLastError

    CryptFindOIDInfo = crypt32.CryptFindOIDInfo
    CryptFindOIDInfo.restype = PCRYPT_OID_INFO
    CryptFindOIDInfo.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]

    CertGetPublicKeyLength = crypt32.CertGetPublicKeyLength
    CertGetPublicKeyLength.argtypes = [ctypes.c_ulong, ctypes.POINTER(CERT_PUBLIC_KEY_INFO)]
    CertGetPublicKeyLength.restype = ctypes.c_ulong

    def get_error_message(error_code):
        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
        FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
        FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100

        kernel32 = ctypes.windll.kernel32
        FormatMessageA = kernel32.FormatMessageA
        FormatMessageA.argtypes = [
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_uint32, ctypes.c_void_p
        ]
        FormatMessageA.restype = ctypes.c_uint32

        buffer = ctypes.c_char_p()
        buffer_size = FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            None, error_code, 0, ctypes.byref(buffer), 0, None
        )

        error_message = buffer.value.decode('gbk')
        kernel32.LocalFree(buffer)
        return error_message.strip()

    # Read certificate file
    cert_file_path = os.path.join(path)
    with open(cert_file_path, "rb") as f:
        cert_data = f.read()

    # Check if certificate is in PEM format
    if cert_data.startswith(b"-----BEGIN CERTIFICATE-----"):
        # Convert PEM to DER format
        cert_data = cert_data.decode("utf-8")
        cert_data = cert_data.replace("-----BEGIN CERTIFICATE-----", "").\
            replace("-----END CERTIFICATE-----", "").replace("\n", "")
        cert_data = base64.b64decode(cert_data)

    # Parse certificate
    cert_context = CertCreateCertificateContext(X509_ASN_ENCODING,
                                                (ctypes.c_byte * len(cert_data))(*cert_data),
                                                len(cert_data))

    if cert_context:
        cert_info = ctypes.cast(cert_context.contents.pCertInfo, PCERT_INFO).contents
        # Public key algorithm
        public_key_algorithm = cert_info.SubjectPublicKeyInfo.Algorithm.pszObjId
        oid_info = CryptFindOIDInfo(ctypes.c_ulong(1), public_key_algorithm, ctypes.c_ulong(0))

        public_key_info = cert_info.SubjectPublicKeyInfo
        public_key_length = CertGetPublicKeyLength(X509_ASN_ENCODING, ctypes.pointer(public_key_info))
        publickey_algoid = public_key_algorithm.decode("utf-8")
        # Signature algorithm
        signature_algorithm_oid = cert_info.SignatureAlgorithm.pszObjId
        oid_info = CryptFindOIDInfo(ctypes.c_ulong(1), signature_algorithm_oid, ctypes.c_ulong(0))
        sha = ''
        if oid_info:
            sha = str(oid_info.contents.pwszName)
        # Free certificate context
        crypt32.CertFreeCertificateContext(cert_context)
        return publickey_algoid, public_key_length, sha
    else:
        # Get error code and output error message
        error_code = GetLastError()
        error_message = get_error_message(error_code)
        print(f"Error code {error_code}: {error_message}")

def encode_oid(identifier):
    """
    Encode OID identifier
    @param identifier: OID (e.g., 1.2.3.4)
    @return: Hex encoded OID (e.g., 550406)
    """
    # Split identifier
    parts = list(map(int, identifier.split('.')))

    # Encode first two numbers
    first_byte = parts[0] * 40 + parts[1]

    # Encode remaining numbers
    remaining_bytes = [first_byte]
    for num in parts[2:]:
        bytes_needed = []
        while num >= 128:
            bytes_needed.append(num % 128)
            num //= 128
        bytes_needed.append(num)

        # Reverse byte list
        bytes_needed.reverse()

        # Set MSB to 1 for all bytes except last
        for i in range(len(bytes_needed) - 1):
            bytes_needed[i] |= 128

        remaining_bytes.extend(bytes_needed)

    # Convert to hex string
    hex_string = ''.join([format(byte, '02x') for byte in remaining_bytes])
    return hex_string

def decode_oid(binary_strings):
    """
    Decode OID from binary string list
    @param binary_strings: Binary string list of OID (e.g., ['01011001', ...])
    @return: Dot-separated OID identifier (e.g., 1.2.3.4)
    """
    # Get integer values from binary string list
    bytes_list = [int(bin_str, 2) for bin_str in binary_strings]

    # Decode first byte (contains first two OID components)
    first_byte = bytes_list[0]
    first = first_byte // 40
    second = first_byte % 40

    # Initialize result list with first two parts
    result = [first, second]

    # Process remaining bytes
    i = 1
    while i < len(bytes_list):
        # Single-byte value if MSB is 0
        if bytes_list[i] < 128:
            result.append(bytes_list[i])
            i += 1
        else:
            # Process multi-byte value
            value = 0
            while i < len(bytes_list) and bytes_list[i] >= 128:
                # Remove MSB and add to value
                value = (value * 128) + (bytes_list[i] - 128)
                i += 1

            # Add last byte (MSB is 0)
            if i < len(bytes_list):
                value = (value * 128) + bytes_list[i]
                i += 1

            result.append(value)

    # Convert to dot-separated string
    return '.'.join(map(str, result))

def hex_to_bin_str_list(hex_string):
    """
    Convert hex string to binary string list
    @param hex_string: Hexadecimal string
    @return: Binary string list representation of hex string
    """
    bin_str = bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)
    bin_str_list = [bin_str[i:i+4] for i in range(0, len(bin_str), 4)]
    final_list = ["".join(bin_str_list[i:i+2]) for i in range(0, len(bin_str_list), 2)]
    return final_list

def oid_tobin(oid):
    """
    Convert OID identifier to binary string list
    @param oid: OID (e.g., 1.2.3.4)
    @return: Binary string list representation of OID (e.g., ['01011001', ...])
    """
    hex_string = encode_oid(oid)
    oid_final_list = hex_to_bin_str_list(hex_string)
    return oid_final_list, hex_string

def get_folder_filenames(file_dir):
    """
    Read all files in current path (only filenames, save to .txt, exclude subfolders)
    @param file_dir: Current path
    @return: Text file with filenames, exi=1 if path exists, 0 otherwise
    """
    temp = 1
    name = "test_me_filename.txt"
    exi = os.path.exists(file_dir)
    if exi:
        for root, dirs, files in os.walk(file_dir):
            if temp <= 1:
                files = [f for f in files if not f.startswith('.')]
                files = str(files)
                files = files.replace("[", "").replace(",", "\n").replace("'", "").replace("]", "").replace(" ", "")
                with open('./test_me_filename.txt', 'w') as f:
                    print(files, file=f)
                temp += 1
        exi = int(exi)
    else:
        print("Folder does not exist")
        exi = int(exi)
    return name, exi

def get_certname(test_me):
    """
    Read filenames from test_me_filename.txt
    @param test_me: Text file with filenames
    @return: List of filenames from text file
    """
    certname_list = []
    for line in open(test_me):
        rs = line.rstrip('\n')
        certname_list.append(rs)
    return certname_list

def generate_random_str():
    """
    Generate random 8-bit binary string
    @return: 8-bit binary string, e.g., '01010101'
    """
    binary_str = ''
    for i in range(8):
        binary_str += str(random.randint(0, 1))
    return binary_str

def find_nodeID(cert_forest, id):
    """
    Find node by ID
    @param cert_forest: Certificate forest
    @param id: Node ID
    @return: Found node with matching node-id
    """
    for i in cert_forest:
        if i['node-id'] == id:
            return i

def get_all_node_ids(node, n, node_ids=None):
    """
    Get all node-ids under current node (including self and children)
    @param node: Current node
    @param n: Level counter (default 1)
    @param node_ids: Node ID dictionary
    @return: Dictionary of all node IDs organized by level, e.g., {'1': ['134346', '123132'], ...}
    """
    if node_ids is None:
        node_ids = {}

    if 'node-id' in node:
        if n not in node_ids:
            node_ids[n] = []
        node_ids[n].append(node['node-id'])

    if 'children' in node:
        for child in node['children']:
            get_all_node_ids(child, n+1, node_ids)

    return node_ids

def partiation(l: str, n=8):
    """
    Split binary stream into 8-bit chunks
    @param l: Binary string like '1010101010101010'
    @param n: Chunk size (default 8)
    @return: List of 8-bit binary strings
    """
    _result = []
    _item_list = []
    for _i in l:
        _item_list.append(_i)
        if len(_item_list) == n:
            _result.append("".join(_item_list))
            _item_list = []
    if len(_item_list) > 0:
        _result.append("".join(_item_list))
    return _result

def get_filenames_in_directory(directory_path):
    """
    List all files in directory
    @param directory_path: Target directory path
    @return: List of files in directory
    """
    filenames = os.listdir(directory_path)
    filenames = [f for f in filenames if os.path.isfile(os.path.join(directory_path, f))]
    return filenames

def copy_and_rename_file(source_path, destination_directory, new_name):
    """
    Copy single file to new path with new name
    @param source_path: Source file path
    @param destination_directory: Target directory
    @param new_name: New filename
    @return:
    """
    if not os.path.isfile(source_path):
        print(f"Source file {source_path} does not exist.")
        return

    if not os.path.exists(destination_directory):
        os.makedirs(destination_directory)

    destination_path = os.path.join(destination_directory, new_name)
    destination_path = destination_path.replace('\\', '/')
    shutil.copy2(source_path, destination_path)
    print(f"File copied to {destination_path}")

def copy_with_options(content_dict, dst_path, mode='merge'):
    """
    Write content dictionary to target path based on specified mode
    @param content_dict: Content dictionary from copy_all function
    @param dst_path: Target path
    @param mode: Copy mode, 'overwrite' or 'merge' (default)
    """
    try:
        if mode not in ['overwrite', 'merge']:
            raise ValueError("Mode must be 'overwrite' or 'merge'")

        if mode == 'overwrite' and os.path.exists(dst_path):
            shutil.rmtree(dst_path)

        if not os.path.exists(dst_path):
            os.makedirs(dst_path)

        for rel_path, content in content_dict.items():
            dst_full_path = os.path.join(dst_path, rel_path)

            if content is None:
                if not os.path.exists(dst_full_path):
                    os.makedirs(dst_full_path)
            else:
                os.makedirs(os.path.dirname(dst_full_path), exist_ok=True)
                with open(dst_full_path, 'wb') as f:
                    f.write(content)

        return True
    except Exception as e:
        print(f"Error during write: {str(e)}")
        return False

def copy_all(src_path):
    """
    Get all content from source path as dictionary (for use with copy_with_options)
    @param src_path: Source path
    @return: Content dictionary
    """
    try:
        content_dict = {}

        for root, dirs, files in os.walk(src_path):
            relative_path = os.path.relpath(root, src_path)

            for dir_name in dirs:
                dir_path = os.path.join(relative_path, dir_name) + '/'
                content_dict[dir_path] = None

            for file_name in files:
                file_path = os.path.join(root, file_name)
                rel_file_path = os.path.join(relative_path, file_name)

                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    content_dict[rel_file_path] = content
                except Exception as e:
                    print(f"Failed to read file {file_path}: {str(e)}")

        return content_dict
    except Exception as e:
        print(f"Error during copy: {str(e)}")
        return None

# Unused function, can be ignored
def weighted_random_sample(n, c):
    """
    Weighted random sampling
    @param n: Sample count
    @param c: Weight coefficient
    @return: Random sample
    """
    weights = [c**(n-i) for i in range(1, n+1)]
    total_weight = sum(weights)
    r = random.uniform(0, total_weight)
    cumulative_weight = 0
    for i in range(1, n+1):
        weight = weights[i-1]
        cumulative_weight += weight
        if cumulative_weight >= r:
            return i
# Example usage

# samples = [weighted_random_sample(10, 0.8) for _ in range(10000)]
# print(Counter(samples))
# sampless = [weighted_random_sample(10, 1.4) for _ in range(10000)]
# print(Counter(sampless))

# samples = [weighted_random_sample(4, 1.4) for _ in range(10000)]
# print(samples)
# print(Counter(samples))
# def calculate_tbs_hash(result_copy):
#     temp_node = []
#     tbs_node = []
#     solve_tree(result_copy, temp_node, None)
#     tbs_node.append(temp_node[1])
#
#     tbs_bin = result_to_binary(tbs_node)
#     tbs_hex = bin_toHex(tbs_bin)
#     tbs_byte = bytes.fromhex(tbs_hex)
#     tbs_hash_hex = hashlib.sha1(tbs_byte).hexdigest()
#
#     return tbs_hash_hex