import os
import ctypes
import re
import subprocess

# Load Crypt32.dll library
crypt32 = ctypes.windll.crypt32
from XDER.ParseCerts.dump import ctree_tobin
from XDER.SaveCerts.create_certfile import bin_toHex, hex_toDER

def certutil_check(cert_tree):
    """
    Use certutil to verify semantic correctness of certificate saved from TLV tree
    @param cert_tree: Certificate TLV tree
    @return: Certutil verification result
    """
    bin_list = ctree_tobin(cert_tree)
    hex_str = bin_toHex('', bin_list)
    hex_toDER(hex_str, "../cache/certutil_check.der")
    current_dir = os.path.dirname(os.path.abspath(__file__)).replace('\XDER', '').replace('\\', '/')
    current_dir = current_dir.replace('public_utils', '')
    command = ["certutil", "-addstore", 'ca', current_dir + 'cache/certutil_check.der']
    completed_process = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)

    if 'failed' not in completed_process.stdout:
        process = subprocess.run("certutil -hashfile " + current_dir + 'cache/certutil_check.der',
                                 stdout=subprocess.PIPE, shell=True)
        output = process.stdout.decode('GBK').split('\n')
        tbs_hash_hex = output[1]
        command = ["certutil", "-delstore", 'ca', tbs_hash_hex.replace('\r', '')]
        completed_process = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
        message = "validity"
        return message
    else:
        message = "invalidity"
        return message

def check_certDoTder_validity(cert_tree):
    """
    Use Crypt32.dll to verify semantic correctness of certificate saved from TLV tree
    @param cert_tree: Certificate TLV tree
    @return: Crypt32.dll verification result
    """
    bin_list = ctree_tobin(cert_tree)
    hex_str = bin_toHex('', bin_list)
    cert_data = bytes.fromhex(hex_str)
    # Define function prototype
    class CertContext(ctypes.Structure):
        _fields_ = [("dwCertEncodingType", ctypes.c_ulong),
                    ("pbCertEncoded", ctypes.POINTER(ctypes.c_byte)),
                    ("cbCertEncoded", ctypes.c_ulong),
                    ("pCertInfo", ctypes.c_void_p),
                    ("hCertStore", ctypes.c_void_p)]

    GetLastError = ctypes.windll.kernel32.GetLastError
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
    PCERT_CONTEXT = ctypes.POINTER(CertContext)
    X509_ASN_ENCODING = 0x00000001

    CertCreateCertificateContext = crypt32.CertCreateCertificateContext
    CertCreateCertificateContext.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_byte), ctypes.c_ulong]
    CertCreateCertificateContext.restype = PCERT_CONTEXT

    # Parse certificate
    cert_context = CertCreateCertificateContext(X509_ASN_ENCODING,
                                                (ctypes.c_byte * len(cert_data))(*cert_data),
                                                len(cert_data))
    if cert_context:
        message = "validity"
    else:
        # Get error code and output error message
        error_code = GetLastError()
        error_message = get_error_message(error_code)
        message = "invalidity  " + f"Error code {error_code}: {error_message}"

    return message


# Nginx control
class op_nginx:
    def __init__(self):
        pass
    def config(self, nginx_conf_file, cert_path, pri_key):
        """
        Configure nginx
        @param nginx_conf_file: Absolute path to config file
        @param cert_path: Absolute path to certificate
        @param pri_key: Absolute path to private key
        @return:
        """
        with open(nginx_conf_file, 'r+') as f:
            conf = f.read()
            conf = re.sub(r'ssl_certificate\s+.*;',
                          'ssl_certificate   %s;' % cert_path,
                          conf)
            conf = re.sub(r'ssl_certificate_key\s+.*;',
                          'ssl_certificate_key   %s;' % pri_key,
                          conf)
            f.seek(0)
            f.write(conf)
            f.truncate()

    def run_nginx(self):
        """
        Start nginx
        @return:
        """
        current_dir = os.path.dirname(__file__).replace('XDER\public_utils', 'BrowCertExtractor\config_server')
        nginx_dir = os.path.join(current_dir, "nginx-1.23.1")
        nginx_exe = os.path.join(nginx_dir, "nginx.exe")

        process = subprocess.Popen([nginx_exe], stdout=subprocess.PIPE, cwd=nginx_dir)
        return process
    # def stop_nginx(self):
    #     """
    #     Stop nginx
    #     @return:
    #     """
    #     current_dir = os.path.dirname(__file__).replace('XDER\public_utils', 'BrowCertExtractor\config_server')
    #     nginx_dir = os.path.join(current_dir, "nginx-1.23.1")
    #     cmd = ["nginx", "-s", "stop"]
    #     # Call subprocess, execute in cwd directory
    #     ret = subprocess.call(cmd, cwd=nginx_dir, shell=True)
    #     return ret
    def stop_nginx(self):
        """
        Stop Nginx service
        @return: command execution return code
        """
        import subprocess
        subprocess.call(
            ["taskkill", "/f", "/im", "nginx.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )
        return 0
def kill_process(process_name):
    """
    Kill a process
    @param process_name: Process name
    @return:
    """
    try:
        # Use taskkill command to terminate process
        subprocess.run(["taskkill", "/f", "/im", process_name], capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        pass

def verify_nginx(cert, key):
    """
    Test if nginx can run with current certificate configuration
    @param cert: Absolute path to certificate
    @param key: Absolute path to private key
    @return: Result (True/False)
    """
    # Configure nginx
    nginx_conf_file = '../BrowCertExtractor/config_server/nginx-1.23.1/conf/nginx.conf'
    op_nginx().config(nginx_conf_file, cert, key)
    # Try to start and stop server once
    try:
        op_nginx().run_nginx()
    except:
        pass
    mark = op_nginx().stop_nginx()
    # Check result: mark=0 means stopped successfully (started correctly), mark=1 means stop failed (not running)
    if mark == 1:
        return False
    elif mark == 0:
        kill_process('nginx.exe')
        return True

# cert = 'E:/work/my_project/AutoBrowCertDetailExtractor/mutat_cert/be55f7b91711120281[www.bing.der]/be55f7b91711120281[www.bing.der].crt'
# ca_cert = '../../mutat_cert/be55f7b91711120281[www.bing.der]/be55f7b91711120281[www.bing.der]CA.der'
# key = 'E:/work/my_project/AutoBrowCertDetailExtractor/XDER/MutateCerts/about_key/rsa_pri_2048.pem'
# a = broswer_nginx(cert, ca_cert, key)
# print(a)
# Conduct batch experiments to see if "invalid" is true