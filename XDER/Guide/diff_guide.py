import time
from BrowCertExtractor.config_server import config_server
from BrowCertExtractor.public_func.clear_cache import clear_cachedata, kill_process
from BrowCertExtractor.use_browsers.ex_sc_code import fire_errorcode
from BrowCertExtractor.use_browsers.ex_sc_code import edge_errorcode
from BrowCertExtractor.use_browsers.ex_sc_code import chrom_errorcode

def verify_guide(cert, ca_cert, key):
    """
    Start Nginx, use playwright to launch browsers, extract certificate verification results,
    extract certificate viewer content
    @param cert: Path of the certificate to be tested
    @param ca_cert: Path of the root CA certificate
    @param key: Path of the private key for the certificate to be tested
    @return: Verification results from Edge/Chrome/Firefox browsers
    """
    # Configure nginx
    nginx_conf_file = '../BrowCertExtractor/config_server/nginx-1.23.1/conf/nginx.conf'
    config_server.op_nginx().config(nginx_conf_file, cert, key)
    # Add CA using certutil
    config_server.certutil_certstore(ca_cert, 'add')
    time.sleep(0.2)
    # Automatically launch browsers
    config_server.op_nginx().run_nginx()  # Start Nginx
    # Test URL
    url = 'https://X-DER.test.com:443'
    # Call Firefox and extract verification result
    fire_secu = fire_errorcode(url)
    # Call Edge and extract verification result
    edge_secu = edge_errorcode(url)
    # Call Chrome and extract verification result
    chrom_secu = chrom_errorcode(url)
    # Delete CA using certutil
    config_server.certutil_certstore(ca_cert, 'del')
    # Stop Nginx
    config_server.op_nginx().stop_nginx()
    # Clear cache
    kill_process("msedge.exe")
    kill_process('nginx.exe')
    kill_process('Nightly.exe')
    clear_cachedata(r"C:\Users\fisher\AppData\Local\Mozilla\Firefox\Profiles")
    clear_cachedata(r"C:\Users\fisher\AppData\Local\Microsoft\Edge\User Data\Default\Cache")
    clear_cachedata(r"C:\Users\fisher\AppData\Local\Google\Chrome\User Data\Default\Cache")
    # Verification results from Edge/Chrome/Firefox browsers
    verify_list = [edge_secu[0], chrom_secu[0], fire_secu[0]]
    errorcode_list = [edge_secu[1], chrom_secu[1], fire_secu[1]]
    return verify_list, errorcode_list