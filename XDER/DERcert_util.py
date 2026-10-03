import copy, time
from random import choice
from XDER.MutateCerts.back_repair import fix_tlvlength
import XDER.MutateCerts.mutate_strategy
import XDER.ParseCerts.dump

import XDER.MutateCerts.locate_oid

import XDER.MutateCerts.prikey_createpukey
from XDER.ParseCerts.dump import ctree_tobin
from XDER.ParseCerts.parse_item import issuer_item
from XDER.ParseCerts.parse_item import subject_item
from XDER.ParseCerts.parse_item import sub_ex
from XDER.ParseCerts.parse_item import certPolicies_item
from XDER.ParseCerts.parse_item import SAN_item
from XDER.ParseCerts.parse_item import EKU_item
from XDER.ParseCerts.parse_item import aiasia_item
from XDER.public_utils.public_funcs import hex_to_bin_str_list
from XDER.public_utils.public_funcs import find_keyalgorithm
from XDER.public_utils.public_funcs import encode_oid
from XDER.public_utils.public_funcs import decode_oid
# add
from XDER.public_utils.public_funcs import get_folder_filenames
from XDER.public_utils.public_funcs import get_certname

import XDER.ParseCerts.get_file
import XDER.ParseCerts.dump

import XDER.SaveCerts.create_certfile
import XDER.public_utils.check_dercert_valid

from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput
from pycallgraph import Config
from pycallgraph import GlobbingFilter
import random
import os, traceback
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec


def parse(file, isprint):
    """
    Parse certificate into TLV tree
    @param file: Certificate path
    @param isprint: Set to 'print' to output 'Parse Success' message
    @return: Certificate TLV tree, forest form of TLV tree, certificate key information
    """
    # Get 8-bit binary string list data of certificate
    bin_list = XDER.ParseCerts.get_file.get_filebindata(file)
    # Convert 8-bit binary string list to tree structure
    cert_tree = XDER.ParseCerts.dump.dump(bin_list)
    # Extract each subtree from TLV tree and build certificate forest
    cert_forest = []
    XDER.ParseCerts.dump.solve_tree(cert_tree, cert_forest, None)
    # Get certificate public key information
    about_key = find_keyalgorithm(file)
    # Verify parsing correctness
    treelist_copy = copy.deepcopy(cert_tree)
    final_binary = ctree_tobin(treelist_copy)
    if final_binary == bin_list:
        if isprint == 'print':
            pp = "\('^o^')/ === " + "[Parse Success   " + "PublicKey:" + about_key[0] + '(' + str(
                about_key[1]) + "bits" + ')' + ' ' * 3 + "Leaf Node Count: " + str(
                len(list(filter(lambda x: x["isNode"], cert_forest)))) + ']'
            print('|' + ' ' * 5 + pp)
        else:
            # No print
            pass
    else:
        print(".·´¯(>▂<)¯´·. Parse Failed")
    return cert_tree, cert_forest, about_key


def structuralize(parse_result):
    """
    Structured and precise parsing
    @param parse_result: Parsing result from parse function
    @return: Certificate TLV tree, certificate forest, certificate dictionary structure, signature length
    """
    cert_tree = parse_result[0]
    cert_forest = parse_result[1]

    # Three certificate parts: tbs, signature algorithm, signature value
    root = cert_tree[0]
    tbs = root['children'][0]
    r_signAL = root['children'][1]
    sign_val = root['children'][2]
    # First part fields
    version = tbs['children'][0]
    serial_num = tbs['children'][1]
    tbs_signAL = tbs['children'][2]
    issuer = tbs['children'][3]
    validity = tbs['children'][4]
    subject = tbs['children'][5]
    pub_key = tbs['children'][6]
    # Collect items in fields for subsequent item name judgment
    issuer_details = issuer['children']
    validity_details = validity['children']
    subject_details = subject['children']

    # Classification
    root['type'] = 'T0-root'
    tbs['type'] = 'T1-tbs'
    r_signAL['type'] = 'T1-r_signAL'
    sign_val['type'] = 'T1-sign_val'
    version['type'] = 'T2-version'
    serial_num['type'] = 'T2-serial_num'
    tbs_signAL['type'] = 'T2-signAL'
    issuer['type'] = 'T2-issuer'
    validity['type'] = 'T2-validity'
    subject['type'] = 'T2-subject'
    pub_key['type'] = 'T2-pub_key'
    # Handle extensions separately since only v3 certificates have extensions
    if len(tbs['children']) == 8:
        extension = tbs['children'][7]
        extension_details = extension['children'][0]['children']
        extension['type'] = 'T2-extension'
    else:
        extension = []
        extension_details = []

    # Certificate dictionary structure
    cert_structure = {
        'T0-root': root,
        'T1-tbs': tbs,
        'T1-r_signAL': r_signAL,
        'T1-sign_val': sign_val,
        'T2-version': version,
        'T2-serial_num': serial_num,
        'T2-signAL': tbs_signAL,
        'T2-issuer': issuer,
        'T2-validity': validity,
        'T2-subject': subject,
        'T2-pub_key': pub_key,
    }
    if extension != []:
        cert_structure['T2-extension'] = extension

    # Process items in fields and extensions, add to certificate dictionary
    iss = 0
    for i in issuer_details:
        oid = decode_oid(i['children'][0]['children'][0]['node-value'])
        item_name = issuer_item(oid)
        i['type'] = 'issuer-' + item_name
        cert_structure[i['type']] = issuer_details[iss]
        iss += 1

    item = ''
    v = 0
    for i in validity_details:
        if v == 0:
            item = "notBefore"
        elif v == 1:
            item = 'notAfter'
        i['type'] = 'validity-' + item
        cert_structure[i['type']] = validity_details[v]
        v += 1

    s = 0
    for i in subject_details:
        oid = decode_oid(i['children'][0]['children'][0]['node-value'])
        item_name = subject_item(oid)
        i['type'] = 'subject-' + item_name
        cert_structure[i['type']] = subject_details[s]
        s += 1

    if extension_details != []:
        e = 0
        for i in extension_details:
            # Determine current sub-extension name
            oid = decode_oid(i['children'][0]['node-value'])
            item_name = sub_ex(oid)
            i['type'] = 'extension-' + item_name
            cert_structure[i['type']] = extension_details[e]
            # Determine item names in current sub-extension
            # 1 cert_policies
            if item_name == 'cert_policies':
                for o in i['children'][-1]['children'][0]['children']:
                    oid = decode_oid(o['children'][0]['node-value'])
                    cps_name = certPolicies_item(oid)
                    o['type'] = 'certPolicies-' + cps_name
                    cert_structure[o['type']] = o
            # 2 SAN/IAN
            if item_name == 'san' or item_name == 'ian':
                san_num = 0
                for o in i['children'][-1]['children'][0]['children']:
                    san_item = SAN_item(o)
                    o['type'] = item_name + '-' + san_item + str(san_num)
                    cert_structure[o['type']] = o
                    san_num += 1
            # 3 BC
            if item_name == 'basic_constraints':
                for o in i['children'][-1]['children'][0]['children']:
                    if o['type'] == 'boolean':
                        o['type'] = 'BC-CAMark'
                        cert_structure[o['type']] = o
                    if o['type'] == 'INTER':
                        o['type'] = 'BC-PathLengthConstraint'
                        cert_structure[o['type']] = o
            # 4 name_constraints
            if item_name == 'name_constraints':
                for o in i['children'][-1]['children'][0]['children']:
                    if o['tag'][0][-5:] == '00000':
                        o['type'] = 'NC-permitted'
                        cert_structure[o['type']] = o
                    if o['tag'][0][-5:] == '00001':
                        o['type'] = 'NC-excluded'
                        cert_structure[o['type']] = o
            # 5 policy_constraints
            if item_name == 'policy_constraints':
                for o in i['children'][-1]['children'][0]['children']:
                    if o['tag'][0][-5:] == '00000':
                        o['type'] = 'PC-requireExplicitPolicy'
                        cert_structure[o['type']] = o
                    if o['tag'][0][-5:] == '00001':
                        o['type'] = 'PC-inhibitPolicyMapping'
                        cert_structure[o['type']] = o
            # 6 EKU
            if item_name == 'eku':
                for o in i['children'][-1]['children'][0]['children']:
                    oid = decode_oid(o['node-value'])
                    EKU_name = EKU_item(oid)
                    o['type'] = 'EKU-' + EKU_name
                    cert_structure[o['type']] = o
            # 7 CRL
            if item_name == 'crldp':
                for o in i['children'][-1]['children'][0]['children'][0]['children']:
                    if o['tag'][0][-5:] == '00000':
                        o['type'] = 'CRL-distributionPoint'
                        cert_structure[o['type']] = o
                    if o['tag'][0][-5:] == '00001':
                        o['type'] = 'CRL-reasons'
                        cert_structure[o['type']] = o
                    if o['tag'][0][-5:] == '00010':
                        o['type'] = 'cRLIssuer'
                        cert_structure[o['type']] = o
            # 8 Freshest_CRL
            if item_name == 'Freshest_CRL':
                for o in i['children'][-1]['children'][0]['children'][0]['children']:
                    if o['tag'][0][-5:] == '00000':
                        o['type'] = 'FreshestCRL-distributionPoint'
                        cert_structure[o['type']] = o
            # 9 aia/sia
            if item_name == 'aia' or item_name == 'sia':
                for o in i['children'][-1]['children'][0]['children']:
                    oid = decode_oid(o['children'][0]['node-value'])
                    aiasia_name = aiasia_item(oid)
                    o['type'] = item_name + '-' + aiasia_name
                    cert_structure[o['type']] = o
            # 10 policy_mappings
            if item_name == 'policy_mappings':
                pm_num = 0
                for o in i['children'][-1]['children'][0]['children']:
                    o['type'] = 'policyMappings-' + str(pm_num)
                    cert_structure[o['type']] = o
                    pm_num += 1
            # Move to next sub-extension
            e += 1

    # Inject child-num identifier to record child count
    for i in parse_result[1]:
        num = str(len(i['children']))
        i.update({'child-num': num})
    # Calculate signature value length
    sign_val = cert_structure.get('T1-sign_val', {}).get('node-value')
    sign_len = len(sign_val) - 1

    return cert_tree, cert_forest, cert_structure, sign_len


def l_oid(cert_forest, OID):
    """
    Locate OID node in certificate forest
    @param cert_forest: Certificate forest
    @param OID: OID identifier, e.g., 2.3.4.5
    @return: Parent node ID of the OID node
    """
    oid = encode_oid(OID)
    # Location oid and draw
    filtered_nodes = list(filter(lambda x: x["isNode"], cert_forest))
    find_node, start, end = XDER.MutateCerts.locate_oid.find_oid_node(filtered_nodes, oid)
    # Get node_id of located OID
    OID_NODE_ID = find_node["node-id"]
    return find_node["p-node-id"]


def update_pubkeyANDsign(mode, struct_result, about_key, sign_len):
    """
    Update public key of mutated certificate and re-sign
    @param mode: None means only sign; not None means update public key and re-sign
    @param struct_result: Structured parsing result (from structuralize function)
    @param about_key: Public key information of mutated certificate
    @param sign_len: Length of signature value of mutated certificate
    @return: Path of preset CA certificate, private key of mutated certificate, length of signature value
    """
    # 0. Certificate dictionary structure, forest, TLV tree
    cert_structure = struct_result[2]
    cert_forest = struct_result[1]
    cert_tree = struct_result[0]

    # 1. Update public key
    prikey = ''
    if mode != None:
        # Generate new public key
        pub_key_hex, prikey = XDER.MutateCerts.prikey_createpukey.prikey_topublic(about_key[0], about_key[1])
        pub_key_bin = hex_to_bin_str_list(pub_key_hex)
        # Get original public key information
        lenn1 = copy.deepcopy(cert_structure['T2-pub_key']['length'])
        keyalgorithm_node_P = cert_structure['T2-pub_key']["p-node-id"]
        keyalgorithm_node_type = cert_structure['T2-pub_key']["type"]
        # Tree processing for new public key
        new_pklist = []
        new_pktree = XDER.ParseCerts.dump.dump(pub_key_bin)
        new_pktree[0]["p-node-id"] = keyalgorithm_node_P
        new_pktree[0]["type"] = keyalgorithm_node_type
        XDER.ParseCerts.dump.solve_tree(new_pktree, new_pklist, None)
        # Replace old public key with new one
        cert_structure['T2-pub_key']['node-id'] = new_pktree[0]["node-id"]
        cert_structure['T2-pub_key']['children'] = new_pktree[0]['children']
        lenn2 = copy.deepcopy(new_pklist[0]['length'])
        if lenn2 - lenn1 != 0:
            fix_tlvlength(struct_result[1], cert_structure['T2-pub_key']['node-id'], lenn2 - lenn1)

    # 2. Generate new signature
    # Extract tbs field data
    tbs_node = []
    tbs_node.append(cert_structure['T1-tbs'])
    tbs_bin = ctree_tobin(tbs_node)
    tbs_hex = XDER.SaveCerts.create_certfile.bin_toHex('', tbs_bin)
    tbs_byte = bytes.fromhex(tbs_hex)

    # Select private key (hash algorithm + key type must match signature algorithm)
    signature = ''
    path = ''
    signature_algorithm = about_key[2]
    # Hash algorithm sha256
    if 'sha256' in signature_algorithm:
        prikey_type = signature_algorithm.replace('sha256', '')
        if prikey_type == 'RSA':
            sign_len = str(sign_len * 8)
        elif prikey_type == 'ECDSA':
            sign_len = str(int(((sign_len - 2)) / 2 - 2) * 8)
            if (int(sign_len) / 8) % 2 == 1:
                sign_len = str(int(sign_len) - 8)
        path = "./ca_suite/" + prikey_type + sign_len + "/ca_key.pem"
        # Load private key
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        if prikey_type == 'RSA':
            signature = private_key.sign(tbs_byte, padding.PKCS1v15(), hashes.SHA256())
        elif prikey_type == 'ECDSA':
            signature = private_key.sign(tbs_byte, ec.ECDSA(hashes.SHA256()))
    # Hash algorithm sha384
    elif 'sha384' in signature_algorithm:
        prikey_type = signature_algorithm.replace('sha384', '')
        if prikey_type == 'RSA':
            sign_len = str(sign_len * 8)
        elif prikey_type == 'ECDSA':
            sign_len = str(int(((sign_len - 2)) / 2 - 2) * 8)
            if (int(sign_len) / 8) % 2 == 1:
                sign_len = str(int(sign_len) - 8)
        path = "./ca_suite/" + prikey_type + sign_len + "/ca_key.pem"
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        if prikey_type == 'RSA':
            signature = private_key.sign(tbs_byte, padding.PKCS1v15(), hashes.SHA384())
        elif prikey_type == 'ECDSA':
            signature = private_key.sign(tbs_byte, ec.ECDSA(hashes.SHA384()))
    # Hash algorithm sha512
    elif 'sha512' in signature_algorithm:
        prikey_type = signature_algorithm.replace('sha512', '')
        if prikey_type == 'RSA':
            sign_len = str(sign_len * 8)
        elif prikey_type == 'ECDSA':
            sign_len = str(int(((sign_len - 2)) / 2 - 2) * 8)
            if (int(sign_len) / 8) % 2 == 1:
                sign_len = str(int(sign_len) - 8)
        path = "./ca_suite/" + prikey_type + sign_len + "/ca_key.pem"
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        if prikey_type == 'RSA':
            signature = private_key.sign(tbs_byte, padding.PKCS1v15(), hashes.SHA512())
        elif prikey_type == 'ECDSA':
            signature = private_key.sign(tbs_byte, ec.ECDSA(hashes.SHA512()))
    # Hash algorithm sha1
    elif 'sha1' in signature_algorithm:
        prikey_type = signature_algorithm.replace('sha1', '')
        if prikey_type == 'RSA':
            sign_len = str(sign_len * 8)
        elif prikey_type == 'ECDSA':
            sign_len = str(int(((sign_len - 2)) / 2 - 2) * 8)
            if (int(sign_len) / 8) % 2 == 1:
                sign_len = str(int(sign_len) - 8)
        path = "./ca_suite/" + prikey_type + sign_len + "/ca_key.pem"
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        if prikey_type == 'RSA':
            signature = private_key.sign(tbs_byte, padding.PKCS1v15(), hashes.SHA1())
        elif prikey_type == 'ECDSA':
            signature = private_key.sign(tbs_byte, ec.ECDSA(hashes.SHA1()))
    # Hash algorithm md5
    elif 'md5' in signature_algorithm:
        prikey_type = signature_algorithm.replace('md5', '')
        path = "./ca_suite/" + prikey_type + sign_len + "/ca_key.pem"
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        if prikey_type == 'RSA':
            signature = private_key.sign(tbs_byte, padding.PKCS1v15(), hashes.MD5())
        elif prikey_type == 'ECDSA':
            signature = private_key.sign(tbs_byte, ec.ECDSA(hashes.MD5()))

    # 3. Process new signature value into 8-bit binary string list and update certificate signature field
    bin = hex_to_bin_str_list(signature.hex())
    signature_bin = ['00000000']
    signature_bin = signature_bin + bin
    lenn3 = len(cert_structure['T1-sign_val']['node-value'])
    lenn4 = len(signature_bin)
    cert_structure['T1-sign_val']['node-value'] = signature_bin
    if lenn4 - lenn3 != 0:
        fix_tlvlength(struct_result[1], cert_structure['T1-sign_val']['node-id'], lenn4 - lenn3)

    # 4. CA certificate path
    ca_path = path.replace('ca_key.pem', "ca.der")

    return ca_path, prikey, sign_len


def save_leaf(struct_result, sign_len, about_key, name):
    """
    Save mutated certificate
    @param struct_result: Structured parsing result (from structuralize function)
    @param sign_len: Length of signature value of mutated certificate
    @param about_key: Certificate key information
    @param name: Seed certificate filename
    @return: Mutated certificate name, preset CA path, private key path, signature length
    """
    cert_tree = struct_result[0]
    # Print: Mutation completed
    print('|' + ' ' * 5 + "(1.Mutation)")
    # Update public key and re-sign
    ca_path, prikey, sign_len = update_pubkeyANDsign(1, struct_result, about_key, sign_len)
    # Print: Public key and signature updated
    final_binlist = ctree_tobin(cert_tree)
    final_hex = XDER.SaveCerts.create_certfile.bin_toHex('', final_binlist)
    print('|' + ' ' * 5 + "(2.Update PublicKey & Re-sign)")
    # Save certificate
    new_name = '[' + name + ']' + uuid.uuid4().hex[:8] + str(int(time.time()))
    MUTAT_DIR = os.environ.get('XDER_MUTAT_DIR', 'mutat_cert')
    path = '../' + MUTAT_DIR + '/' + new_name
    if not os.path.exists(path):
        os.makedirs(path)
    floder = path + '/' + new_name + '.der'
    floder_ = path + '/' + new_name + '.crt'
    der_bytes = XDER.SaveCerts.create_certfile.hex_toDER(final_hex, floder)
    XDER.SaveCerts.create_certfile.der_to_pem(der_bytes, floder_)
    # Print: Save success
    print('|' + ' ' * 5 + "Create leaf cert succeed")
    return new_name, ca_path, prikey, sign_len


def leaf_toca(structuralize_leaf, message):
    """
    Generate CA based on mutated certificate
    @param structuralize_leaf: Structured parsing result of mutated certificate
    @param message: Return value from save_leaf function
    @return:
    """
    # Select preset CA and private key
    casuite_path = message[1]
    # Parse CA
    parse_result = parse(casuite_path, "no")
    about_key = parse_result[2]
    ca_structresult = structuralize(parse_result)
    sign_len = ca_structresult[3]
    # Establish name connection between CA and mutated certificate
    XDER.MutateCerts.mutate_strategy.tamper_withca(ca_structresult[1], structuralize_leaf['T2-issuer'],
                                                   ca_structresult[2]['T2-subject'])
    XDER.MutateCerts.mutate_strategy.tamper_withca(ca_structresult[1], structuralize_leaf['T2-issuer'],
                                                   ca_structresult[2]['T2-issuer'])
    # Self-sign, no public key update
    update_pubkeyANDsign(None, ca_structresult, about_key, sign_len)

    # Save CA certificate (2-length certificate chain created)
    def save_ca(format, result_copy, name):
        result = copy.deepcopy(result_copy)
        temp_bin = ctree_tobin(result)
        temp_hex = XDER.SaveCerts.create_certfile.bin_toHex('', temp_bin)
        floder_pem = ''
        if format == 'pem':
            MUTAT_DIR = os.environ.get('XDER_MUTAT_DIR', 'mutat_cert')
            floder_pem = '../' + MUTAT_DIR + '/' + name + '/' + name + 'CA' + '.crt'
            floder_der = '../' + MUTAT_DIR + '/' + name + '/' + name + 'CA' + '.der'
            der_bytes = XDER.SaveCerts.create_certfile.CAhex_toDER(temp_hex, floder_der)
            XDER.SaveCerts.create_certfile.CAder_to_pem(der_bytes, floder_pem)
        print('|' + ' ' * 5 + "Create CA cert succeed")
        return floder_pem

    save_ca('pem', ca_structresult[0], message[0])