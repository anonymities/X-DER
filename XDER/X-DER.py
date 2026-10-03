import copy, os, subprocess
from XDER.DERcert_util import leaf_toca
from XDER.public_utils.public_funcs import get_folder_filenames
from XDER.public_utils.public_funcs import get_certname
import XDER.DERcert_util
import MutateCerts.mutate_strategy
import MutateCerts.back_repair
from XDER.ParseCerts.dump import solve_tree
import random, traceback
from XDER.public_utils.public_funcs import generate_random_str
from XDER.public_utils.public_funcs import find_nodeID
from XDER.public_utils.public_funcs import get_all_node_ids
from XDER.public_utils.remove_floder import remove_folder
from XDER.public_utils.check_dercert_valid import verify_nginx
from XDER.Guide.diff_guide import verify_guide
from XDER.Guide.code_guide import reCode_fire, reCode_chrome_edge
from XDER.Guide.feedback_guide import FeedbackGuide
from datetime import datetime

import sys, os
sys.tracebacklimit = 0



MUTAT_DIR = 'mutat_cert'   # overridden by main at runtime
SUFFIX = ''                # overridden by main at runtime

def kong(a,b,c):
    """
    No mutation
    @param a: dummy parameter
    @param b: dummy parameter
    @param c: dummy parameter
    @return:
    """
    pass

def add(cert_forest, node_added, num):
    """
    Add leaf node value
    :param num: add num bytes to current leaf node value
    :param cert_forest: certificate forest
    :param node_added: mutated leaf node
    :return:
    """
    j = 0
    while j < num:
        binary_str = generate_random_str()
        position = random.randint(0, len(node_added["node-value"]))
        MutateCerts.mutate_strategy.add(cert_forest, node_added, position, binary_str)
        j += 1
    return 1

def change_value(cert_forest, node_changed, num):
    """
    Modify leaf node value, non-TLV mode of change_value
    :param num: modify value of current leaf node num times
    :param cert_forest: certificate forest
    :param node_changed: mutated leaf node
    :return:
    """
    i = 0
    while i < num:
        binary_str = generate_random_str()
        if len(node_changed["node-value"]) != 0:
            position = random.randint(0, len(node_changed["node-value"]) - 1)
        else:
            position = 0
        MutateCerts.mutate_strategy.change_value(cert_forest, node_changed, position, binary_str, '')
        i += 1
    return 1

def dele(cert_forest, node_deled, num):
    """
    Delete leaf node value
    :param num: delete num bytes from value of current leaf node
    :param cert_forest: certificate forest
    :param node_deled: mutated leaf node
    :return:
    """
    j = 0
    while j < num:
        if node_deled["node-value"] != []:
            position = random.randint(0, len(node_deled["node-value"]) - 1)
            MutateCerts.mutate_strategy.delete(cert_forest, node_deled, position)
            j += 1
        else:
            j += 1
            if j + 1 == num:
                add(cert_forest, node_deled, num)

def del_leaf(cert_forest, _leafnode_deled, _node_position):
    """
    Delete leaf node
    @param cert_forest: certificate forest
    @param _leafnode_deled: leaf node to be deleted
    @param _node_position: position of deleted leaf node
    @return:
    """
    MutateCerts.mutate_strategy.delete_leaf(cert_forest, _leafnode_deled, _node_position)

def del_inner(cert_forest, _innernode_deled, _position):
    """
    Delete inner node
    @param cert_forest: certificate forest
    @param _innernode_deled: inner node to be deleted
    @param _position: position of deleted inner node
    @return:
    """
    MutateCerts.mutate_strategy.delete_innernode(cert_forest, _innernode_deled, _position)

def addleaf_toinner(cert_forest, _innernode_added, out_leafnode, position):
    """
    Add leaf node to inner node
    @param cert_forest: certificate forest
    @param _innernode_added: inner node to add new node
    @param out_leafnode: new leaf node
    @param position: add position
    @return:
    """
    addded_postion = MutateCerts.mutate_strategy.addleaf_toinner(cert_forest, _innernode_added, out_leafnode, position)
    return addded_postion

def addinner_toinner(cert_forest, _innernode_added, out_innernode, position):
    """
    Add inner node to inner node
    @param cert_forest: certificate forest
    @param _innernode_added: inner node to add new node
    @param out_innernode: new inner node
    @param position: add position
    @return:
    """
    addded_postion = MutateCerts.mutate_strategy.addinner_toinner(cert_forest, _innernode_added, out_innernode,
                                                                  position)
    return addded_postion

def replace_node(cert_forest, _node_replaced, out_node, _node_position):
    """
    Replace node
    @param cert_forest: certificate forest
    @param _node_replaced: node to be replaced
    @param out_node: new replacement node
    @param _node_position: replace position
    @return:
    """
    MutateCerts.mutate_strategy.replace_node(cert_forest, _node_replaced, out_node, _node_position)

def change_tag(cert_forest, _node, mode):
    """
    Tag mutation
    @param cert_forest: certificate forest
    @param _node: mutated node
    @param mode: mode=change for mutation
    @return:
    """
    MutateCerts.mutate_strategy.change_tag(cert_forest, _node, mode)

def change_length(cert_forest, _node):
    """
    Length mutation
    @param cert_forest: certificate forest
    @param _node: mutated node
    @return:
    """
    MutateCerts.mutate_strategy.lengthMut(cert_forest, _node)

def repalce_value(cert_forest, node_changed, num):
    """
    Modify leaf node value, TLV mode of change_value
    @param cert_forest: certificate forest
    @param node_changed: mutated leaf node
    @param num: placeholder to prevent code errors
    @return:
    """
    MutateCerts.mutate_strategy.change_value(cert_forest, node_changed, num, '', 'TLV')
    return 1

def creat_node():
    """
    Create a node
    @return:
    """
    # Select from library
    store = "der"
    certname_txt = get_folder_filenames("../../" + store + "/")
    certname_list = get_certname(certname_txt[0])
    certname = random.choice(certname_list)
    path = "../../" + store + "/" + certname
    # Parse selected certificate
    cert_tree, cert_forest, about_key = XDER.DERcert_util.parse(path, 'no')
    the_node = random.choice(cert_forest)
    node_ids = copy.deepcopy(get_all_node_ids(the_node, 1))
    nodeids_layer = copy.deepcopy([list(node_ids)[i] for i in range(len(list(node_ids)) - 1, -1, -1)])
    # Mutate parsed node
    randsmap_nodeidslayer = random.sample(nodeids_layer, random.randint(1, len(nodeids_layer)))
    randsmap_nodeidslayer.sort(reverse=True)
    # Select random mutation stop layer
    the_layer = randsmap_nodeidslayer.index(random.choice(randsmap_nodeidslayer))
    for i in randsmap_nodeidslayer:
        if randsmap_nodeidslayer.index(i) > the_layer:
            break
        for id in random.sample(node_ids[i], random.randint(1, len(node_ids[i]))):
            node_finded = find_nodeID(cert_forest, id)
            # Do not mutate root node
            if i == 1 and node_finded['isNode'] is False:
                continue
            p_nodefinded = find_nodeID(cert_forest, node_finded['p-node-id'])
            # Mutate leaf node
            if node_finded['isNode'] == True:
                _node_position = p_nodefinded['children'].index(node_finded)
                try:
                    byte_num = random.randint(1, len(node_finded['node-value']))
                    if len(node_finded['node-value']) == 1:
                        byte_num = random.randint(1, 3)
                except:
                    byte_num = random.randint(1, 10)
                mutat_func = [(kong, (cert_forest, node_finded, byte_num)),
                              (add, (cert_forest, node_finded, byte_num)),
                              (repalce_value, (cert_forest, node_finded, byte_num)),
                              (change_value, (cert_forest, node_finded, byte_num)),
                              (dele, (cert_forest, node_finded, byte_num)),
                              (del_leaf, (cert_forest, node_finded, _node_position)),
                              (change_tag, (cert_forest, node_finded, 'change'))]
                random_func, random_arg = random.choice(mutat_func)
                random_func(*random_arg)
                cert_forest = []
                solve_tree(cert_tree, cert_forest, None)
            # Mutate inner node
            elif node_finded['isNode'] == False:
                _node_position = p_nodefinded['children'].index(node_finded)
                mutat_func = [(del_inner, (cert_forest, node_finded, _node_position)),
                              (kong, (cert_forest, node_finded, 1)),
                              (change_tag, (cert_forest, node_finded, 'change'))]
                random_func, random_arg = random.choice(mutat_func)
                random_func(*random_arg)
                cert_forest = []
                solve_tree(cert_tree, cert_forest, None)
    return the_node

# Do NOT delete following variables, used as global variables in object
nginxerror_num = 0
succeed = 0
mut_op = {}
names_mutateweight = {
    'T1-r_signAL': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'T2-version': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'T2-serial_num': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'T2-signAL': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'T2-issuer': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'T2-validity': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'T2-subject': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-akid': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-skid': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-key_usage': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-cert_policies': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-san': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-basic_constraints': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-name_constraints': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-policy_constraints': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-eku': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-crldp': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-inhibit_any': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-Freshest_CRL': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-aia': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-sia': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
    'extension-policy_mappings': [{add: 1, repalce_value: 1, change_value: 1, dele: 1,
                 del_leaf: 1, replace_node: 1, change_tag: 1, change_length: 1},
                   {del_inner: 1, replace_node: 1, addinner_toinner: 1, change_tag: 1, change_length: 1}],
}
returncode_dir = {
    'T1-r_signAL': [],
    'T2-version': [],
    'T2-serial_num': [],
    'T2-signAL': [],
    'T2-issuer': [],
    'T2-validity': [],
    'T2-subject': [],
    'extension-akid': [],
    'extension-skid': [],
    'extension-key_usage': [],
    'extension-cert_policies': [],
    'extension-san': [],
    'extension-basic_constraints': [],
    'extension-name_constraints': [],
    'extension-policy_constraints': [],
    'extension-eku': [],
    'extension-crldp': [],
    'extension-inhibit_any': [],
    'extension-Freshest_CRL': [],
    'extension-aia': [],
    'extension-sia': [],
    'extension-policy_mappings': [],
}

class MutChamber:
    def __init__(self, name, path):
        """
        Print "Mutation Start"
        @param name: name of certificate to mutate
        @param path: path of certificate to mutate
        """
        self.name = name
        self.path = path
        pp = "┏( >_<)┛ >>> Enter MutChamber"
        print('|' + ' ' * 5 + pp)

    def self_define(self, struct_result, about_key, name, field, mode='feedback', user_target=None, user_strategy=None):
        """
        Specify a field/extension in certificate to mutate
        @param struct_result: structured certificate parsing result
        @param about_key: key information of mutated certificate
        @param name: name of mutated certificate
        @param field: specified field/extension, e.g., "T2-issuer"
        @return:
        """
        global nginxerror_num
        global succeed
        global mut_op
        global names_mutateweight
        global returncode_dir
        returncode_list = returncode_dir[field]
        feedback_guide = FeedbackGuide()  # initialize feedback guide
        if mode == 'user':
            feedback_guide = None
        leaf_mutateOP = names_mutateweight[field][0]
        inner_mutateOP = names_mutateweight[field][1]
        cert_tree, cert_forest, cert_structure, sign_len = struct_result
        node_ids = copy.deepcopy(get_all_node_ids(cert_structure[field], 1))
        nodeids_layer = copy.deepcopy([list(node_ids)[i] for i in range(len(list(node_ids)) - 1, -1, -1)])
        rand_nodelayers = random.sample(nodeids_layer, random.randint(1, len(nodeids_layer)))
        rand_nodelayers.sort(reverse=True)
        for i in rand_nodelayers:
            nodeid_sample = random.sample(node_ids[i], random.randint(1, len(node_ids[i])))
            k = 0
            while k <= len(nodeid_sample) - 1:
                id = nodeid_sample[k]
                node_finded = find_nodeID(cert_forest, id)
                p_nodefinded = find_nodeID(cert_forest, node_finded['p-node-id'])
                if node_finded['isNode'] == True:
                    is_node = creat_node()
                    try:
                        byte_num = random.randint(1, len(node_finded['node-value']))
                        if len(node_finded['node-value']) == 1:
                            byte_num = random.randint(1, 3)
                    except:
                        byte_num = random.randint(1, 10)
                    node_findedcopy = copy.deepcopy(node_finded)
                    _node_position = p_nodefinded['children'].index(node_finded)
                    mutat_func = {add: (cert_forest, node_finded, byte_num),
                                  repalce_value: (cert_forest, node_finded, byte_num),
                                  change_value: (cert_forest, node_finded, byte_num),
                                  dele: (cert_forest, node_finded, byte_num),
                                  del_leaf: (cert_forest, node_finded, _node_position),
                                  replace_node: (cert_forest, node_finded, is_node, _node_position),
                                  change_tag: (cert_forest, node_finded, 'change'),
                                  change_length: (cert_forest, node_finded)}
                    if mode == 'user':
                        # per the paper: specify target and strategy directly
                        # user_target and user_strategy are passed in from outside
                        if user_target is None or user_strategy is None:
                            # if not provided, default to the first operation
                            op = list(mutat_func.keys())[0]
                        else:
                            # find the function object by name
                            op = None
                            for f in mutat_func.keys():
                                if f.__name__ == user_strategy:
                                    op = f
                                    break
                            if op is None:
                                op = list(mutat_func.keys())[0]
                        random_func, random_arg = (op, mutat_func[op])
                    else:
                        op = feedback_guide.weighted_choice(mutat_func)
                        random_func, random_arg = (op, mutat_func[op])
                    random_func(*random_arg)
                    func_name = random_func.__name__
                    message = XDER.DERcert_util.save_leaf(struct_result, sign_len, about_key, name)
                    leaf_toca(struct_result[2], message)
                    current_dir = os.path.dirname(os.path.abspath(__file__)).replace('\XDER', '').replace('\\','/')
                    command = ["certutil", "-asn", current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + '.der']
                    completed_process = subprocess.run(command, check=False, stdout=subprocess.PIPE,stderr=subprocess.PIPE, text=True)
                    if 'Decode Error!' in completed_process.stdout:
                        XDER.DERcert_util.save_leaf(struct_result, sign_len, about_key, func_name)
                    verify_result = verify_nginx(
                        current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + '.crt',
                        current_dir + '/XDER/MutateCerts/about_key/' + message[2])
                    if verify_result == True:
                        cert_forest = []
                        solve_tree(cert_tree, cert_forest, None)
                        k += 1
                        nginxerror_num = 0
                        succeed += 1
                        if func_name in mut_op:
                            mut_op[func_name] = mut_op[func_name] + 1
                        else:
                            mut_op[func_name] = 1
                        print('|' + ' ' * 5 + str(mut_op))
                        re_verify, re_errorcode = verify_guide(current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + '.crt',
                                     current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + 'CA.der',
                                     current_dir + '/XDER/MutateCerts/about_key/' + message[2]
                                     )
                        if (re_verify[0] == re_verify[1] == re_verify[2]) != 1:
                            returncode_str = reCode_chrome_edge(re_errorcode[0]) + ' '\
                                              + reCode_chrome_edge(re_errorcode[1]) + ' ' + reCode_fire(re_errorcode[2])
                            if returncode_str not in returncode_list:
                                if mode == 'feedback':
                                    feedback_guide.update(op.__name__, True)
                                    print(
                                        f'|{" " * 5}Increase weight: {op.__name__} -> {feedback_guide.weights[op.__name__]}')
                                returncode_list.append(returncode_str)
                        print('|' + ' ' * 5 + '=======================')
                    else:
                        if func_name == 'del_leaf':
                            MutateCerts.back_repair.back_node(cert_forest, p_nodefinded,
                                                              node_findedcopy, _node_position, 'insert')
                        if func_name == 'replace_node' or func_name == 'add' or func_name == 'change_value' \
                           or func_name == 'dele' or func_name == 'change_tag' or func_name == 'repalce_value':
                            MutateCerts.back_repair.back_node(cert_forest, p_nodefinded,
                                                              node_findedcopy, _node_position, 'replace')
                        if func_name == 'change_length':
                            MutateCerts.back_repair.back_node(cert_forest, p_nodefinded,
                                                              node_findedcopy, _node_position, 'len')
                        remove_folder(current_dir + '/' + MUTAT_DIR + '/' + message[0])
                        cert_forest = []
                        solve_tree(cert_tree, cert_forest, None)
                        nginxerror_num += 1
                        print('|' + ' ' * 5 + '=======================')
                elif node_finded['isNode'] == False:
                    is_node = creat_node()
                    node_findedcopy = copy.deepcopy(node_finded)
                    _node_position = p_nodefinded['children'].index(node_finded)
                    mutat_func = {del_inner: (cert_forest, node_finded, _node_position),
                                  replace_node: (cert_forest, node_finded, is_node, _node_position),
                                  addinner_toinner: (cert_forest, node_finded, is_node, None),
                                  change_tag: (cert_forest, node_finded, 'change'),
                                  change_length: (cert_forest, node_finded)}
                    if mode == 'user':
                        # per the paper: specify target and strategy directly
                        # user_target and user_strategy are passed in from outside
                        if user_target is None or user_strategy is None:
                            # if not provided, default to the first operation
                            op = list(mutat_func.keys())[0]
                        else:
                            # find the function object by name
                            op = None
                            for f in mutat_func.keys():
                                if f.__name__ == user_strategy:
                                    op = f
                                    break
                            if op is None:
                                op = list(mutat_func.keys())[0]
                        random_func, random_arg = (op, mutat_func[op])
                    else:
                        op = feedback_guide.weighted_choice(mutat_func)
                        random_func, random_arg = (op, mutat_func[op])
                    addded_postion = random_func(*random_arg)
                    func_name = random_func.__name__
                    message = XDER.DERcert_util.save_leaf(struct_result, sign_len, about_key, name)
                    leaf_toca(struct_result[2], message)
                    current_dir = os.path.dirname(os.path.abspath(__file__)).replace('\XDER', '').replace('\\','/')
                    command = ["certutil", "-asn", current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + '.der']
                    completed_process = subprocess.run(command, check=False, stdout=subprocess.PIPE,stderr=subprocess.PIPE, text=True)
                    if 'Decode Error!' in completed_process.stdout:
                        XDER.DERcert_util.save_leaf(struct_result, sign_len, about_key, func_name)
                    verify_result = verify_nginx(
                        current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + '.crt',
                        current_dir + '/XDER/MutateCerts/about_key/' + message[2])
                    if verify_result == True:
                        cert_forest = []
                        solve_tree(cert_tree, cert_forest, None)
                        k += 1
                        nginxerror_num = 0
                        succeed += 1
                        if func_name in mut_op:
                            mut_op[func_name] = mut_op[func_name] + 1
                        else:
                            mut_op[func_name] = 1
                        print('|' + ' ' * 5 + str(mut_op))
                        re_verify, re_errorcode = verify_guide(current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + '.crt',
                                     current_dir + '/' + MUTAT_DIR + '/' + message[0] + '/' + message[0] + 'CA.der',
                                     current_dir + '/XDER/MutateCerts/about_key/' + message[2]
                                     )
                        if (re_verify[0] == re_verify[1] == re_verify[2]) != 1:
                            returncode_str = reCode_chrome_edge(re_errorcode[0]) + ' '\
                                              + reCode_chrome_edge(re_errorcode[1]) + ' ' + reCode_fire(re_errorcode[2])
                            if returncode_str not in returncode_list:
                                if mode == 'feedback':
                                    feedback_guide.update(op.__name__, True)
                                    print(
                                        f'|{" " * 5}Increase weight: {op.__name__} -> {feedback_guide.weights[op.__name__]}')
                                returncode_list.append(returncode_str)
                        print('|' + ' ' * 5 + '=======================')
                    else:
                        if func_name == 'del_inner':
                            MutateCerts.back_repair.back_node(cert_forest, p_nodefinded,
                                                              node_findedcopy, _node_position, 'insert')
                        if func_name == 'replace_node' or func_name == 'change_tag' or func_name == 'add' :
                            MutateCerts.back_repair.back_node(cert_forest, p_nodefinded,
                                                              node_findedcopy, _node_position, 'replace')
                        if func_name == 'addleaf_toinner' or func_name == 'addinner_toinner':
                            MutateCerts.back_repair.back_node(cert_forest, node_finded, is_node, addded_postion, 'del')
                        if func_name == 'change_length':
                            MutateCerts.back_repair.back_node(cert_forest, p_nodefinded,
                                                              node_findedcopy, _node_position, 'len')
                        remove_folder(current_dir + '/' + MUTAT_DIR + '/' + message[0])
                        cert_forest = []
                        solve_tree(cert_tree, cert_forest, None)
                        nginxerror_num += 1
                        print('|' + ' ' * 5 + '=======================')
                if nginxerror_num == 50:
                    k += 1
                    nginxerror_num = 0
                    continue
        struct_result[1] = cert_forest

    def add_ypjsan(self, struct_result):
        """
        Add DNSname = X-DER.test.com entry to SAN
        @param struct_result: structured certificate parsing result
        @return:
        """
        cert_tree, cert_forest, cert_structure, sign_len = struct_result
        try:
            san_nodeid = XDER.DERcert_util.l_oid(cert_forest, '2.5.29.17')
            san_node = find_nodeID(cert_forest, san_nodeid)

            node_value = ['01011000', '00101101', '01000100', '01000101', '01010010', '00101110',
                          '01110100', '01100101', '01110011', '01110100', '00101110', '01100011',
                          '01101111', '01101101']

            ypj_node = {
                "node-id": 'yuziqiao-2309-2119-9812-090617ypj',
                "type": None,
                "tag": ['10000010'],
                "tag-len": 1,
                "p-node-id": '53b3a437-9102-4ca8-8774-638915584801',
                "length": 14,
                "isNode": True,
                "children": [],
                "hex_value": '58 2D 44 45 52 2E 74 65 73 74 2E 63 6F 6D',
                "node-value": node_value,
                "value": "T:10000010  |  L:00001110  |  V:['01011000','00101101','01000100','01000101','01010010','00101110','01110100','01100101','01110011','01110100','00101110','01100011','01101111','01101101']",
                "child-num": '0'
            }
            MutateCerts.mutate_strategy.addleaf_toinner(cert_forest,
                                                        cert_structure[san_node["type"]]['children'][-1]['children'][0],
                                                        ypj_node, 0)
        except:
            san_ex = {'node-id': 'b47bb4de-9d37-413a-a757-99c6eea81116',
                      'type': 'extension-san',
                      'tag': ['00110000'],
                      'tag-len': 1,
                      'p-node-id': 'a7a71ae3-f291-45c3-84e4-9a86deaad030',
                      'length': 25,
                      'isNode': False,
                      'children': [
                          {'node-id': '22278bb3-2c63-4ae9-b520-517c67e1a16a',
                           'type': 'OBJECT IDENTIFIER',
                           'tag': ['00000110'],
                           'tag-len': 1,
                           'p-node-id': 'b47bb4de-9d37-413a-a757-99c6eea81116',
                           'length': 3,
                           'isNode': True,
                           'children': [],
                           'hex_value': '55 1d 11',
                           'node-value': ['01010101', '00011101', '00010001'],
                           'value': "T:00000110  |  L:00000011  |  V:['01010101','00011101','00010001']",
                           'child-num': '0'},
                          {'node-id': '38c5ec1f-cea2-42cc-b9aa-f76247ac6a4a',
                           'tag': ['00000100'],
                           'tag-len': 1,
                           'p-node-id': 'b47bb4de-9d37-413a-a757-99c6eea81116',
                           'length': 18,
                           'isNode': False,
                           'children': [
                               {'node-id': '15c876ec-0701-479a-a2cb-147bfae381e7',
                                'type': 'SEQUENCE',
                                'tag': ['00110000'],
                                'tag-len': 1,
                                'p-node-id': '38c5ec1f-cea2-42cc-b9aa-f76247ac6a4a',
                                'length': 16,
                                'isNode': False,
                                'children': [
                                    {'node-id': '77827739-d4f6-42b5-ae1e-8d8b44bdf9c7',
                                     'type': 'san-dNSName0',
                                     'tag': ['10000010'],
                                     'tag-len': 1,
                                     'p-node-id': '15c876ec-0701-479a-a2cb-147bfae381e7',
                                     'length': 14,
                                     'isNode': True,
                                     'children': [],
                                     'hex_value': '58 2D 44 45 52 2E 74 65 73 74 2E 63 6F 6D',
                                     'node-value': ['01011000', '00101101', '01000100', '01000101', '01010010',
                                                    '00101110', '01110100', '01100101', '01110011', '01110100',
                                                    '00101110', '01100011', '01101111', '01101101'],
                                     'value': "T:10000010  |  L:00001110  |  V:['01011000','00101101','01000100','01000101','01010010','00101110','01110100','01100101','01110011','01110100','00101110','01100011','01101111','01101101']",
                                     'child-num': '0'}],
                                'hex_value': 'invisible',
                                'node-value': [],
                                'value': 'T:00110000  |  L:00010000  |  V:ALL subtree of current node',
                                'child-num': '1'}],
                           'hex_value': 'invisible',
                           'node-value': [],
                           'value': 'T:00000100  |  L:00010010  |  V:ALL subtree of current node',
                           'child-num': '1'}],
                      'hex_value': 'invisible',
                      'node-value': [],
                      'value': 'T:00110000  |  L:00011001  |  V:ALL subtree of current node',
                      'child-num': '2'}
            MutateCerts.mutate_strategy.addinner_toinner(cert_forest,
                                                         cert_structure['T2-extension']['children'][0], san_ex, 0)
        cert_forest = []
        solve_tree(cert_tree, cert_forest, None)
        struct_result[1] = cert_forest
def run_mutchamber(path, mode='feedback', user_target=None, user_strategy=None):
    """
    Mutate a specified certificate
    @param path: path of certificate to mutate (e.g., C:\fisher\Desktop\www.wosign.com.der)
    @return:
    """
    cert_structure = ['T1-r_signAL', 'T2-version', 'T2-serial_num', 'T2-signAL', 'T2-issuer', 'T2-validity', 'T2-subject',
        'extension-akid', 'extension-skid', 'extension-key_usage', 'extension-cert_policies', 'extension-san',
        'extension-basic_constraints', 'extension-name_constraints', 'extension-policy_constraints', 'extension-eku',
        'extension-crldp', 'extension-inhibit_any', 'extension-Freshest_CRL', 'extension-aia', 'extension-sia',
        'extension-policy_mappings']
    print('——' * 20 + ' [٩(◕‿◕｡)۶ DERChamber] ' + '——' * 20)
    print('|' + ' ' * 5 + path)
    temp_name = path.split('\\')
    name = temp_name[len(temp_name) - 1]
    parse_result = XDER.DERcert_util.parse(path, 'print')
    about_key = parse_result[2]
    struct_result = XDER.DERcert_util.structuralize(parse_result)
    struct_result = list(struct_result)
    if mode == 'user' and user_target is not None:
        # user mode: specify target directly, no random selection
        name_choiced = user_target
    else:
        # feedback mode: randomly select a field
        choice_num = 0
        while 1:
            choice_num += 1
            name_choiced = random.choice(cert_structure)
            if name_choiced in struct_result[2]:
                break
            if choice_num >= 100:
                break
    x_cert = MutChamber(name, path)
    x_cert.add_ypjsan(struct_result)
    x_cert.self_define(struct_result, about_key, name, name_choiced, mode=mode, user_target=user_target,
                       user_strategy=user_strategy)
    print('——' * 20 + ' [٩(◕‿◕｡)۶ DERChamber] ' + '——' * 20, '\n')

def BatchMut_certs(floder, sample_num, mode='feedback', user_target=None, user_strategy=None):
    """
    Batch mutation
    @param floder: seed certificate library
    @param sample_num: randomly select sample_num certificates from library
    @return:
    """
    certname_txt = get_folder_filenames(floder)
    certname_list = get_certname(certname_txt[0])
    samplecertname_list = random.sample(certname_list, sample_num)
    tc = {}
    for item in samplecertname_list:
        path = floder + item
        try:
            run_mutchamber(path, mode=mode, user_target=user_target, user_strategy=user_strategy)
        except:
            tb = traceback.format_exc()
            tc[path] = tb
        if succeed >= 2025:
            break
    for a, b in tc.items():
        print(f'{a}:{b}')
    with open(f'mut_op_result{SUFFIX}.txt', 'a', encoding='utf-8') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f'[{timestamp}] {mut_op}\n')
if __name__ == '__main__':
    MODE = 'user'
    USER_TARGET = 'extension-san'
    USER_STRATEGY = 'change_tag'

    SUFFIX = '_feedback' if MODE == 'feedback' else '_user'
    MUTAT_DIR = 'mutat_cert' + SUFFIX

    os.environ['XDER_MUTAT_DIR'] = MUTAT_DIR   # <-- newly added line

    BatchMut_certs('E:\\work\\my_project\\der\\', 2, mode=MODE, user_target=USER_TARGET, user_strategy=USER_STRATEGY)
