import copy
def encode_length(length):
    """
    Convert integer length field to a continuous binary string
    @param length: Integer length field, e.g. 1233
    @return: Binary string
    """
    def int_to_binary_array(n):
        return format(n, '08b')

    if length < 128:
        # Short form
        return int_to_binary_array(length)
    else:
        # Long form
        length_of_length = 1
        temp_length = length
        while temp_length > 255:
            temp_length = temp_length >> 8
            length_of_length += 1
        result = [int_to_binary_array(128+length_of_length)]
        bytes_of_length = []
        for _ in range(length_of_length):
            bytes_of_length.append(int_to_binary_array(length & 0xFF))
            length = length >> 8
        result += bytes_of_length[::-1]
        return ''.join(result)

def to_binary(n):
    """
    Convert integer to a continuous binary string
    @param n: Integer number
    @return: Binary string
    """
    return bin(n).replace("0b", "").zfill(8)

def fix_tlvlength(cert_forest, node_id, change_num=0):
    """
    Fix the length field (int) from bottom to top, encode the int length when saving the certificate
    @param cert_forest: Certificate forest
    @param node_id: ID of the node to be fixed
    @param change_num: Offset value for fixing
    @return:
    """
    if node_id is None:
        return
    # Find current node
    current_node = None
    for node in cert_forest:
        if node_id == node["node-id"]:
            current_node = node
            break
    # Record initial length of current node
    init_len = copy.deepcopy(current_node["length"])
    # Fix the length value of current node
    current_node["length"] = current_node["length"] + change_num
    # Calculate initial length bytes
    init_lengthbyte = int(len(encode_length(init_len)) / 8)
    # Calculate fixed length bytes
    current_lengthbyte = int(len(encode_length(current_node["length"])) / 8)
    # Calculate total length change of current TLV node
    change_num = change_num + (current_lengthbyte - init_lengthbyte)

    # Check if it's a leaf node
    if current_node["isNode"]:
        current_node["value"] = f'T:{current_node["tag"]}  |  L:{to_binary(int(current_node["length"]))}  |  V:{current_node["node-value"]}'
    else:
        current_node["value"] = f'T:{current_node["tag"]}  |  L:{to_binary(int(current_node["length"]))}  |  V:ALL subtree of current node'
    # Recursively fix parent nodes
    fix_tlvlength(cert_forest, current_node["p-node-id"], change_num=change_num)

def back_node(cert_forest, _innernode_muted, node_copyed, position, mode):
    """
    Rollback and repair if Nginx verification fails after mutation
    @param cert_forest: Certificate forest
    @param _innernode_muted: Parent node of the mutated node
    @param node_copyed: Original data of the mutated node (copy before mutation)
    @param position: Position of the mutated node in parent node
    @param mode: Rollback and repair mode
    @return:
    """
    # Calculate node_copyed info
    length = int(node_copyed['length'])
    node_copyed["p-node-id"] = _innernode_muted['node-id']
    nodeCopyed_tlvlength = (length + int(len(encode_length(length)) / 8)) + node_copyed['tag-len']
    # Calculate info of replaced node
    if mode == 'replace':
        _length = int(_innernode_muted['children'][position]['length'])
        _innernode_muted_tlvlength = (_length + int(len(encode_length(_length)) / 8)) + _innernode_muted['children'][position]['tag-len']
    # Set position index
    index = position
    # Start rollback
    if mode == 'insert':
        _innernode_muted['children'].insert(index, node_copyed)
        if len(_innernode_muted['children']) >= 1:
            _innernode_muted['isNode'] = False
            _innernode_muted["hex_value"] = "invisible"
            _innernode_muted['node-value'] = []
        # Fix length
        fix_tlvlength(cert_forest, _innernode_muted["node-id"], nodeCopyed_tlvlength)
    elif mode == 'replace':
        _innernode_muted['children'][index] = node_copyed
        # Fix length
        fix_tlvlength(cert_forest, _innernode_muted["node-id"], nodeCopyed_tlvlength - _innernode_muted_tlvlength)
    elif mode == 'del':
        _innernode_muted['children'].pop(index)
        # Fix length
        fix_tlvlength(cert_forest, _innernode_muted["node-id"], -nodeCopyed_tlvlength)
    elif mode == 'len':
        a = node_copyed['length']
        b = copy.deepcopy(_innernode_muted['children'][position]['length'])
        _innernode_muted['children'][position]['length'] = a
        init_lengthbyte = int(len(encode_length(a)) / 8)
        current_lengthbyte = int(len(encode_length(b)) / 8)
        # Fix length
        fix_tlvlength(cert_forest, _innernode_muted["node-id"], init_lengthbyte - current_lengthbyte)

def repair_tag(node_list,node_id):
    """
    Unused function
    @param node_list: Node list
    @param node_id: Node ID
    @return:
    """
    current_node = None
    for n in node_list:
        if n.get("node-id") == node_id:
            current_node = n
            break
    if current_node is None:
        return
    if not current_node.get("children",[]):
        current_node["tag"] = current_node["tag"][:2] + "0" + current_node["tag"][3:]
    if current_node["isNode"]:
        current_node["value"] = f'T:{current_node["tag"]}    |    L:{to_binary(int(current_node["length"]))}    |    V:{current_node["node-value"]}'
    else:
        current_node["value"] = f'T:{current_node["tag"]}    |    L:{to_binary(int(current_node["length"]))}    |    []'
    if current_node.get("p-node-id"):
        repair_tag(node_list,current_node.get("p-node-id"))