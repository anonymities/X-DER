import copy
from XDER.MutateCerts.back_repair import fix_tlvlength, encode_length
import random
from XDER.public_utils.public_funcs import find_nodeID
from XDER.public_utils.public_funcs import partiation

# function of mutate
def add(cert_forest,_node, position, binary_str):
    """
    Leaf node addition mutation
    @param cert_forest: Certificate forest
    @param _node: Node to be mutated
    @param position: Mutation position
    @param binary_str: Mutation value
    @return:
    """
    if _node["node-value"]  != []:
        _node["node-value"].insert(position, binary_str)
        fix_tlvlength(cert_forest, _node["node-id"], +1)
    else:
        _node["node-value"].append(binary_str)
        fix_tlvlength(cert_forest, _node["node-id"], +1)

def change_value(cert_forest, _node, position, binary_str, mode):
    """
    Modify leaf node value
    @param cert_forest: Certificate forest
    @param _node: Node to be mutated
    @param position: Mutation position
    @param binary_str: Mutation value
    @param mode: Non-TLV mode: modify value at specified position; TLV mode: wrap value as a TLV node
    @return:
    """
    if mode != 'TLV':
        if _node["node-value"] == []:
            add(cert_forest, _node, position, binary_str)
        else:
            _node["node-value"][position] = binary_str
    if mode == 'TLV':
        value_TLV= []
        new_tag = change_tag(cert_forest, _node, 'new_tag')
        for i in new_tag:
            value_TLV.append(i)
        temp_length = encode_length(len(_node["node-value"]))
        lengthField_list = partiation(temp_length)
        for i in lengthField_list:
            value_TLV.append(i)
        for i in _node["node-value"]:
            value_TLV.append(i)
        # Mutate
        _node["node-value"].clear()
        for i in value_TLV:
            _node["node-value"].append(i)
        fix_tlvlength(cert_forest, _node["node-id"], len(new_tag) + len(lengthField_list))

def delete(cert_forest,_node, position):
    """
    Delete leaf node value
    @param cert_forest: Certificate forest
    @param _node: Node to be mutated
    @param position: Deletion position
    @return:
    """
    if _node["node-value"] != []:
        _node["node-value"].pop(position)
        fix_tlvlength(cert_forest, _node["node-id"], -1)
    else:
        pass

def delete_leaf(cert_forest, _leafnode_deled, _node_position):
    """
    Delete leaf node
    @param cert_forest: Certificate forest
    @param _leafnode_deled: Leaf node to be deleted
    @param _node_position: Position of deleted leaf node in its parent
    @return:
    """
    # Find parent node of current node
    _node_p = find_nodeID(cert_forest, _leafnode_deled['p-node-id'])
    # Set position index
    index = _node_position
    # Repair length
    length = int(_leafnode_deled['length'])
    if len(_node_p['children']) == 1:
        _node_p['isNode'] = True
        _node_p["hex_value"] = ''
        _node_p["node-value"] = []
    fix_tlvlength(cert_forest, _leafnode_deled["p-node-id"], -(length + int(len(encode_length(length)) / 8) + _leafnode_deled['tag-len']))
    # Remove current node from parent's children
    _node_p['children'].pop(index)
    return

def delete_innernode(cert_forest, _innernode_deled, _node_position):
    """
    Delete inner node
    @param cert_forest: Certificate forest
    @param _innernode_deled: Inner node to be deleted
    @param _node_position: Position of deleted inner node in its parent
    @return:
    """
    # Find parent node of current node
    _node_p = find_nodeID(cert_forest, _innernode_deled['p-node-id'])
    # Set position index
    index = _node_position
    # Repair length
    length = int(_innernode_deled['length'])
    if len(_node_p['children']) == 1:
        _node_p['isNode'] = True
        _node_p["hex_value"] = ''
        _node_p["node-value"] = []
    fix_tlvlength(cert_forest, _innernode_deled["p-node-id"], -(length + int(len(encode_length(length)) / 8) + _innernode_deled['tag-len']))
    # Remove current node from parent's children
    _node_p['children'].pop(index)
    return

def replace_node(cert_forest, _node_replaced, out_node, _node_position):
    """
    Replace node mutation
    @param cert_forest: Certificate forest
    @param _node_replaced: Node to be replaced
    @param out_node: Node used for replacement
    @param _node_position: Position of replaced node in its parent
    @return:
    """
    _innernode_muted = find_nodeID(cert_forest, _node_replaced['p-node-id'])
    # Modify out node info
    length = int(out_node['length'])
    out_node["p-node-id"] = _innernode_muted['node-id']
    outnode_tlvlength = (length + int(len(encode_length(length)) / 8)) + out_node['tag-len']
    # Calculate info of replaced node
    _length = int(_innernode_muted['children'][_node_position]['length'])
    _tag_len = _innernode_muted['children'][_node_position]['tag-len']
    _innernode_muted_tlvlength = (_length + int(len(encode_length(_length)) / 8)) + _tag_len
    # Set position index
    index = _node_position
    back_index = index
    _innernode_muted['children'][index] = out_node
    # Repair length
    fix_tlvlength(cert_forest, _innernode_muted["node-id"], outnode_tlvlength - _innernode_muted_tlvlength)
    return

def addleaf_toinner(cert_forest, _innernode_added, out_leafnode, position):
    """
    Add leaf node to inner node
    @param cert_forest: Certificate forest
    @param _innernode_added: Target inner node
    @param out_leafnode: New leaf node to add
    @param position: Insert position
    @return:
    """
    # Modify out node info
    length = int(out_leafnode['length'])
    out_leafnode["p-node-id"] = _innernode_added['node-id']
    # Generate insert index and insert
    if position == None:
        addded_postion = random.randint(0, len(_innernode_added['children']))
    else:
        addded_postion = position
    _innernode_added['children'].insert(addded_postion, out_leafnode)
    # Repair length
    fix_tlvlength(cert_forest, _innernode_added["node-id"], (length + int(len(encode_length(length)) / 8)) + out_leafnode['tag-len'])
    return addded_postion

def addinner_toinner(cert_forest, _innernode_added, out_innernode, position):
    """
    Add inner node to inner node
    @param cert_forest: Certificate forest
    @param _innernode_added: Target inner node
    @param out_innernode: New inner node to add
    @param position: Insert position
    @return:
    """
    # Modify out node info
    length = int(out_innernode['length'])
    out_innernode["p-node-id"] = _innernode_added['node-id']
    # Generate insert index and insert
    if position == None:
        addded_postion = random.randint(0, len(_innernode_added['children']))
    else:
        addded_postion = position
    _innernode_added['children'].insert(addded_postion, out_innernode)
    # Repair length
    fix_tlvlength(cert_forest, _innernode_added["node-id"], (length + int(len(encode_length(length)) / 8)) + out_innernode['tag-len'])
    return addded_postion

def tamper_withca(cert_forest, leaf_issuer, ca_is):
    """
    Build name linkage when generating CA certificate from mutated certificate.
    Make CA user = CA issuer = terminal leaf certificate issuer
    @param cert_forest: Certificate forest
    @param leaf_issuer: Issuer field of mutated (terminal leaf) certificate
    @param ca_is: Issuer/user field of root CA certificate
    @return:
    """
    the_notnode = copy.deepcopy(leaf_issuer)

    ca_is['node-id'] = the_notnode["node-id"]
    ca_is['children'] = the_notnode['children']
    fix_tlvlength(cert_forest, ca_is["node-id"], int(the_notnode['length']) - int(ca_is['length']))

    tag_difference = the_notnode['tag-len'] - ca_is['tag-len']
    ca_is['tag'].clear()
    for i in the_notnode['tag']:
        ca_is['tag'].append(i)
    ca_is['tag-len'] = the_notnode['tag-len']
    fix_tlvlength(cert_forest, ca_is["p-node-id"], tag_difference)

def change_tag(cert_forest, _node, mode):
    """
    Tag mutation
    @param cert_forest: Certificate forest
    @param _node: Node to be mutated
    @param mode: mode=change: mutate; mode=new_tag: return new generated tag (list) only
    @return:
    """
    def generate_tag_bytes():
        # Generate random Tag
        tag_class = random.randint(0, 3)  # 2 bits: 0-3
        pc = random.randint(0, 1)  # 1 bit: 0 or 1
        tag_value = random.randint(0, 127)

        # Encode first byte
        byte0 = (tag_class << 6) | (pc << 5)
        tag_bytes = []

        if tag_value < 31:  # Short form
            byte0 |= tag_value
            tag_bytes.append(byte0)
        else:  # Long form
            byte0 |= 0x1F  # Set last 5 bits to 11111
            tag_bytes.append(byte0)

            # Encode following bytes
            bytes_list = []
            while tag_value:
                bytes_list.append(tag_value & 0x7F)
                tag_value >>= 7
            bytes_list.reverse()

            # Set highest bit (except last one)
            for i in range(len(bytes_list) - 1):
                bytes_list[i] |= 0x80
            tag_bytes.extend(bytes_list)

        # Convert to binary string list
        return [format(b, '08b') for b in tag_bytes]
    # Generate new Tag
    tag_list = generate_tag_bytes()
    # 'change' = mutate, 'new_tag' = return new generated tag
    if mode == 'change':
        node_tagLength = _node["tag-len"]
        fix_tlvlength(cert_forest, _node['p-node-id'], len(tag_list) - node_tagLength)
        _node["tag"].clear()
        for i in tag_list:
            _node["tag"].append(i)
        # Repair tag-len flag
        _node["tag-len"] = len(tag_list)
    elif mode == 'new_tag':
        return tag_list

def lengthMut(cert_forest, _node):
    """
    Length mutation
    @param _node: Node to be mutated
    @param cert_forest: Certificate forest
    @return:
    """
    # New length field
    newLength = random.randint(0, 150)
    # Calculate length info
    length = _node['length']
    # Mutate
    _node['length'] = newLength
    init_lengthbyte = int(len(encode_length(length)) / 8)
    current_lengthbyte = int(len(encode_length(newLength)) / 8)
    # Repair
    fix_tlvlength(cert_forest, _node["p-node-id"], current_lengthbyte - init_lengthbyte)

def exchange(cert_forest, _node1, _node2):
    """
    Unused function
    @param cert_forest: Certificate forest
    @param _node1: Node 1
    @param _node2: Node 2
    @return:
    """
    _node1_p = find_nodeID(cert_forest, _node1['p-node-id'])
    _node2_p = find_nodeID(cert_forest, _node2['p-node-id'])

    index1 = _node1_p['children'].index(_node1)
    index2 = _node2_p['children'].index(_node2)

    copy_node1 = copy.deepcopy(_node1)
    copy_node2 = copy.deepcopy(_node2)
    leen1 = copy_node1['length'] + int(len(encode_length(copy_node1['length'])) / 8) + 1
    leen2 = copy_node2['length'] + int(len(encode_length(copy_node2['length'])) / 8) + 1

    _node1_p['children'][index1] = copy_node2
    fix_tlvlength(cert_forest, _node1['p-node-id'], leen2 - leen1)
    _node2_p['children'][index2] = copy_node1
    fix_tlvlength(cert_forest, _node2['p-node-id'], leen1 - leen2)

# Node tree type mutation
# Find inner node (node-finded), convert all its children to a single data string.
# Repair: record node-finded and its position, use replace to repair
# Plus leaf node to inner node conversion