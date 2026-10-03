from XDER.MutateCerts.back_repair import encode_length
from XDER.ParseCerts.TLVdumper import TLVdumper
from XDER.SaveCerts.create_certfile import bin_toHex
from XDER.public_utils.public_funcs import partiation
import uuid

def to_binary(data):
    """
    Convert integer to binary string
    @param data: Integer
    @return: Continuous binary string, e.g., '110101'
    """
    return bin(data).replace("0b", "").zfill(8)

def dump(data):
    """
    Parse into TLV tree
    @param data: Certificate binary string list, e.g., ['10101111', '01010111', ..., '01010010']
    @return: Nested dictionary representing TLV tree, no parent-node connections (p-node-id is None)
    """
    valuelst = []
    tree = []
    index = 0
    while index < len(data) - 1:
        # Get P/C flag from tag
        ret = TLVdumper().is_constructed(data, index)
        # Extract tag field
        tagtup = TLVdumper().get_tag(data, index)
        # Extract length field
        index = index + 1
        lengthtup = TLVdumper().get_length(data, index)
        # Extract value field
        index = index + lengthtup[1]
        value = data[index:index + lengthtup[0]]
        # Generate random node ID
        node_id = str(uuid.uuid4())
        # Nested judgment
        if (ret == False and lengthtup[0] > 1):
            try:
                val_tagpluslen_length = int(value[1][1:], 2) + 1 + 1
            except:
                return []
            tag = TLVdumper().get_tag(value, 0)
            if value[1][0] == '0' and len(value) >= 2:
                value0_len = TLVdumper().get_length(value, 1)
                if value0_len[0] <= 127 and lengthtup[0] == (1 + value0_len[1] + value0_len[0]) and tag[2] != "tag_else":
                    ret = True
                else:
                    ret = False
            elif value[1][0] == '1' and len(value) > val_tagpluslen_length:
                value0_len = TLVdumper().get_length(value, 1)
                if value0_len[0] >= 128 and lengthtup[0] == (1 + value0_len[1] + value0_len[0]) and tag[2] != "tag_else":
                    ret = True
                else:
                    ret = False
            else:
                ret = False
        elif (ret == True and lengthtup[0] < 2):
                ret = False
        if tagtup[2] == "tag_else":
            ret = False
        if value != []:
            next_tag = TLVdumper().get_tag(value, 0)
            if next_tag[2] == "tag_else":
                ret = False
        # Return 0 indicates code bug, needs fix
        if len(value) != lengthtup[0]:
            return 0
        # Store current node TLV info into tree structure
        if ret:
            temp = {
                "node-id": node_id,
                "type": tagtup[2],
                "tag": [tagtup[0]],
                "tag-len": len([tagtup[0]]),
                "p-node-id": None,
                "length": lengthtup[0],
                "isNode": False,
                "children": dump(value),
                "hex_value": "invisible",
                "node-value": [],
                "value": f"T:{tagtup[0]}  |  L:{to_binary(lengthtup[0])}  |  V:ALL subtree of current node"
            }
            if dump(value) in [0, []]:
                hex_value = bin_toHex('', value)
                temp = {
                    "node-id": node_id,
                    "type": tagtup[2],
                    "tag": [tagtup[0]],
                    "tag-len": len([tagtup[0]]),
                    "p-node-id": None,
                    "length": lengthtup[0],
                    "isNode": True,
                    "children": [],
                    "hex_value": hex_value,
                    "node-value": value,
                    "value": f"T:{tagtup[0]}  |  L:{to_binary(lengthtup[0])}  |  V:{value}",
                }
                tree.append(temp)
                valuelst.append(value)
            else:
                tree.append(temp)
        else:
            hex_value = bin_toHex('', value)
            temp = {
                "node-id": node_id,
                "type": tagtup[2],
                "tag": [tagtup[0]],
                "tag-len": len([tagtup[0]]),
                "p-node-id": None,
                "length": lengthtup[0],
                "isNode": True,
                "children": [],
                "hex_value": hex_value,
                "node-value": value,
                "value": f"T:{tagtup[0]}  |  L:{to_binary(lengthtup[0])}  |  V:{value}",
            }
            tree.append(temp)
            valuelst.append(value)
        # Move index to next node
        index = index + lengthtup[0]
    return tree

def solve_tree(certTree: list, cert_forest, parent_node_id):
    """
    Add parent node ID to each node in TLV tree and build a forest from TLV tree
    @param certTree: Certificate TLV tree
    @param cert_forest: Extract subtrees from TLV tree to build a forest
    @param parent_node_id: Parent node ID
    @return:
    """
    for n in certTree:
        if parent_node_id is not None:
            n["p-node-id"] = parent_node_id
        cert_forest.append(n)
    for n in certTree:
        if n.get("children") not in (None, []):
            solve_tree(n.get("children"), cert_forest, n["node-id"])


def ctree_tobin(cert_tree: list):
    """
    Compress certificate tree into binary string list
    @param cert_tree: Certificate TLV tree
    @return: Certificate binary string list, e.g., ['11100100', ...]
    """
    def read(r: list, all_result):
        if r is None or r == []:
            return
        for i in r:
            _node_v = i.get("node-value")
            # Process tag field in TLV tree
            _node_tag = i.get("tag")
            for tag in _node_tag:
                all_result.append(tag)
            _node_length = i.get("length")
            # Process length field in TLV tree
            en_len = encode_length(int(_node_length))
            for item in partiation(en_len):
                all_result.append(item)
            # Process value field in TLV tree
            if _node_v is not None:
                for v in _node_v:
                    all_result.append(v)
            children = i.get("children", None)
            if children is not None and children != []:
                read(children, all_result)
    binSTR_list = []
    read(cert_tree, binSTR_list)
    return binSTR_list