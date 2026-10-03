def hex_to_bin(h):
    """
    Convert hex string to continuous 8-bit binary string
    @param h: Hex string
    @return: Continuous binary string
    """
    r = []
    for i in h:
        r.append(bin(int(i, 16))[2:].zfill(4))
    return "".join(r)

def find_oid_node(nodes: [dict], value) -> (dict, int, int):
    """
    Find node with specified value in nodes list
    @param nodes: List composed of multiple nodes
    @param value: Hexadecimal value
    @return: Found node _n with Value field matching the parameter value
    """
    find_bin = hex_to_bin(value)
    for _n in nodes:
        node_v = "".join(_n.get("node-value"))
        if find_bin in node_v:
            index = node_v.index(find_bin)

            start = index - 4 * 8
            len_index = start + 1 * 8
            len_bin = node_v[len_index: len_index + 1 * 8]
            len_int = int(len_bin, 2)
            end = len_index + 1 * 8 + (len_int * 8)
            return _n, start // 8, end // 8

def parse_oid(parent, nodes: list):
    """
    Unused function, please ignore
    @param parent: Parent node ID
    @param nodes: Node list
    @return:
    """
    oid_node = []  # Store node ID and node TLV in list
    oid_edge = []
    if nodes is None or nodes == []:
        return
    for n in nodes:
        oid_node.append((n["node-id"], n["value"]))
    if parent is not None:
        for n in nodes:
            oid_edge.append((parent, n["node-id"]))
    for n in nodes:
        if n.get("children") not in (None, []):
            parse_oid(n["node-id"], n.get("children"))