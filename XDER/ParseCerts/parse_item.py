import json

# Load full OID table
path_oid = "./ParseCerts/oid.txt"
with open(path_oid, 'r', encoding='utf-8') as file:
    content = file.read()
    data = json.loads(content)

def issuer_item(oid):
    """
    Process issuer field
    @param oid: OID value, e.g. 1.2.4.5
    @return: Return corresponding name if found, return OID if not found
    """
    global data
    find = False
    OID_name = ''
    for i in data:
        if i['Section'] == 'issuer':
            if i['OID'] == oid:
                find = True
                OID_name = i['Item']
    if find == True:
        return OID_name
    else:
        return oid

def subject_item(oid):
    """
    Process subject field
    @param oid: OID value, e.g. 1.2.4.5
    @return: Return corresponding name if found, return OID if not found
    """
    global data
    find = False
    OID_name = ''
    for i in data:
        if i['Section'] == 'subject':
            if i['OID'] == oid:
                find = True
                OID_name = i['Item']
    if find == True:
        return OID_name
    else:
        return oid

def sub_ex(oid):
    """
    Process extension field
    @param oid: OID value, e.g. 1.2.4.5
    @return: Return corresponding name if found, return OID if not found
    """
    global data
    find = False
    OID_name = ''
    for i in data:
        if i['OID'] == oid:
            find = True
            OID_name = i['Section']
    if find == True:
        return OID_name
    else:
        return oid

def certPolicies_item(oid):
    """
    Process certificate policies field
    @param oid: OID value, e.g. 1.2.4.5
    @return: Return corresponding name if found, return OID if not found
    """
    global data
    find = False
    OID_name = ''
    for i in data:
        if i['Section'] == 'cert_policies':
            if i['OID'] == oid:
                find = True
                OID_name = i['Item']
    if find == True:
        return OID_name
    else:
        return oid

def SAN_item(single_san):
    """
    Process Subject Alternative Name field
    @param single_san: Single SAN entry
    @return: Field name, e.g. dNSName
    """
    tag = single_san['tag'][0]
    san_dir = {
        '10000000': 'otherName',
        '10000001': 'rfc822Name',
        '10000010': 'dNSName',
        '10000011': 'x400Address',
        '10000100': 'directoryName',
        '10000101': 'ediPartyName',
        '10000110': 'uniformResourceIdentifier',
        '10000111': 'iPAddres',
        '10001000': 'registeredID'

    }
    try:
        san_item = san_dir[tag]
    except:
        san_item = 'unKnownName'
    return san_item


def EKU_item(oid):
    """
    Process Extended Key Usage field
    @param oid: OID value, e.g. 1.2.4.5
    @return: Return corresponding name if found, return OID if not found
    """
    global data
    find = False
    OID_name = ''
    for i in data:
        if i['Section'] == 'eku':
            if i['OID'] == oid:
                find = True
                OID_name = i['Item']
    if find == True:
        return OID_name
    else:
        return oid

def aiasia_item(oid):
    """
    Process Authority Information Access field
    @param oid: OID value, e.g. 1.2.4.5
    @return: Return corresponding name if found, return OID if not found
    """
    global data
    find = False
    OID_name = ''
    for i in data:
        if i['OID'] == oid:
            find = True
            OID_name = i['Item']
    if find == True:
        return OID_name
    else:
        return oid