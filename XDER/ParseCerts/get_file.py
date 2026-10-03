import os

def get_filebindata(_filename):
    """
    Read certificate in hexadecimal format and convert to binary string list
    @param _filename: Path to the certificate file
    @return: Binary string list of the certificate data
    """
    # Read certificate in hexadecimal format
    data_list = []
    with open(_filename, 'rb') as fp:
        data = fp.read().hex()
    # Convert hexadecimal to binary string list
    for item in range(0, len(data)):
        data_list.append(data[item])
    for j in range(0, len(data_list)):
        if data_list[j] == 'a':
            data_list[j] = '10'

        if data_list[j] == 'b':
            data_list[j] = '11'

        if data_list[j] == 'c':
            data_list[j] = '12'

        if data_list[j] == 'd':
            data_list[j] = '13'

        if data_list[j] == 'e':
            data_list[j] = '14'

        if data_list[j] == 'f':
            data_list[j] = '15'
    data_list_tran = []
    for k in range(0, len(data_list)):
        s1 = bin(int(data_list[k]))[2:].zfill(4)
        data_list_tran.append(s1)

    l = data_list_tran
    l = "".join(l)

    data_list_bin = []
    str1 = ""
    addition_number = 0
    m = 1
    while addition_number < len(l):
        while m <= 8:
            if addition_number > len(l) - 1:
                break
            else:
                str1 = str1 + l[addition_number]
                addition_number = addition_number + 1
            m = m + 1

        data_list_bin.append(str1)
        str1 = ''
        m = 1

    return data_list_bin

# Unused function, can be ignored
def get_filename(dir_name):
    '''
    function:Get the file name
    :param dir_name: File path
    :return: List of file names
    '''
    filenamelist = os.listdir(dir_name)
    return filenamelist