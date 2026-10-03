class TLVdumper(object):
    """
    This class processes T, L, and V fields separately.
    """

    def get_tag(self, datastr, index):
        """
        Extract tag from data stream
        @param datastr: Certificate binary string list
        @param index: Index position
        @return: Tag field info including 8-bit binary of tag
        """
        # 8-bit binary of tag, P/C bit of tag, and Class bit of tag
        tag_str = datastr[index]  # 8-bit binary of tag
        tag_str_signbit = tag_str[2]  # Primitive/Constructed bit: 0-primitive 1-constructed
        tag_attribute = tag_str[:2]  # Class bit (universal, application, context-specific, private)
        # Tag class judgment
        if tag_attribute == "00":  # ‘00’ universal type
            if tag_str == '00000001':
                type = 'boolean'  # fix 0x01
            elif tag_str == '00000010':
                type = 'INTEGER'  # fix 0x02
            elif tag_str == '00000011':
                type = 'BIT STRING'  # fix 0x03
            elif tag_str == '00000100':
                type = 'OCTET STRING'  # fix 0x04
            elif tag_str == '00000101':
                type = 'NULL'  # fix 0x05
            elif tag_str == '00000110':
                type = 'OBJECT IDENTIFIER'  # fix 0x06
            elif tag_str == '00000111':
                type = 'Object Descriptor'  # fix 0x07
            elif tag_str == '00001000':
                type = 'EXTERNAL and INSTANCE OF'  # fix 0x08
            elif tag_str == '00001001':
                type = 'REAL(float)'  # fix 0x09
            elif tag_str == '00001010':
                type = 'ENUMERATED'  # 0x0a
            elif tag_str == '00001011':
                type = 'EMBEDDED_PDV'  # 0x0B
            elif tag_str == '00001100':
                type = 'UTF8STRING'  # fix 0x0C  (12)
            elif tag_str == '00001101':
                type = 'RELATIVE_OID'  # fix 0x0D
            elif tag_str == '00110000':
                type = 'SEQUENCE'  # fix 0x30
            elif tag_str == '00110001':
                type = 'SET'  # fix 0x31
            elif tag_str == '00010010':
                type = 'NUMERICSTRING'  # fix 0x12
            elif tag_str == '00010011':
                type = 'PRINTABLESTRING'  # fix 0x13
            elif tag_str == '00010100':
                type = 'TELETEXSTRING'  # fix 0x14
            elif tag_str == '00010101':
                type = 'VIDEOSTRING'  # 0x15
            elif tag_str == '00010110':
                type = 'IA5STRING'  # fix 0x16
            elif tag_str == '00010111':
                type = 'UTCTime'  # fix 0x17
            elif tag_str == '00011000':
                type = 'GeneralizedTime'  # fix 0x18
            elif tag_str == '00011001':
                type = 'GraphicString'  # fix 0x19
            elif tag_str == '00011010':
                type = 'VisibleString, ISO646String'  # fix 0x1A
            elif tag_str == '00011011':
                type = 'GeneralString'  # fix 0x1b
            elif tag_str == '00011100':
                type = 'UniversalString'  # fix 0x1c
            elif tag_str == '00011101':
                type = 'CHARACTER STRING'  # fix 0x1D
            elif tag_str == '00011110':
                type = 'BMPString'  # fix 0x1E
            else:
                type = 'tag_else'
        elif '1010' in tag_str[0:4]:
            type = 'Optional'  # 0xan
        elif '1000' in tag_str[0:4]:
            type = 'context'  # 0x8n
        else:
            type = 'tag_else'
        return tag_str, tag_str_signbit, type

    def is_constructed(self, datastr, index):
        """
        Process P/C bit in tag
        @param datastr: Certificate binary string list
        @param index: Position
        @return: True for constructed, False for primitive
        """
        tag_str_signbit = datastr[index][2]
        if tag_str_signbit == '1':
            return True
        else:
            return False

    @staticmethod
    def get_length(datastr, index):
        """
        Process Length field in TLV
        @param datastr: Certificate binary string list
        @param index: Position
        @return: Value length of TLV (full_len_value), Length of length field (Len_len)
        """
        length_str = datastr[index]
        length_str_signbit = length_str[0]
        if length_str_signbit == '0':
            Len_len = 1
            Len_value = length_str
            full_len_value = int(Len_value, 2)
        elif length_str_signbit == '1':
            Len_len = int(length_str[1:], 2) + 1
            Len_value = datastr[index + 1:index + Len_len]
            value = ''
            for i in range(0, len(Len_value)):
                value = value + Len_value[i]
            if Len_value != []:
                full_len_value = int(value, 2)
            elif Len_value == []:
                full_len_value = 0
        return full_len_value, Len_len

    # The following content is unused and can be ignored
    # @staticmethod
    # def getvaluelength():
    #     tup = DERdumper.getLength()
    #     return tup[0]

    def get_value(self, datastr, index):
        '''
        function: Get value
        :param datastr: Data to be parsed
        :param index: Mark bit
        :return: value
        '''
        tup = TLVdumper().get_length(datastr, index)
        value = datastr[tup[1] + 1: tup[0] + tup[1] + 1]
        return value