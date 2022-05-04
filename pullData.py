'''https://docs.python.org/3/library/struct.html'''
import struct


def findLocalFileHeaders(header_count):
    """
    In charge of finding the local file headers in a zip file
    """
    offset = 0
    for i in range(header_count):
        start_offset = offset  # store our start offset for this local file header
        """
        Signature
        """
        sig = (data[offset:offset+4], 'B')
        if(b'PK\x03\x04' not in sig):
            print("INVALID SIGNATURE - ENDING\n FOUND - "+str(sig)+"\n")
            break
        offset += 4
        """
        Version
        """
        # because the flag is 2 bytes, we use cc here to see the binary representing the flags
        fields = struct.unpack('cc', data[offset:offset+2])
        version = fields
        offset += 2
        """
        Flags
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        flags = fields
        offset += 2
        """
        Compression
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        compression = fields
        offset += 2
        """
        Modification Time
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        mod_time = fields
        offset += 2
        """
        Modification Date
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        mod_date = fields
        offset += 2

        '''
        'LLLHH' represents [crc-32 (long), compressed size (long), uncompressed size (long), file name length (unsigned short), extra field length (unsigned short)]
        From [crc-32] to [extra field len] is 16 hex values
        '''
        fields = struct.unpack('LLLHH', data[offset:offset+16])
        crc32, comp_size, uncomp_size, file_name_len, extra_len = fields
        offset += 16

        # now that we have the file name size stored in the header, we can start at the 30th index, where the file name of some varible size resides
        filename = data[offset:offset+file_name_len]
        offset += file_name_len  # now lets move to the end of the file name
        # and use it to start on the extra field, ending at the indicated variable size
        extra = data[offset:offset+extra_len]

        """
        Create record
        """
        record = {'B@Signature': sig,
                  'cc@Version': version,
                  'cc@Flags': flags,
                  'cc@Compression': compression,
                  'cc@Mod Time': mod_time,
                  'cc@Mod Date': mod_date,
                  'L@Crc-32': crc32,
                  'L@Compressed size': comp_size,
                  'L@Uncompressed size': uncomp_size,
                  'H@File name len': file_name_len,
                  'H@Extra field len': extra_len,
                  'B@File name': filename,
                  'B@Extra field': extra
                  }
        print(str(hex(start_offset))+':'+str(record)+"\n")
        offset += extra_len + comp_size  # go to the next header
        # grab_header(start_offset, start)
    end_offset = offset
    row = end_offset/16
    print(str(i)+" Local File Headers found. \n Final local file header ending offset: "+str(hex(end_offset)) +
          ":"+str(end_offset)+"B Column:"+str(row)+"\n\n")
    return end_offset


def findCDFileHeaders(offset, header_count):
    for i in range(header_count):
        start_offset = offset
        """
        Signature
        """
        sig = data[offset:offset+4]
        if(b'\x50\x4b\x01\x02' not in sig):
            print("INVALID SIGNATURE - ENDING\n FOUND - "+str(sig)+"\n")
            break
        offset += 4
        """
        Version
        """
        # because the flag is 2 bytes, we use cc here to see the binary representing the flags
        fields = struct.unpack('cc', data[offset:offset+2])
        version = fields
        offset += 2
        """
        Version Meeded
        """
        # because the flag is 2 bytes, we use cc here to see the binary representing the flags
        fields = struct.unpack('cc', data[offset:offset+2])
        version_needed = fields
        offset += 2
        """
        Flags
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        flags = fields
        offset += 2
        """
        Compression
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        compression = fields
        offset += 2
        """
        Modification Time
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        mod_time = fields
        offset += 2
        """
        Modification Date
        """
        fields = struct.unpack('cc', data[offset:offset+2])
        mod_date = fields
        offset += 2

        """
        'LLLHH' represents [crc-32 (long), compressed size (long), uncompressed size (long), file name length (unsigned short), extra field length (unsigned short)]
        From [crc-32] to [extra field len] is 16 hex values 
        """
        # local file header meta data
        fields = struct.unpack('LLLHH', data[offset:offset+16])
        crc32, comp_size, uncomp_size, file_name_len, extra_len = fields
        offset += 16
        """
        File comm. length and disk # start
        """
        fields = struct.unpack('HH', data[offset:offset+4])
        file_comnt_len, disk_num = fields
        offset += 4
        """
        Internal attribute
        """
        fields = data[offset:offset+2]
        inter_attr = fields
        offset += 2
        """
        External attribute
        """
        fields = data[offset:offset+4]
        exter_attr = fields
        offset += 4
        """
        Offset of local header
        """
        fields = struct.unpack('L', data[offset:offset+4])
        offset_local_header = fields
        offset += 4
        """
        File name, extra field, file comment
        """
        filename = data[offset:offset+file_name_len]
        offset += file_name_len  # now lets move to the end of the file name
        extra = data[offset:offset+extra_len]
        offset += extra_len
        comment = data[offset:offset+file_comnt_len]
        offset += file_comnt_len
        """
        Create record
        """
        record = {'B@Signature': sig,
                  'cc@Version': version,
                  'cc@Vers. needed': version_needed,
                  'cc@Flags': flags,
                  'cc@Compression': compression,
                  'cc@Mod Time': mod_time,
                  'cc@Mod Date': mod_date,
                  'L@Crc-32': crc32,
                  'L@Compressed size': comp_size,
                  'L@Uncompressed size': uncomp_size,
                  'H@File name len': file_name_len,
                  'H@Extra field len': extra_len,
                  'H@File comm. len': file_comnt_len,
                  'H@Disk # start': disk_num,
                  'B@Internal attr.': inter_attr,
                  'B@External attr.': exter_attr,
                  'L@Offset of local header': offset_local_header,
                  'B@File name': filename,
                  'B@Extra field': extra,
                  'B@File Comment': comment
                  }
        print(str(hex(start_offset))+':'+str(record)+'\n')
        # grab_header(hex(start_offset), hex(offset))

    end_offset = offset
    row = end_offset/16
    print(str(i)+" Central File Headers found. \n Final central file header ending offset: " +
          str(hex(end_offset))+":"+str(end_offset-start_offset)+"B Row:"+str(row)+"\n\n")
    return start_offset, end_offset


def findEOCDR(offset):
    start_offset = offset
    sig = data[offset:offset+4]
    if(b'\x50\x4b\x05\x06' in sig):
        offset += 4
        fields = struct.unpack('HHHHLLH', data[offset:offset+18])
        end_disk_num, disk_num, disk_entr, tot_entr, cds, cd_offset, cm_len = fields
        offset += 18
        zip_comment = data[offset:offset+cm_len]
        offset += cm_len
        record = {'B@Signature': sig,
                  'H@End Disk#': end_disk_num,
                  'H@Disk #': disk_num,
                  'H@Disk Entries': disk_entr,
                  'H@Tot Entries': tot_entr,
                  'L@Central Directory Size': cds,
                  'L@Central Directory Offset': cd_offset,
                  'H@Comnt Len': cm_len,
                  'B@Comment': zip_comment}
        print(str(hex(start_offset))+':'+str(record)+"\n")
    else:
        print("INVALID SIGNATURE FOR EOCDR\n FOUND - "+str(sig)+"\n")
        return start_offset, offset
    # grab_header(hex(start_offset), hex(offset))
    return start_offset, offset


def encodeHeader(header):
    nheader = []
    for key in header:
        encodeWith = key.split('@')[0]
        if('B' in encodeWith):
            byte = header[key]
        else:
            byte = struct.pack(encodeWith, header[key])
        nheader.append(byte)
    return nheader


def replaceHeader(offset, header):
    f = open(file, "r+b")
    f.seek(offset)
    for each in header:
        f.write(each)
    f.close()


def grab_header(start_offset, end_offset):
    start_offset = int(start_offset, 16)
    end_offset = int(end_offset, 16)
    header = ''
    offset = 0
    cycle = 0
    for byte in data.hex(' ').split(' '):
        if(offset >= start_offset and offset <= end_offset):
            header += byte
            if(cycle == 1):
                header += ' '
                cycle = 0
            else:
                cycle += 1
        offset += 1
    print(header)


if __name__ == '__main__':
    N = 10000
    file = 'sample/ans.zip'
    data = open(file, 'rb').read()

    print("Local File Headers:")
    end_offset = findLocalFileHeaders(N)

    print("Central Directory File Headers:")
    start_offset, end_offset = findCDFileHeaders(end_offset, N)

    print("End of Central Directory Record:")
    start_offset, end_offset = findEOCDR(end_offset)

    row = end_offset/16
    print("Finished at ending offset: " +
          str(hex(end_offset))+":"+str(end_offset-start_offset)+"B Row:"+str(row)+"\n\n")
    #header = record
    # header['H@Disk Entries'] = 5
    # header['H@Tot Entries'] = 5
    # replaceHeader(start_offset, encodeHeader(header))
