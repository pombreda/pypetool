#!/usr/bin/env python
#-*- coding=utf-8 -*-

import struct
from ctypes import *

BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
QWORD = c_ulonglong

class PETypeError(RuntimeError):
    def __init__(self, cause, message):
        self.cause = cause
        self.message = message
    def __str__(self):
        return '%s => %s' % (self.cause, self.message)

def StrToCType(inputStr):
    length = len(inputStr)
    types = {1:'B', 2:'H', 4:'I', 8:'Q'}
    if type(inputStr) != str or length not in types.keys():
        raise PETypeError('StrToCType', 'The parameter maybe wrong!')
    return struct.unpack(types[length], inputStr)[0]

def toBYTEs(num_array):
    bytes = ''
    try:
        for num in num_array:
            if type(num) != int or num > 0xff:
                raise PETypeError('toBYTE', 'The parameter maybe wrong!')
            bytes += struct.pack('B', num)
    except TypeError:
        raise PETypeError('toBYTE', 'The parameter maybe wrong!')
    return bytes

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic', WORD),
        ('e_cblp', WORD),
        ('e_cp', WORD),
        ('e_crlc', WORD),
        ('e_cparhdr', WORD),
        ('e_minalloc', WORD),
        ('e_maxalloc', WORD),
        ('e_ss', WORD),
        ('e_sp', WORD),
        ('e_csum', WORD),
        ('e_ip', WORD),
        ('e_cs', WORD),
        ('e_lfarlc', WORD),
        ('e_ovno', WORD),
        ('e_res', WORD * 4),
        ('e_oemid', WORD),
        ('e_oeminfo', WORD),
        ('e_res2', WORD * 10),
        ('e_lfanew', DWORD)
        ]

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine', WORD),
        ('NumberOfSections', WORD),
        ('TimeDateStamp', DWORD),
        ('PointerToSymbolTable', DWORD),
        ('NumberOfSymbols', DWORD),
        ('SizeOfOptionalHeader', WORD),
        ('Characteristics', WORD)
        ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress', DWORD),
        ('Size', DWORD)
        ]

class IMAGE_OPTIONAL_HEADER32(Structure):
    _fields_ = [
        #Standard fields
		('Magic', WORD),
        ('MajorLinkerVersion', BYTE),
        ('MinorLinkerVersion', BYTE),
        ('SizeOfCode', DWORD),
        ('SizeOfInitialzedData', DWORD),
        ('SizeOfUninitializedData', DWORD),
        ('AddressOfEntryPoint', DWORD),
        ('BaseOfCode', DWORD),
        ('BaseOfData', DWORD),
        #NT additional fields
        ('ImageBase', DWORD),
        ('SectionAlignment', DWORD),
        ('FileAlignment', DWORD),
        ('MajorOperationSystemVersion', WORD),
        ('MinorOperatingSystemVersion', WORD),
        ('MajorImageVersion', WORD),
        ('MinorImageVersion', WORD),
        ('MajorSubsystemVersion', WORD),
        ('MinorSubsystemVersion', WORD),
        ('Win32VersionValue', DWORD),
        ('SizeOfImage', DWORD),
        ('SizeOfHeaders', DWORD),
        ('CheckSum', DWORD),
        ('Subsystem', WORD),
        ('DllCharacteristics', WORD),
        ('SizeOfStackReserve', DWORD),
        ('SizeOfStackCommit', DWORD),
        ('SizeOfHeapReserver', DWORD),
        ('SizeOfHeapCommit', DWORD),
        ('LoaderFlags', DWORD),
        ('NumberOfRvaAndSizes', DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)
        ]
IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER32

class IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ = [
        #Standard fields
        ('Magic', WORD),
        ('MajorLinkerVersion', BYTE),
        ('MinorLinkerVersion', BYTE),
        ('SizeOfCode', DWORD),
        ('SizeOfInitialzedData', DWORD),
        ('SizeOfUninitializedData', DWORD),
        ('AddressOfEntryPoint', DWORD),
        ('BaseOfCode', DWORD),
        #NT additional fields
        ('ImageBase', QWORD),
        ('SectionAlignment', DWORD),
        ('FileAlignment', DWORD),
        ('MajorOperationSystemVersion', WORD),
        ('MinorOperatingSystemVersion', WORD),
        ('MajorImageVersion', WORD),
        ('MinorImageVersion', WORD),
        ('MajorSubsystemVersion', WORD),
        ('MinorSubsystemVersion', WORD),
        ('Win32VersionValue', DWORD),
        ('SizeOfImage', DWORD),
        ('SizeOfHeaders', DWORD),
        ('CheckSum', DWORD),
        ('Subsystem', WORD),
        ('DllCharacteristics', WORD),
        ('SizeOfStackReserve', DWORD),
        ('SizeOfStackCommit', DWORD),
        ('SizeOfHeapReserver', DWORD),
        ('SizeOfHeapCommit', DWORD),
        ('LoaderFlags', DWORD),
        ('NumberOfRvaAndSizes', DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)
        ]

class IMAGE_NT_HEADERS32(Structure):
    _fields_ = [
        ('Signature', DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER32)
        ]
IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32

class IMAGE_NT_HEADERS64(Structure):
    _fields_ = [
        ('Signature', DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER64)
        ]

class SECTION_MISC(Union):
    _fields_ = [
        ('PhysicalAddress', DWORD),
        ('VirtualSize', DWORD)
        ]
class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name', BYTE * 8),
        ('Misc', SECTION_MISC),
        ('VirtualAddress', DWORD),
        ('SizeOfRawData', DWORD),
        ('PointerToRawData', DWORD),
        ('PointerToRelocations', DWORD),
        ('PointerToLinenumbers', DWORD),
        ('NumberOfReloctions', WORD),
        ('NumberOfLinenumbers', WORD),
        ('Characteristics', DWORD),
        ]

def __test():
    pass

if __name__ == '__main__':
    __test()