#!/usr/bin/env python
#-*- coding=utf-8 -*-

from pestruct import *

__type_dic__ = {BYTE:1, WORD:2, DWORD:4, QWORD:8}

class PEResolveError(RuntimeError):
    def __init__(self, num, cause, message, offset = -1):
        self.num = num
        self.cause = cause
        self.message = message
        self.offset = offset
    def __str__(self):
        return '[%d]%s => %s' % (self.num, self.cause, self.message)

def ResolveDOSHeader(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveDOSHeader', 'Parameter must be type "file"!')
    DOSHeader = IMAGE_DOS_HEADER()
    for item in DOSHeader._fields_:
        item_name = item[0]
        if item_name == 'e_res':
            item_type = __type_dic__[WORD]
            for i in range(4):
                item_cont = fobj.read(item_type)
                DOSHeader.e_res[i] = StrToCType(item_cont)
        elif item_name == 'e_res2':
            item_type = __type_dic__[WORD]
            for i in range(10):
                item_cont = fobj.read(item_type)
                DOSHeader.e_res2[i] = StrToCType(item_cont)
        else:
            item_type = __type_dic__[item[1]]
            item_cont = fobj.read(item_type)
            if item_cont == '':
                raise PEResolveError(1, 'ResolveDOSHeader', 'Read blank!', fobj.tell())
            exec('DOSHeader.%s = %d' % (item_name, StrToCType(item_cont)))
    return DOSHeader

def ResolveFileHeader(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveFileHeader', 'Parameter must be type "file"!')
    FileHeader = IMAGE_FILE_HEADER()
    for item in FileHeader._fields_:
        item_name = item[0]
        item_type = __type_dic__[item[1]]
        item_cont = fobj.read(item_type)
        if item_cont == '':
            raise PEResolveError(1, 'ResolveFileHeader', 'Read blank!', fobj.tell())
        exec('FileHeader.%s = %d' % (item_name, StrToCType(item_cont)))
    return FileHeader

def ResolveDataDirectory(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveDataDirectory', 'Parameter must be type "file"!')
    DataDirectory = IMAGE_DATA_DIRECTORY()
    for item in DataDirectory._fields_:
        item_name = item[0]
        item_type = __type_dic__[item[1]]
        item_cont = fobj.read(item_type)
        if item_cont == '':
            raise PEResolveError(1, 'ResolveDataDirectory', 'Read blank!', fobj.tell())
        exec('DataDirectory.%s = %d' % (item_name, StrToCType(item_cont)))
    return DataDirectory
    
def ResolveOptionalHeader64(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveOptionalHeader64', 'Parameter must be type "file"!')
    OptionalHeader64 = IMAGE_OPTIONAL_HEADER64()
    item_cont = fobj.read(__type_dic__[WORD])
    if item_cont != '\x0b\x02':
        raise PEResolveError(3, 'ResolveOptionalHeader64', 'Not a PE64 File!', fobj.tell())
    OptionalHeader64.Magic = StrToCType(item_cont)
    for item in OptionalHeader64._fields_:
        item_name = item[0]
        if item_name == 'Magic':
            continue
        elif item_name == 'DataDirectory':
            for i in range(16):
                OptionalHeader64.DataDirectory[i] = ResolveDataDirectory(fobj)
        else:
            item_type = __type_dic__[item[1]]
            item_cont = fobj.read(item_type)
            if item_cont == '':
                raise PEResolveError(1, 'ResolveOptionalHeader64', 'Read blank!', fobj.tell())
            exec('OptionalHeader64.%s = %d' % (item_name, StrToCType(item_cont)))
    return OptionalHeader64

def ResolveOptionalHeader32(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveOptionalHeader32', 'Parameter must be type "file"!')
    OptionalHeader32 = IMAGE_OPTIONAL_HEADER32()
    item_cont = fobj.read(__type_dic__[WORD])
    if item_cont != '\x0b\x01':
        raise PEResolveError(3, 'ResolveOptionalHeader32', 'Not a PE32 File!', fobj.tell())
    OptionalHeader32.Magic = StrToCType(item_cont)
    for item in OptionalHeader32._fields_:
        item_name = item[0]
        if item_name == 'Magic':
            continue
        elif item_name == 'DataDirectory':
            for i in range(16):
                OptionalHeader32.DataDirectory[i] = ResolveDataDirectory(fobj)
        else:
            item_type = __type_dic__[item[1]]
            item_cont = fobj.read(item_type)
            if item_cont == '':
                raise PEResolveError(1, 'ResolveOptionalHeader32', 'Read blank!', fobj.tell())
            exec('OptionalHeader32.%s = %d' % (item_name, StrToCType(item_cont)))
    return OptionalHeader32
ResolveOptionalHeader = ResolveOptionalHeader32

def ResolveNTHeader64(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveNTHeader64', 'Parameter must be type "file"!')
    NTHeader64 = IMAGE_NT_HEADERS64()
    NTHeader64.Signature = StrToCType(fobj.read(__type_dic__[DWORD]))
    if NTHeader64.Signature != 0x4550:
        raise PEResolveError(2, 'ResolveNTHeader64', 'Not a PE File!', fobj.tell())
    NTHeader64.FileHeader = ResolveFileHeader(fobj)
    NTHeader64.OptionalHeader = ResolveOptionalHeader64(fobj)
    return NTHeader64

def ResolveNTHeader32(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveNTHeader32', 'Parameter must be type "file"!')
    NTHeader32 = IMAGE_NT_HEADERS32()
    NTHeader32.Signature = StrToCType(fobj.read(__type_dic__[DWORD]))
    if NTHeader32.Signature != 0x4550:
        raise PEResolveError(2, 'ResolveNTHeader32', 'Not a PE File!', fobj.tell())
    NTHeader32.FileHeader = ResolveFileHeader(fobj)
    NTHeader32.OptionalHeader = ResolveOptionalHeader32(fobj)
    return NTHeader32
ResolveNTHeader = ResolveNTHeader32

def __ResolveSectionMisc__(fobj):
    SectionMisc = SECTION_MISC()
    SectionMisc.VirtualSize = StrToCType(fobj.read(__type_dic__[DWORD]))
    return SectionMisc

def ResolveSectionHeader(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveNTHeader32', 'Parameter must be type "file"!')
    SectionHeader = IMAGE_SECTION_HEADER()
    for item in SectionHeader._fields_:
        item_name = item[0]
        if item_name == 'Misc':
            SectionHeader.Misc = __ResolveSectionMisc__(fobj)
        elif item_name == 'Name':
            for i in range(8):
                item_type = __type_dic__[BYTE]
                item_cont = fobj.read(item_type)
                if item_cont == '':
                    raise PEResolveError(1, 'ResolveSectionHeader', 'Read blank!', fobj.tell())
                SectionHeader.Name[i] = StrToCType(item_cont)
        else:
            item_type = __type_dic__[item[1]]
            item_cont = fobj.read(item_type)
            if item_cont == '':
                raise PEResolveError(1, 'ResolveSectionHeader', 'Read blank!', fobj.tell())
            exec('SectionHeader.%s = %d' % (item_name, StrToCType(item_cont)))
    return SectionHeader

def __test__():
    #fobj = open(r'd:\MyProject\PEFile\notepad.exe', 'rb')
    fobj = open(r'C:\Windows\System32\drivers\360netmon.sys', 'rb')
    DOSHeader = ResolveDOSHeader(fobj)
    offset_PE = DOSHeader.e_lfanew
    fobj.seek(offset_PE)
    NH = ResolveNTHeader(fobj)
    FH = NH.FileHeader
    OH = NH.OptionalHeader
    
    i = 0
    for DataDirectory in OH.DataDirectory:
        print('index = %d' % i)
        print('Offset => %08X' % DataDirectory.VirtualAddress)
        print('Size => %08X' % DataDirectory.Size)
        print('===================')
        i += 1
    
    #rva = OH.AddressOfEntryPoint
    #for i in range(FH.NumberOfSections):
        #SH = ResolveSectionHeader(fobj)
        #name = toBYTEs(SH.Name)
        #vo = SH.VirtualAddress
        #vs = SH.Misc.VirtualSize
        #ro = SH.PointerToRawData
        #rs = SH.SizeOfRawData
        #ch = SH.Characteristics
        #if vo < rva:
            #raw = rva - (vo - ro)
            #es = name
        #print('%s=>  %08X | %08X | %08X | %08X | %08X' % (name, vo, vs, ro, rs, ch))
    #print('RVA: %08X' % rva)
    #print('RAW: %08X' % raw)
    #print('Entry Section: %s' % es)
    fobj.close()

if __name__ == '__main__':
    __test__()