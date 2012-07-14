#!/usr/bin/env python
#-*- coding=utf-8 -*-

from peresolve import *

def ResolveExportDirectory(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveExportDirectory', 'Parameter must be type "file"!')
    ExportDirectory = IMAGE_EXPORT_DIRECTORY()
    for item in ExportDirectory._fields_:
        item_name = item[0]
        item_type = __type_dic__[BYTE]
        item_cont = fobj.read(item_type)
        if item_cont == '':
            raise PEResolveError(1, 'ResolveExportDirectory', 'Read blank!', fobj.tell())
        exec('ExportDirectory.%s = %d' % (item_name, StrToCType(item_cont)))
    return ExportDirectory

def ResolveImportDescriptor(fobj):
    if type(fobj) != file:
        raise PEResolveError(0, 'ResolveImportDescriptor', 'Parameter must be type "file"!')
    ImportDescriptor = IMAGE_INPORT_DESCRIPTOR()
    for item in ImportDescriptor._fields_:
        item_name = item[0]
        if item_name == 'Characteristics':
            ImportCharacteristics = IMPORT_CHARACTERISTICS()
            ImportCharacteristics.Characteristics = StrToCType(fobj.read(DWORD))
        else:
            item_type = __type_dic__[BYTE]
            item_cont = fobj.read(item_type)
            if item_cont == '':
                raise PEResolveError(1, 'ResolveImportDescriptor', 'Read blank!', fobj.tell())
            exec('ImportDescriptor.%s = %d' % (item_name, StrToCType(item_cont)))
    return ImportDescriptor

def __test__():
    fobj = open(r'C:\Windows\System32\drivers\360netmon.sys', 'rb')
    DOSHeader = ResolveDOSHeader(fobj)
    offset_PE = DOSHeader.e_lfanew
    fobj.seek(offset_PE)
    NH = ResolveNTHeader(fobj)
    FH = NH.FileHeader
    OH = NH.OptionalHeader

if __name__ == '__main__':
    __test__()