#!/usr/bin/env python
#-*- coding=utf-8 -*-

from pestruct import *

class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ('Characteristics', DWORD),
        ('TimeDateStamp', DWORD),
        ('MagorVersion', WORD),
        ('MinorVersion', WORD),
        ('Name', DWORD),
        ('Base', DWORD),
        ('NumberOfFunctions', DWORD),
        ('NumberOfNames', DWORD),
        ('AddressOfFunctions', DWORD),
        ('AddressOfNames', DWORD),
        ('AddressOfNameOrdinals', DWORD),
        ]

class IMPORT_CHARACTERISTICS(Union):
    _fields_ = [
        ('Characteristics', DWORD),
        ('OriginalFirstThunk', DWORD),
        ]
class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [
        ('Characteristics', IMPORT_CHARACTERISTICS),
        ('TimeDateStamp', DWORD),
        ('ForwarderChain', DWORD),
        ('Name', DWORD),
        ('FirstThunk', DWORD),
        ]

class IMAGE_RESOURCE_DIRECTORY(Structure):
    _fields_ = [
        ('Characteristics', DWORD),
        ('TimeDateStamp', DWORD),
        ('MajorVersion', WORD),
        ('MinorVersion', WORD),
        ('NumberOfNamedEnteries', WORD),
        ('NumberOfIdEntries', WORD),
        ]