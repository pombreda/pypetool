#!/usr/bin/env python
#-*- coding=utf-8 -*-

import os, re

files = os.listdir('.')
for f in files:
    if re.match('.+\.py$', f) and f != 'compile_files.py':
        try:
            exec('import %s' % f[:-3])
        except ImportError:
            print('Import module [%s] failed!' % f)
        else:
            print('Import module [%s] done!' % f)
print('All done!')
raw_input('Press key [Enter] to quit...')