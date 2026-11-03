#!/usr/bin/env python3

'''
config file for ctodcfuzzer
'''

import os
import sys
import tempfile
from typing import Dict


if not __package__:
    sys.path.append(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    __package__ = "ctodcfuzzer"

INPUT_DIR = 'queue'
CRASH_DIR = 'crashes'

# NOTE: you can define your own config
CONFIG: Dict = {
    # these will be default parameters for cli.py
    'scheduler': {
        'focus_time': 300,
        'coverage_update_time': 30,
        'sync_time': 300,
        'weight': 20,
        'sync_top_k': 10,
        'timeout': '86400'
    },
    # unused now
    'docker': {
        'root_dir': '/work/ctodcfuzzer',
        'network': 'ctodcfuzzer'
    },    
    'evaluator': {
        'binary_root': '',
        'binary_crash_root': '',
    },
    'score_DAFL':{
        'command' : '/fuzzer/score/afl-fuzz',
        'target_root' : '/benchmark/bin/DAFL'
    },
    'dominator':{
        'command' : '',
        'target_root' : '/benchmark/bin/Dominator'
    },
    # only specify basic things
    # how to launch fuzzers with proper arguments is handled by fuzzer driver
    'fuzzer': {
        'aflgo': {
            'input_dir': INPUT_DIR, # queue dir
            'crash_dir': CRASH_DIR,
            'command': '/fuzzer/AFLGo/afl-fuzz', # fuzzer binary path
            'target_root': '/benchmark/bin/AFLGo' # which binary is used to fuzz
        },
        'windranger': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'command': '/fuzzer/WindRanger/fuzz/afl-fuzz',
            'target_root': '/benchmark/bin/WindRanger'
        },
        'dafl': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'command': '/fuzzer/DAFL/afl-fuzz',
            'target_root': '/benchmark/bin/DAFL'
        }
    },
    # each target 
    'target': {
        'cjpeg-2018-14498': {
            'group': 'libjpeg',
            'seed': '/benchmark/seed/libjpeg',
            'args': {
                'default': '-outfile /dev/null @@',
            }
        },
        'cjpeg-2020-13790': {
            'group': 'libjpeg',
            'seed': '/benchmark/seed/libjpeg',
            'args': {
                'default': '-outfile /dev/null @@',
            }
        },
        'cxxfilt-2016-4487': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4489': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4490': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4491': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492-crash1': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492-crash2': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-6131': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            'args': {
                'default': '',
            }
        },
        'nm-2017-14940': {
            'group': 'binutils',
            'seed': '/benchmark/seed/nm-2017-14940',
            'args': {
                'default': '-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@',
            }
        },
        'objcopy-2017-8393': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objcopy-2017-8393',
            'args': {
                'default': '--compress-debug-sections @@ out',
            }
        },
        'objcopy-2017-8394': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objcopy-2017-8394',
            'args': {
                'default': '-Gs @@ out',
            }
        },
        'objcopy-2017-8395': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objcopy-2017-8395',
            'args': {
                'default': '--compress-debug-sections @@ out',
            }
        },
        'objdump-2017-8392': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8392',
            'args': {
                'default': '-SD @@',
            }
        },
        'objdump-2017-8396': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8396',
            'args': {
                'default': '-W @@',
            }
        },
        'objdump-2017-8397': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8397',
            'args': {
                'default': '-W @@',
            }
        },
        'objdump-2017-8398': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8398',
            'args': {
                'default': '-W @@',
            }
        },
        'objdump-2018-17360': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2018-17360',
            'args': {
                'default': '--dwarf-check -C -g -f -dwarf -x @@',
            }
        },
        'strip-2017-7303': {
            'group': 'binutils',
            'seed': '/benchmark/seed/strip-2017-7303',
            'args': {
                'default': '-o /dev/null @@',
            }
        },
        'lrzip-2017-8846': {
            'group': 'lrzip',
            'seed': '/benchmark/seed/lrzip-2017-8846',
            'args': {
                'default': '-m 10 -t @@',
            }
        },
        'lrzip-2018-11496': {
            'group': 'lrzip',
            'seed': '/benchmark/seed/lrzip-2018-11496',
            'args': {
                'default': '-t @@',
            }
        },
        'swftophp-2016-9827': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2016-9827',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2016-9829': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2016-9829',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2016-9831': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2016-9831',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2017-11728': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2017-11728',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2017-11729': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2017-11729',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2017-7578': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2017-7578',
            'args': {
                'default': '@@',
            }
        },'swftophp-2017-9988': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2017-9988',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-11095': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-11095',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-11225': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-11225',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-11226': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-11226',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-20427': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-20427',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-7868': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-8807',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-8807': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-8807',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-8962': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-8807',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2019-12982': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2019-12982',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2019-9114': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2019-9114',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2020-6628': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2020-6628',
            'args': {
                'default': '@@',
            }
        },
        'xmllint-2017-5969': {
            'group': 'libxml2',
            'seed': '/benchmark/seed/xmllint-2017-5969',
            'args': {
                'default': '--recover @@',
            }
        },
        'xmllint-2017-9047': {
            'group': 'libxml2',
            'seed': '/benchmark/seed/xmllint-2017-9047',
            'args': {
                'default': '--valid @@',
            }
        },
        'xmllint-2017-9048': {
            'group': 'libxml2',
            'seed': '/benchmark/seed/xmllint-2017-9048',
            'args': {
                'default': '--valid @@',
            }
        }
    }

}

# list of all fuzzers

FUZZERS = [ 'aflgo', 'windranger', 'dafl' ]

DATABASE_DIR= tempfile.mkdtemp()



