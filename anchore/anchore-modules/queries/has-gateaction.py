#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <STOP|WARN|GO> ...\nhelp: use 'all' to show all gateactions")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

if 'all' in config['params']:
    config['params'] = ['STOP', 'WARN', 'GO']

OFH=open(config['output'], 'w')
OFH.write("ImageID Repo/Tag Gate Trigger Action\n")

try:
    gfiles = os.listdir(config['dirs']['gatesdir'])
    for g in gfiles:
        gatefile = '/'.join([config['dirs']['gatesdir'], g])
        patt = re.match("(.*)\.eval$", g)
        if not patt:
            continue

        gate = patt.group(1)
        triggers = {}
        FH=open(gatefile, 'r')
        for l in FH.readlines():
            l = l.strip()
            (trigger, action) = re.match('(\S*)\s*(.*)', l).group(1, 2)

            if trigger != 'FINAL':
                continue

            if action in config['params'] and trigger not in triggers:
                OFH.write(config['meta']['shortId'] + " " + config['meta']['humanname'] + " " + gate + " " + trigger + " " + action + "\n")
                triggers[trigger] = action
                hascontent=True
        FH.close()
    if not hascontent:
        pass
except:
    pass

OFH.close()
sys.exit(0)
