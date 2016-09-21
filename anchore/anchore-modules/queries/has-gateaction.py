#!/usr/bin/env python

import sys
import os
import re
import traceback
import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <STOP|WARN|GO> <STOP|WARN|GO> ...\nhelp: use 'all' to show all trigger/actions")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

if 'all' in config['params']:
    config['params'] = ['STOP', 'WARN', 'GO']

outlist = list()
outlist.append(["Image_ID", "Repo_Tag", "Gate", "Trigger", "Action"])


report = anchore.anchore_utils.load_gates_eval_report(config['meta']['imageId'])
action = ""
for ge in report:
    try:
        action = ge['action']
        trigger = ge['trigger']
        gate = ge['check']
        if action == 'all' or action in config['params']:
            outlist.append([config['meta']['shortId'], config['meta']['humanname'], gate, trigger, action])
    except Exception as err:
        # bad record
        print "WARN: bad record detected: " + str(err)
        traceback.print_exc()
        
anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

sys.exit(0)
