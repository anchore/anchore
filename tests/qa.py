#!/usr/bin/python

import os
import shutil
import sys
import random
import copy
import json
import re
import subprocess
import time

ts = str(int(time.time()))
outputdir = "qa."+ts
if not os.path.exists(outputdir):
    os.makedirs(outputdir)

os.putenv('ANCHOREROOT', '/root/.local/')
p = os.getenv('PATH')
os.putenv('PATH', p + ":" + '/root/.local/bin')

FH=open("anchore-commands.txt", 'r')

cmd_count = 0
for l in FH.readlines():
    l = l.strip()
    if (len(l) > 0):
        print "RUNNING COMMAND (output." + str(cmd_count) + ")"
        print "\t" + l
        rc = os.system( "(" + l + ")" + " > "+outputdir+"/output."+str(cmd_count) + " 2>&1" )
        print "\t" + str(rc)
        print ""
        if rc != 0:
            print "COMMAND FAILED - bailing : "+outputdir+"/output."+str(cmd_count)
            sys.exit(1)
        cmd_count = cmd_count + 1

FH.close()

sys.exit(0)
