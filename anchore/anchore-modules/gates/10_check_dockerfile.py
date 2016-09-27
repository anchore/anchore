#!/usr/bin/env python

import sys
import os
import json
import re
import anchore.anchore_utils

gate_name = "DOCKERFILECHECK"
triggers = {
    'EXPOSE':
    {
        'description':'triggers if this happens',
        'params':'ALLOWEDPORTS,DENIEDPORTS'
    },
    'NOFROM':
    {
        'description':'triggers if that happens',
        'params':'None'
    },
    'FROMSCRATCH':
    {
        'description':'triggers if that happens',
        'params':'None'
    },
    'NOTAG':
    {
        'description':'triggers if that happens',
        'params':'None'
    },
    'SUDO':
    {
        'description':'triggers if that happens',
        'params':'None'
    }
}

try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name, gate_help=triggers)
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    print "ERROR: could not set up environment for gate"
    sys.exit(1)

imgid = config['imgid']

outlist = list()

try:
    params = config['params']
except:
    params = None

parsed_params = {}
if params:
    for paramstr in params:
        try:
            key, val = paramstr.split("=")
            parsed_params[key] = list()
            for p in val.split(","):
                parsed_params[key].append(p)
        except:
            pass

# do something
try:
    ireport = anchore.anchore_utils.load_image_report(imgid)
    if 'dockerfile_mode' in ireport and ireport['dockerfile_mode'] == "Actual":
        if 'dockerfile_contents' in ireport:
            dockerfile_contents = ireport['dockerfile_contents']
            fromstr = None
            exposestr = None
            sudostr = None
            for line in dockerfile_contents.splitlines():
                line = line.strip()
                if re.match("^\s*FROM\s+(.*)", line):
                    fromstr = re.match("^\s*FROM\s+(.*)", line).group(1)
                elif re.match("^\s*EXPOSE\s+(.*)", line):
                    exposestr = re.match("^\s*EXPOSE\s+(.*)", line).group(1)
                elif re.match(".*sudo.*", line):
                    sudostr = line

            if fromstr:
                if fromstr.lower() == 'scratch':
                    outlist.append("FROMSCRATCH 'FROM' container is 'scratch' - ("+str(fromstr)+")")
                elif re.match("(\S+):(\S+)", fromstr):
                    repo, tag = re.match("(\S+):(\S+)", fromstr).group(1,2)
                    if tag == 'latest':
                        outlist.append("NOTAG 'FROM' container does not specify a non-latest container tag - ("+str(fromstr)+")")
                else:
                    outlist.append("NOTAG 'FROM' container does not specify a non-latest container tag - ("+str(fromstr)+")")
            else:
                outlist.append("NOFROM No 'FROM' directive in Dockerfile")

            if exposestr:
                iexpose = exposestr.split()
                if 'DENIEDPORTS' in parsed_params:
                    if 'ALL' in parsed_params['DENIEDPORTS'] and len(iexpose) > 0:
                        outlist.append("EXPOSE Dockerfile exposes network ports but policy sets DENIEDPORTS=ALL: " + str(iexpose))
                    else:
                        for p in parsed_params['DENIEDPORTS']:
                            if p in iexpose:
                                outlist.append("EXPOSE Dockerfile exposes port ("+p+") which is in policy file DENIEDPORTS list")
                            elif p+'/tcp' in iexpose:
                                outlist.append("EXPOSE Dockerfile exposes port ("+p+"/tcp) which is in policy file DENIEDPORTS list")
                            elif p+'/udp' in iexpose:
                                outlist.append("EXPOSE Dockerfile exposes port ("+p+"/udp) which is in policy file DENIEDPORTS list")
    
                if 'ALLOWEDPORTS' in parsed_params:
                    if 'NONE' in parsed_params['ALLOWEDPORTS'] and len(iexpose) > 0:
                        outlist.append("EXPOSE Dockerfile exposes network ports but policy sets ALLOWEDPORTS=NONE: " + str(iexpose))
                    else:
                        for p in parsed_params['ALLOWEDPORTS']:
                            done=False
                            while not done:
                                try:
                                    iexpose.remove(p)
                                    done=False
                                except:
                                    done=True

                                try:
                                    iexpose.remove(p+'/tcp')
                                    done=False
                                except:
                                    done=True

                                try:
                                    iexpose.remove(p+'/udp')
                                    done=False
                                except:
                                    done=True

                        for ip in iexpose:
                            outlist.append("EXPOSE Dockerfile exposes port ("+ip+") which is not in policy file ALLOWEDPORTS list")

            if sudostr:
                outlist.append("SUDO Dockerfile contains a 'sudo' command: " + str(sudostr))

except Exception as err:
    outlist.append(gate_name + " gate failed to run with exception: " + str(err))
    #exit(1)

# write output
anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)

sys.exit(0)
