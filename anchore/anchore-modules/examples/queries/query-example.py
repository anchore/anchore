#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

# parse the commandline and set up local config
try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <package> <package> ...\nhelp: search input image(s) for specified <package> installations")
except Exception as err:
    print str(err)
    sys.exit(1)
if not config:
    sys.exit(0)

# at this point, the 'config' dict contains (minimally)
# config['name'] : name for this module
# config['imgid'] : image ID of image to be queried
# config['dirs']['datadir'] : top level directory of the anchore image data store
# config['dirs']['imgdir'] : location of the files that contain useful image information
# config['dirs']['analyzerdir'] : location of the files that contain results of the image analysis
# config['dirs']['comparedir'] : location of the files that contain comparison results between image and other images in its familytree
# config['dirs']['gatesdir'] : location of the results of the latest anchore gate evaulation
# config['params'] : any extra parameters passed in from the CLI to this module

# set up the output row array
outlist = list()

# the first value in the output array must contain column header names (no whitespace!)
outlist.append(["FullImageID", "FileName", "IsFound"])

# perform your check

# read the file that container a list of all files in the container that is a result of previous anchore analysis
allfiles = '/'.join([config['dirs']['analyzerdir'], 'file_list', 'files.all'])
    
# use helpful anchore util to read the contents of analyzer file into a dict
files = anchore.anchore_utils.read_kvfile_todict(allfiles)

# perform your check
if "./etc/passwd" in files.keys():
    outlist.append([config['imgid'], "/etc/passwd", "Yes"])
else:
    outlist.append([config['imgid'], "/etc/passwd", "No"])

# use helpful anchore util to write the resulting list to the correct location
anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

# all done!
sys.exit(0)

# To try this query:
# 1) place this example script in the queries directory (cp query-example.py $ANCHOREROOT/lib/anchore/queries/query-example)
# 2) ensure that the script is executable (chmod +x $ANCHOREROOT/lib/anchore/queries/query-example)
# 3) run the anchore query against an analyzed container (anchore explore --image centos query query-example all)
