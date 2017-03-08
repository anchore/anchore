#!/usr/bin/env python

import sys
import os
import re
import traceback
import json 

import anchore.anchore_utils

def walktree(last, indict, maxlevel, currlevel):
    ret = {}

    if currlevel < maxlevel:
        c = 0
        for k in indict.keys():
            if k != 'count':
                c += indict[k]['count']
        
        if currlevel == maxlevel-1 or len(indict.keys()) == 1:
            ret[last] = str(c)

        for k in indict.keys():
            if k != 'count':
                f = re.sub("^/*", "/", last + "/" + k)
                ret.update(walktree(f, indict[k], maxlevel, currlevel + 1))

    return(ret)

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <all|directory depth> <path prefix> <base|compare image ID> exclude=</some/path> exclude=</some/other/path> ...\nhelp: <directory depth> parameter is the depth of the directory search - (default is 'all').  <path prefix> will filter any result that does not begin with the supplied prefix (default is '/').  <base|compare image ID> is either 'base' or a specific image ID that will be used to compare against (default is 'base').  exclude=</some/path> will filter out any result that begins with </some/path> and can be supplied multiple times.")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: <packageA> <packageB> ..."

tags = "none"
if config['meta']['humanname']:
    tags = config['meta']['humanname']

excludes = []
params = []
prefix = None
# first strip out the exclude= options
for p in config['params']:
    try:
        (key, value) = p.split('=')
        if key == 'exclude':
            excludes.append(value)
        else:
            params.append(p)
    except:
        params.append(p)

try:
    depth=params[0]
    if depth == 'all':
        depth=99999999
    else:
        depth=int(depth)
except:
    depth = 99999999

try:
    prefix = params[1]
except:
    prefix = '/'

allimages = {}
image = anchore.anchore_image.AnchoreImage(config['imgid'], allimages=allimages)

try:
    compareto = params[2]
    if compareto == 'base':
        compareto = image.get_earliest_base()
except:
    compareto = image.get_earliest_base()

compareimage = anchore.anchore_image.AnchoreImage(compareto, allimages=allimages)

outlist = list()
outlist.append(["Image_Id", "Repo_Tags", "Compare_Image_Id", "Compare_Repo_Tags", "File/Directory_Name"])

try:
    # handle the good case, something is found resulting in data matching the required columns
    nonpkgfilesdict = anchore.anchore_utils.load_analysis_output(config['imgid'], 'file_list', 'files.nonpkged')

    cnonpkgfilesdict = anchore.anchore_utils.load_analysis_output(compareimage.meta['imageId'], 'file_list', 'files.nonpkged')
    notfoundfiles = list(set(nonpkgfilesdict.keys()) - set(cnonpkgfilesdict.keys()))

    maxdepth = 1
    output = {}

    for f in notfoundfiles:
        
        efound = False
        for e in excludes:
            if re.match("^"+e, f):
                efound = True

        if efound:
            continue

        efound = False
        if not re.match("^"+prefix, f):
            efound = True
        
        if efound:
            continue
            
        lastref = output
        for tok in f.split('/'):
            if tok:
                if tok not in lastref:
                    lastref[tok] = {}
                    lastref[tok]['count'] = 1
                    maxdepth += 1
                else:
                    lastref[tok]['count'] += 1
                lastref = lastref[tok]

    o = walktree('/', output, depth, 0)
    for item in o.keys():
        outlist.append([config['meta']['shortId'], tags, compareimage.meta['shortId'], compareimage.get_human_name(), item])

except Exception as err:
    print "ERROR: " + str(err)
    import traceback
    traceback.print_exc()
    # handle the case where something wrong happened
    #outlist.append(["UNKNOWN", "UNKNOWN", "UNKNOWN"])

# handle the no match case
if len(outlist) < 1:
    #outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

sys.exit(0)

    
