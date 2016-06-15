import json
import time

import deb_pkg_tools
import os
import sys
import re
import rpm
import subprocess
from prettytable import PrettyTable
from textwrap import fill
from deb_pkg_tools.version import Version
from rpmUtils.miscutils import splitFilename

import logging

import anchore_image
from configuration import AnchoreConfiguration

module_logger = logging.getLogger(__name__)

def init_analyzer_cmdline(argv, name):
    ret = {}

    if len(argv) < 4:
        print "ERROR: invalid input"
        raise Exception

    anchore_conf = AnchoreConfiguration()
    ret['anchore_config'] = anchore_conf.data

    ret['name'] = name
    ret['imgid'] = argv[1]

    ret['dirs'] = {}
    ret['dirs']['datadir'] = argv[2]
    ret['dirs']['outputdir'] = '/'.join([argv[3], "analyzer_output", name])
    ret['dirs']['unpackdir'] = argv[4]

    for d in ret['dirs'].keys():
        if not os.path.isdir(ret['dirs'][d]):
            try:
                os.makedirs(ret['dirs'][d])
            except Exception as err:
                print "ERROR: cannot find/create input dir '"+ret['dirs'][d]+"'"
                raise err

    return(ret)

def init_gate_cmdline(argv, paramhelp):
    return(init_query_cmdline(argv, paramhelp))

def init_query_cmdline(argv, paramhelp):
    ret = {}

    if len(argv) == 2 and re.match(".*help.*", argv[1]):
        # print argv[0].split('/')[-1]
        print paramhelp
        return (False)

    if len(argv) < 5:
        print "ERROR: invalid input"
        raise Exception

    anchore_conf = AnchoreConfiguration()
    ret['anchore_config'] = anchore_conf.data

    ret['name'] = argv[0].split('/')[-1]
    ret['imgfile'] = argv[1]

    images = read_plainfile_tolist(ret['imgfile'])
    ret['imgid'] = images[0]
    if 'imgid' not in ret:
        print "ERROR: could not read imgid from input file"
        raise Exception

    ret['images'] = images

    ret['dirs'] = {}
    ret['dirs']['datadir'] = argv[2]

    ret['dirs']['imgdir'] = '/'.join([ret['dirs']['datadir'], ret['imgid'], 'image_output'])
    ret['dirs']['analyzerdir'] = '/'.join([ret['dirs']['datadir'], ret['imgid'], 'analyzer_output'])
    ret['dirs']['comparedir'] = '/'.join([ret['dirs']['datadir'], ret['imgid'], 'compare_output'])
    ret['dirs']['gatesdir'] = '/'.join([ret['dirs']['datadir'], ret['imgid'], 'gates_output'])

    ret['dirs']['outputdir'] = argv[3]

    try:
        ret['params'] = argv[4:]
    except:
        ret['params'] = list()

    for d in ret['dirs'].keys():
        thedir = ret['dirs'][d]
        if not os.path.exists(thedir):
            raise Exception(d + " directory '" + thedir + "' does not exist.")

    metafile = '/'.join([ret['dirs']['imgdir'], 'image_info', 'image.meta'])
    if not os.path.exists(metafile):
        raise Exception("image metadata not available")


    ret['meta'] = read_kvfile_todict(metafile)
    ret['imgtags'] = ret['meta']['humanname']
    ret['output'] = '/'.join([ret['dirs']['outputdir'], ret['name']])

    return (ret)


def print_result(config, result, outputmode=None):
    if not result:
        return (False)

    if not outputmode:
        if config.cliargs['json']:
            outputmode = 'json'
        elif config.cliargs['plain']:
            outputmode = 'plaintext'
        else:
            outputmode = 'table'

    try:
        width = int(subprocess.check_output(['stty', 'size']).split()[1]) - 10
    except:
        width = 70

    if outputmode == 'json':
        print json.dumps(result)
    else:
        output = list()
        if len(result.keys()) > 0:
            sortby = False

            # this is awkward - need better way to differentiate header from results
            for i in result.keys():
                json_dict = result[i]
                sortby = False
                for h in json_dict['result']['header']:
                    if re.match(r"^\*.*", h):
                        sortby = h

                header = json_dict['result']['header']
                if outputmode == 'table':
                    t = PrettyTable(header)
                break

            emptyresult = False
            for i in result.keys():
                json_dict = result[i]

                for orow in json_dict['result']['rows']:
                    if outputmode == 'table':
                        row = [fill(x, max(12, width / (len(orow))) ) for x in orow ]
                        t.add_row(row)
                    elif outputmode == 'plaintext':
                        row = [ re.sub("\s", ",", x) for x in orow ]
                        output.append(row)
                    elif outputmode == 'raw':
                        output.append(orow)
            if outputmode == 'table':
                if sortby:
                    print t.get_string(sortby=sortby, reversesort=True)
                else:
                    print t
                print ""
            elif outputmode == 'plaintext':
                print ' '.join(header)
                print ""
                for r in output:
                    print ' '.join(r)
            elif outputmode == 'raw':
                for i in range(len(output)):
                    row = output[i]
                    for j in range(len(row)):
                        print "--- " + header[j] + " ---"
                        print output[i][j]
                        print 


    return (True)

def cve_load_data(cvedatadir, image):
    cve_data = None

    distro = image.get_distro()
    distrovers = image.get_distro_vers()

    cvejsonfile = '/'.join([cvedatadir, distro+":"+distrovers, "cve.json"])
    if os.path.exists(cvejsonfile):
        FH = open(cvejsonfile, 'r')
        cve_data = json.loads(FH.read())
        FH.close()
    return (cve_data)


def cve_scanimage(cve_data, image):
    if not cve_data:
        return ({})

    all_packages = {}
    analysis_report = image.get_analysis_report().copy()

    thelist = []
    if 'package_list' in analysis_report and 'pkgs.all' in analysis_report['package_list']:
        thelist = analysis_report['package_list']['pkgs.all']
    for l in thelist:
        l = l.strip()
        (p, v) = l.split()
        if p not in all_packages:
            all_packages[p] = v

    thelist = []
    if 'package_list' in analysis_report and 'pkgs_plus_source.all' in analysis_report['package_list']:
        thelist = analysis_report['package_list']['pkgs_plus_source.all']
    for l in thelist:
        l = l.strip()
        (p, v) = l.split()
        if p not in all_packages:
            all_packages[p] = v

    results = {}
    for v in cve_data:
        outel = {}
        vuln = v['Vulnerability']
        print "cve-scan: CVE: " + vuln['Name']
        if 'FixedIn' in vuln:
            for fixes in vuln['FixedIn']:
                isvuln = False
                vpkg = fixes['Name']
                print "cve-scan: Vulnerable Package: " + vpkg
                if vpkg in all_packages:
                    ivers = all_packages[fixes['Name']]
                    vvers = re.sub(r'^[0-9]*:', '', fixes['Version'])
                    print "cve-scan: " + vpkg + "\n\tfixed vulnerability package version: " + vvers + "\n\timage package version: " + ivers
                    if image.get_distro() == "centos" or image.get_distro() == "rhel":
                        if vvers != 'None':
                            fixfile = vpkg + "-" + vvers + ".rpm"
                            imagefile = vpkg + "-" + ivers + ".rpm"
                            (n1, v1, r1, e1, a1) = splitFilename(imagefile)
                            (n2, v2, r2, e2, a2) = splitFilename(fixfile)
                            if rpm.labelCompare(('1', v1, r1), ('1', v2, r2)) < 0:
                                isvuln = True
                        else:
                            isvuln = True

                    elif image.get_distro() == "ubuntu" or image.get_distro() == "debian":
                        if vvers != 'None':                            
                            if ivers != vvers and deb_pkg_tools.version.compare_versions(ivers, '<', vvers):
                                isvuln = True
                        else:
                            isvuln = True

                    if isvuln:
                        print "cve-scan: Found vulnerable package: " + vpkg
                        severity = url = description = 'Not Available'
                        if 'Severity' in vuln:
                            severity = vuln['Severity']
                        if 'Link' in vuln:
                            url = vuln['Link']
                        if 'Description' in vuln:
                            description = vuln['Description']
                        
                        outel = {'pkgName': vpkg, 'imageVers': ivers, 'fixVers': vvers, 'severity': severity, 'url': url, 'description': description}
                if outel:
                    results[vuln['Name']] = outel
    return (results)


def cve_get_fixpkg(cve_data, cveId):
    retlist = list()
    for v in cve_data:
        vuln = v['Vulnerability']
        if cveId == vuln['Name']:
            if 'FixedIn' in vuln:
                for p in vuln['FixedIn']:
                    retlist.append(p['Name'])
    return (retlist)

def image_context_add(imagelist, allimages, docker_cli=None, dockerfile=None, anchore_datadir=None, tmproot='/tmp', anchore_db=None, must_be_analyzed=False, usertype=None, must_load_all=False):
    retlist = list()
    for i in imagelist:
        if i in allimages:
            retlist.append(i)
        else:
            try:
                newimage = anchore_image.AnchoreImage(i, anchore_datadir, docker_cli=docker_cli, allimages=allimages, dockerfile=dockerfile, tmpdirroot=tmproot, usertype=usertype, anchore_db=anchore_db)
            except Exception as err:
                if must_load_all:
                    import traceback
                    traceback.print_exc()
                    errorstr = "Could not load/initialize all input images.\n" + "\tImage: " + str(i) + "\n\tInfo: " + str(err.message)
                    raise Exception(errorstr)

            if not must_be_analyzed or newimage.is_analyzed():
                allimages[newimage.meta['imageId']] = newimage
                retlist.append(newimage.meta['imageId'])

            if must_be_analyzed and not newimage.is_analyzed():
                errorstr = "Image(s) must be analyzed before operation can be performed.\n\tImage: " + str(i)
                raise Exception(errorstr)

            #elif must_be_analyzed and not newimage.is_analyzed():
            #    raise Exception(errorstr)
            # Check that all input images are successfully loaded
            #if must_load_all and (len(retlist) != len(imagelist)):
            #    lnames = list()
            #    for i in retlist:
            #        lnames.append(allimages[i].meta['imagename'])
            #    ldiff = list(set(imagelist) - set(lnames))
            #    raise Exception(errorstr)

    return (retlist)


def update_file_list(listbuf, outfile, backup=False):
    src = listbuf
    if not os.path.exists(outfile):
        write_plainfile_fromlist(outfile, src)
        #FH = open(outfile, 'w')
        #for l in src:
        #    FH.write(l + "\n")
        #FH.close()
    else:
        dst = read_plainfile_tolist(outfile)
        #FH = open(outfile, 'r')
        #dst = list()
        #for l in FH.readlines():
        #    l = l.strip()
        #    dst.append(l)
        #FH.close()
        if src != dst:
            if backup:
                hfile = outfile + "." + str(int(time.time()))
                os.rename(outfile, hfile)

            write_plainfile_fromlist(outfile, src)
            #FH = open(outfile, 'w')
            #for l in src:
            #    FH.write(l + "\n")
            #FH.close()

    return (True)


def update_file_jsonstr(jsonbuf, outfile, backup=False):
    src = json.loads(jsonbuf)
    if not os.path.exists(outfile):
        FH = open(outfile, 'w')
        FH.write(json.dumps(src))
        FH.close()
    else:
        FH = open(outfile, 'r')
        dst = json.loads(FH.read())
        FH.close()
        if src != dst:
            if backup:
                hfile = outfile + "." + str(int(time.time()))
                os.rename(outfile, hfile)
            FH = open(outfile, 'w')
            FH.write(json.dumps(src))
            FH.close()

    return (True)


def update_file_str(buf, outfile, backup=False):
    src = buf
    if not os.path.exists(outfile):
        write_plainfile_fromstr(outfile, src)
        #FH = open(outfile, 'w')
        #FH.write(src)
        #FH.close()
    else:
        dst = read_plainfile_tostr(outfile)
        #FH = open(outfile, 'r')
        #dst = FH.read()
        #FH.close()
        if src != dst:
            if backup:
                hfile = outfile + "." + str(int(time.time()))
                os.rename(outfile, hfile)
            write_plainfile_fromstr(outfile, src)
            #FH = open(outfile, 'w')
            #FH.write(src)
            #FH.close()

    return (True)


def write_plainfile_fromstr(file, instr):
    FH=open(file, 'w')
    thestr = instr.encode('utf8')
    FH.write(thestr)
    FH.close()

def read_plainfile_tostr(file):
    if not os.path.isfile(file):
        return ("")
    FH = open(file, 'r')
    ret = FH.read().decode('utf8')
    FH.close()
    return (ret)


def read_kvfile_tolist(file):
    if not os.path.isfile(file):
        return([])

    ret = list()
    FH=open(file, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')
        row = l.split()
        ret.append(row)
    FH.close()

    return (ret)

def read_plainfile_tolist(file):
    if not os.path.isfile(file):
        return([])

    ret = list()
    FH=open(file, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')
        ret.append(l)
    FH.close()

    return (ret)

def read_kvfile_todict(file):
    if not os.path.isfile(file):
        return ({})

    ret = {}
    FH = open(file, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')
        (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
        ret[k] = v
    FH.close()

    return (ret)

def write_plainfile_fromlist(file, list):
    OFH = open(file, 'w')
    for l in list:
        thestr = l + "\n"
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def write_kvfile_fromlist(file, list):
    OFH = open(file, 'w')
    for l in list:
        thestr = ' '.join(l) + "\n"
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def write_kvfile_fromdict(file, indict):
    dict = indict.copy()
    OFH = open(file, 'w')
    for k in dict.keys():
        if not dict[k]:
            dict[k] = "none"
        thestr = ' '.join([k, dict[k], '\n'])
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def touch_file(file):
    return(open(file, 'a').close())
