import json
import yaml
import time

import os
import shutil
import sys
import re
import rpm
import subprocess
import docker
import io
import tarfile
import urllib

from stat import *
from prettytable import PrettyTable
from textwrap import fill
from rpmUtils.miscutils import splitFilename

import logging

import anchore_image, anchore_image_db
from configuration import AnchoreConfiguration
from anchore.util import contexts, scripting
import anchore_auth

module_logger = logging.getLogger(__name__)

def init_analyzer_cmdline(argv, name):
    ret = {}

    if len(argv) < 4:
        print "ERROR: invalid input"
        raise Exception

    anchore_conf = AnchoreConfiguration()
    anchore_common_context_setup(anchore_conf)


    ret['analyzer_config'] = None
    anchore_analyzer_configfile = '/'.join([anchore_conf.config_dir, 'analyzer_config.yaml'])
    if os.path.exists(anchore_analyzer_configfile):
        with open(anchore_analyzer_configfile, 'r') as FH:
            anchore_analyzer_config = yaml.safe_load(FH.read())

        if anchore_analyzer_config and name in anchore_analyzer_config:
            ret['analyzer_config'] = anchore_analyzer_config[name]

    ret['anchore_config'] = anchore_conf.data

    ret['name'] = name
    import hashlib
    FH=open(argv[0], 'r')
    ret['selfcsum'] = hashlib.md5(FH.read()).hexdigest()
    FH.close()
    ret['imgid'] = argv[1]

    fullid = discover_imageId(argv[1])
    if len(fullid.keys()) > 0:
        ret['imgid_full'] = fullid.keys()[0]
    else:
        ret['imgid_full'] = ret['imgid']

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

def init_gate_cmdline(argv, gate_name, gate_help={}):
    if len(argv) > 2 and argv[2] == 'anchore_get_help':
        if gate_help:
            thefile = os.path.join(argv[1], gate_name + ".help")
            update_file_jsonstr(json.dumps(gate_help), thefile)
        sys.exit(0)
        
    ret = init_query_cmdline(argv, gate_name)
    return(ret)

def init_query_cmdline(argv, paramhelp):
    ret = {}

    if len(argv) == 2 and re.match(".*help.*", argv[1]):
        print paramhelp
        return (False)

    if len(argv) < 5:
        print "ERROR: invalid input"
        raise Exception

    anchore_conf = AnchoreConfiguration()
    anchore_common_context_setup(anchore_conf)

    ret['anchore_config'] = anchore_conf.data

    ret['name'] = argv[0].split('/')[-1]
    ret['imgfile'] = argv[1]

    images = read_plainfile_tolist(ret['imgfile'])
    ret['imgid'] = images[0]
    if 'imgid' not in ret:
        print "ERROR: could not read imgid from input file"
        raise Exception

    ret['image_report'] = contexts['anchore_db'].load_image_report(ret['imgid'])

    ret['images'] = images

    ret['dirs'] = {}
    ret['dirs']['datadir'] = argv[2]

    ret['dirs']['imgdir'] = '/'.join([ret['dirs']['datadir'], ret['imgid'], 'image_output'])
    ret['dirs']['analyzerdir'] = '/'.join([ret['dirs']['datadir'], ret['imgid'], 'analyzer_output'])
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

    ret['meta'] = ret['image_report']['meta']
    ret['baseid'] = ret['image_report']['familytree'][0]

    ret['imgtags'] = ret['meta']['humanname']
    ret['output'] = '/'.join([ret['dirs']['outputdir'], ret['name']])
    ret['output_warns'] = '/'.join([ret['dirs']['outputdir'], ret['name']+".WARNS"])

    return (ret)

def anchore_common_context_setup(config):
    if 'docker_cli' not in contexts or not contexts['docker_cli']:

        dimages = {}
        try:
            contexts['docker_cli'] = docker.Client(base_url=config['docker_conn'], timeout=int(config['docker_conn_timeout']))
            testconn = contexts['docker_cli'].version()
            docker_images = contexts['docker_cli'].images(all=True)
            for i in docker_images:
                if 'Id' in i:
                    Id = re.sub("sha256:", "", i['Id'])
                    dimages[Id] = i
                    
        except Exception as err:
            contexts['docker_cli']=None

        contexts['docker_images'] = dimages

    if 'anchore_allimages' not in contexts or not contexts['anchore_allimages']:
        contexts['anchore_allimages'] = {}

    if 'anchore_db' not in contexts or not contexts['anchore_db']:
        contexts['anchore_db'] = anchore_image_db.AnchoreImageDB(imagerootdir=config['image_data_store'])

    if 'anchore_auth' not in contexts or not contexts['anchore_auth']:
        aafile = os.path.join(config['anchore_data_dir'], "conf", "anchore_auth.json")
        username = config.DEFAULT_ANON_ANCHORE_USERNAME
        password = config.DEFAULT_ANON_ANCHORE_PASSWORD
        if os.path.exists(aafile):
            try:
                with open(aafile, 'r') as FH:
                    aa = json.loads(FH.read())
                    username = aa['username']
                    password = aa['password']
            except:
                pass
                
        contexts['anchore_auth'] = anchore_auth.anchore_auth_init(username, password, aafile, config['anchore_client_url'], config['anchore_token_url'], config['anchore_auth_conn_timeout'], config['anchore_auth_max_retries'])

    if 'anchore_config' not in contexts or not contexts['anchore_config']:
        contexts['anchore_config'] = config

    return(True)

# anchoreDB pass through functions

def save_gate_output(imageId, gate_name, data):
    return(contexts['anchore_db'].save_gate_output(imageId, gate_name, data))

def save_gate_help_output(gate_help):
    return(contexts['anchore_db'].save_gate_help_output(gate_help))

def save_analysis_output(imageId, module_name, module_value, data, module_type=None):
    return(contexts['anchore_db'].save_analysis_output(imageId, module_name, module_value, data, module_type=module_type))


def load_analysis_output(imageId, module_name, module_value):
    ret = {}
    ret = contexts['anchore_db'].load_analysis_output(imageId, module_name, module_value, module_type='user')
    if ret: return(ret)
    ret = contexts['anchore_db'].load_analysis_output(imageId, module_name, module_value, module_type='extra')
    if ret: return(ret)
    ret = contexts['anchore_db'].load_analysis_output(imageId, module_name, module_value)
    if ret: return(ret)
    #return(contexts['anchore_db'].load_analysis_output(imageId, module_name, module_value))
    return(ret)

def load_gate_output(imageId, gate_name):
    return(contexts['anchore_db'].load_gate_report(imageId, gate_name))


def load_image_report(imageId):
    return(contexts['anchore_db'].load_image_report(imageId))

def load_analysis_report(imageId):
    return(contexts['anchore_db'].load_analysis_report(imageId))

def load_gates_report(imageId):
    return(contexts['anchore_db'].load_gates_report(imageId))

def load_gates_eval_report(imageId):
    return(contexts['anchore_db'].load_gates_eval_report(imageId))


def list_analysis_outputs(imageId):
    return(contexts['anchore_db'].list_analysis_outputs(imageId))

def load_analyzer_manifest(imageId):
    return(contexts['anchore_db'].load_analyzer_manifest(imageId))


def load_image(imageId):
    return(contexts['anchore_db'].load_image(imageId))

def load_all_images():
    return(contexts['anchore_db'].load_all_images())


def is_image_analyzed(imageId):
    return(contexts['anchore_db'].is_image_analyzed(imageId))

def is_image_present(imageId, imagelist=None):
    return(contexts['anchore_db'].is_image_present(imageId, imagelist))


def get_image_list():
    return(contexts['anchore_db'].get_image_list())

def delete_image(imageId):
    return(contexts['anchore_db'].delete_image(imageId))


def make_anchoretmpdir(tmproot):
    import random
    tmpdir = '/'.join([tmproot, str(random.randint(0, 9999999)) + ".anchoretmp"])
    try:
        os.makedirs(tmpdir)
        return(tmpdir)
    except:
        return(False)

def discover_gates():
    config = contexts['anchore_config']
    ret = {}

    gatesdir = '/'.join([config["scripts_dir"], "gates"])
    outputdir = make_anchoretmpdir(config['tmpdir'])

    path_overrides = ['/'.join([config['user_scripts_dir'], 'gates'])]
    if config['extra_scripts_dir']:
        path_overrides = path_overrides + ['/'.join([config['extra_scripts_dir'], 'gates'])]

    try:
        results = scripting.ScriptSetExecutor(path=gatesdir, path_overrides=path_overrides).execute(capture_output=True, fail_fast=True, cmdline=' '.join([outputdir, 'anchore_get_help']))
    except Exception as err:
        pass

    # walk through outputdir looking for dropped help output
    allhelp = {}
    for d in os.listdir(outputdir):
        gate_name = None
        match = re.match("(.*)\.help", d)
        if match:
            gate_name = match.group(1)
        if gate_name:
            helpfile = os.path.join(outputdir, d)
            with open(helpfile, 'r') as FH:
                helpdata = json.loads(FH.read())
            allhelp[gate_name] = helpdata

    shutil.rmtree(outputdir)

    save_gate_help_output(allhelp)

    return(allhelp)

def discover_from_info(dockerfile_contents):
    fromline = fromid = None
    fromline = re.match(".*FROM\s+(\S+).*", dockerfile_contents).group(1)
    if fromline:
        fromline = fromline.lower()
        if re.match("scratch", fromline) or re.match(".*<unknown>.*", fromline):
            fromid = fromline
        else:
            try:
                fromid = discover_imageId(fromline).keys()[0]
            except:
                fromid = None
    return(fromline, fromid)

def get_imageIds_named(name):
    ret = list()
    for result in contexts['anchore_db'].load_all_images_iter():
        imageId = result[0]
        image = result[1]
        if name == imageId:
            ret.append(imageId)
        elif re.match("^"+name, imageId):
            ret.append(imageId)
        elif name in image['anchore_all_tags'] + image['anchore_current_tags'] or name+":latest" in image['anchore_all_tags'] + image['anchore_current_tags']:
            ret.append(imageId)

    return(ret)

def discover_imageIds(namelist):
    ret = {}
    
    for name in namelist:
        result = discover_imageId(name)
        ret.update(result)

    return(ret)

def discover_imageId(name):

    ret = {}

    # method -
    # 1) check if 'name' is in docker images list (key == imageId)
    # 2) check if 'name' or 'name:latest' is in docker images list repo/tags
    # 3) check anchoreDB
    # 4) check docker_inspect

    imageId = None
    try:

        iname = re.sub("sha256:", "", name)
        for dimageId in contexts['docker_images'].keys():
            i = contexts['docker_images'][dimageId]
            if iname == i['Id'] or iname == re.sub("sha256:", "", i['Id']):
                imageId = re.sub("sha256:", "", i['Id'])
                repotags = i['RepoTags']
                break
            elif 'RepoTags' in i and i['RepoTags']:
                for r in i['RepoTags']:
                    if name == r or name+":latest" == r:
                        imageId = re.sub("sha256:", "", i['Id'])
                        repotags = i['RepoTags']
                        break

        if imageId:
            repos = []
            if repotags:
                for r in repotags:
                    repos.append(r)

            ret[imageId] = repos

        if not imageId:
            aimage = contexts['anchore_db'].load_image(name)
            if aimage:
                imageId = name
                ret[imageId] = aimage.pop('anchore_all_tags', [])

        if not imageId:
            ilist = get_imageIds_named(name)
            if len(ilist) == 1:
                imageId = ilist[0]
                aimage = contexts['anchore_db'].load_image(imageId)
                ret[imageId] = aimage.pop('anchore_all_tags', [])
            elif len(ilist) > 1:
                raise ValueError("Input image name '"+str(name)+"' is ambiguous in anchore:\n\tmatching imageIds: " + str(ilist))

        if not imageId:
            docker_cli = contexts['docker_cli']
            if docker_cli:
                try:
                    docker_data = docker_cli.inspect_image(name)
                    imageId = re.sub("sha256:", "", docker_data['Id'])
                    repos = []
                    for r in docker_data['RepoTags']:
                        repos.append(r)
                    ret[imageId] = repos
                except Exception as err:
                    pass
                    
    except ValueError as err:
        raise err

    except Exception as err:
        raise err

    if len(ret.keys()) <= 0:
        raise ValueError("Input image name '"+str(name)+"' not found in local dockerhost or anchore DB.")

    return(ret)

def print_result(config, result, outputmode=None):
    if not result:
        return (False)

    if not outputmode:
        if config.cliargs['json']:
            outputmode = 'json'
        elif config.cliargs['plain']:
            outputmode = 'plaintext'
        elif config.cliargs['html']:
            outputmode = 'table'
            tablemode = 'html'
        else:
            outputmode = 'table'
            tablemode = 'stdout'


    if outputmode == 'table' and tablemode == 'stdout':
        try:
            width = int(subprocess.check_output(['stty', 'size']).split()[1]) - 10
        except:
            width = 70
    else:
        width = 9999999

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

                header = json_dict['result']['header']
                if outputmode == 'table':
                    header = [ re.sub("_", " ", x.encode('utf8')) for x in header ]
                    t = PrettyTable(header)
                    t.align = 'l'

                for h in header:
                    if re.match(r"^\*.*", h):
                        sortby = h

                break

            emptyresult = False
            for i in result.keys():
                json_dict = result[i]

                for orow in json_dict['result']['rows']:
                    if outputmode == 'table':
                        row = [ fill(x, max(12, width / (len(orow))) ).encode('utf8') for x in orow ]
                        t.add_row(row)
                    elif outputmode == 'plaintext':
                        row = [ re.sub("\s", ",", x.encode('utf8')) for x in orow ]
                        output.append(row)
                    elif outputmode == 'raw':
                        output.append(orow)

#            if outputmode == 'table' and tablemode == 'html':
#                print "<HTML><BODY>"

            if outputmode == 'table':
                if sortby:
                    if tablemode == 'stdout':
                        print t.get_string(sortby=sortby, reversesort=True)
                    elif tablemode == 'html':
                        print t.get_html_string(sortby=sortby, reversesort=True).encode('utf8')
                else:
                    if tablemode == 'stdout':
                        print t
                    elif tablemode == 'html':
                        print t.get_html_string().encode('utf8')
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

        for k in result.keys():
            if 'warns' in result[k]:
                if outputmode == 'table':
                    t = PrettyTable(['WarningOutput'])
                    t.align = 'l'
                    for warn in result[k]['warns']:
                        t.add_row([warn])
                    
                    if tablemode == 'stdout':
                        print t
                    elif tablemode == 'html':
                        print "<BR></BR>"
                        print t.get_html_string()
                if outputmode == 'plaintext':
                    print "\nWarning Output\n"
                    for warn in result[k]['warns']:
                        print str(warn)
                if outputmode == 'raw':
                    pass

#        if outputmode == 'table' and tablemode == 'html':
#            print "</BODY></HTML>"
    return (True)

def apkg_get_all_pkgfiles(unpackdir):
    apkdb = '/'.join([unpackdir, 'rootfs/lib/apk/db/installed'])
    if not os.path.exists(apkdb):
        raise ValueError("cannot locate APK installed DB '"+str(apkdb)+"'")
        
    apkgs = {}                
    apkg = {
        'version':"NA",
        'sourcepkg':"NA",
        'release':"NA",
        'origin':"NA",
        'arch':"NA",
        'license':"NA",
        'size':"NA"
    }
    thename = ""
    thepath = ""
    thefiles = list()
    allfiles = list()

    FH=open(apkdb, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')

        if not l:
            apkgs[thename] = apkg
            if thepath:
                flist = list()
                for x in thefiles:
                    flist.append(os.path.join(thepath, x))
                flist.append(os.path.join(thepath))
                allfiles = allfiles + flist
            apkgs[thename]['files'] = allfiles
            apkg = {
                'version':"NA",
                'sourcepkg':"NA",
                'release':"NA",
                'origin':"NA",
                'arch':"NA",
                'license':"NA",
                'size':"NA",
                'type':"APKG"
            }
            allfiles = list()
            thefiles = list()
            thepath = ""

        patt = re.match("(\S):(.*)", l)
        if patt:
            (k, v) = patt.group(1,2)
            apkg['type'] = "APKG"
            if k == 'P':
                thename = v
                apkg['name'] = v
            elif k == 'V':
                (vers, rel) = re.match("(\S*)-(\S*)", v).group(1, 2)
                apkg['version'] = vers
                apkg['release'] = rel
            elif k == 'm':
                apkg['origin'] = v
            elif k == 'I':
                apkg['size'] = v
            elif k == 'L':
                apkg['license'] = v
            elif k == 'o':
                apkg['sourcepkg'] = v
            elif k == 'A':
                apkg['arch'] = v
            elif k == 'F':
                if thepath:
                    flist = list()
                    for x in thefiles:
                        flist.append(os.path.join(thepath, x))
                    flist.append(os.path.join(thepath))
                    allfiles = allfiles + flist

                thepath = "/" + v
                thefiles = list()
            elif k == 'R':
                thefiles.append(v)

    FH.close()
    return(apkgs)

def dpkg_compare_versions(v1, op, v2):
    cmd = ['dpkg', '--compare-versions', v1, op, v2]
    return(subprocess.call(cmd))

def dpkg_get_all_packages(unpackdir):
    actual_packages = {}
    all_packages = {}
    other_packages = {}
    cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-W", "-f="+"${Package} ${Version} ${source:Package} ${source:Version} ${Architecture}\\n"]
    try:
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines(True):
            l = l.strip()
            l = l.decode('utf8')
            (p, v, sp, sv, arch) = re.match('(\S*)\s*(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4, 5)
            if p and v:
                if p not in actual_packages:
                    actual_packages[p] = {'version':v, 'arch':arch}
                if p not in all_packages:
                    all_packages[p] = {'version':v, 'arch':arch}
            if sp and sv:
                if sp not in all_packages:
                    all_packages[sp] = {'version':sv, 'arch':arch}
            if p and v and sp and sv:
                if p == sp and v != sv:
                    other_packages[p] = [{'version':sv, 'arch':arch}]

    except Exception as err:
        print "Could not run command: " + str(cmd)
        print "Exception: " + str(err)
        print "Please ensure the command 'dpkg' is available and try again"
        raise err

    ret = (all_packages, actual_packages, other_packages)
    return(ret)

def dpkg_get_all_pkgfiles(unpackdir):
    allfiles = {}

    try:
        (allpkgs, actpkgs, othpkgs) = dpkg_get_all_packages(unpackdir)    
        cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-L"] + actpkgs.keys()
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines():
            l = l.strip()
            l = l.decode('utf8')
            allfiles[l] = True
            
    except Exception as err:
        print "Could not run command: " + str(' '.join(cmd))
        print "Exception: " + str(err)
        print "Please ensure the command 'dpkg' is available and try again"
        raise err

    return(allfiles)

def rpm_get_all_packages(unpackdir):
    rpms = {}
    try:
        rpm.addMacro("_dbpath", unpackdir + "/rootfs/var/lib/rpm")
        ts = rpm.TransactionSet()
        mi = ts.dbMatch()
        if mi.count() == 0:
            raise Exception
        for h in mi:
            rpms[h['name']] = {'version':h['version'], 'release':h['release'], 'arch':h['arch']}
    except:
        try:
            sout = subprocess.check_output(['chroot', unpackdir + '/rootfs', 'rpm', '--queryformat', '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n', '-qa'])
            for l in sout.splitlines():
                l = l.strip()
                l = l.decode('utf8')
                (name, vers, rel, arch) = re.match('(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4)
                rpms[name] = {'version':vers, 'release':rel, 'arch':arch}
        except:
            raise ValueError("could not get package list from RPM database: " + str(err))

    return(rpms)

def rpm_get_all_pkgfiles(unpackdir):
    rpmfiles = {}

    try:
        rpm.addMacro("_dbpath", unpackdir + "/rootfs/var/lib/rpm")
        ts = rpm.TransactionSet()
        mi = ts.dbMatch()
        
        rpmfiles = {}
        for h in mi:
            fs = h['FILENAMES']
            for f in fs:
                rpmfiles[f] = h['name']
    except:
        try:
            sout = subprocess.check_output(['chroot', unpackdir + '/rootfs', 'rpm', '-qal'])
            for l in sout.splitlines():
                l = l.strip()
                l = l.decode('utf8')
                rpmfiles[l] = True
        except Exception as err:
            raise ValueError("could not get file list from RPM database: " + str(err))

    return(rpmfiles)

def get_distro_from_path(inpath):

    meta = {
        'DISTRO':None,
        'DISTROVERS':None,
        'LIKEDISTRO':None
    }

    if os.path.exists('/'.join([inpath,"/etc/os-release"])):
        FH=open('/'.join([inpath,"/etc/os-release"]), 'r')
        for l in FH.readlines():
            l = l.strip()
            l = l.decode('utf8')
            try:
                (key, val) = l.split("=")
                val = re.sub(r'"', '', val)
                if key == "ID":
                    meta['DISTRO'] = val
                elif key == "VERSION_ID":
                    meta['DISTROVERS'] = val
                elif key == "ID_LIKE":
                    meta['LIKEDISTRO'] = ','.join(val.split())
            except:
                a=1
        FH.close()
    elif os.path.exists('/'.join([inpath, "/etc/system-release-cpe"])):
        FH=open('/'.join([inpath, "/etc/system-release-cpe"]), 'r')
        for l in FH.readlines():
            l = l.strip()
            l = l.decode('utf8')
            try:
                distro = l.split(':')[2]
                vers = l.split(':')[4]
                meta['DISTRO'] = distro
                meta['DISTROVERS'] = vers
            except:
                pass
        FH.close()
    elif os.path.exists('/'.join([inpath, "/bin/busybox"])):
        meta['DISTRO'] = "busybox"
        try:
            sout = subprocess.check_output(['/'.join([inpath, "/bin/busybox"])])
            fline = sout.splitlines(True)[0]
            slist = fline.split()
            meta['DISTROVERS'] = slist[1]
        except:
            meta['DISTROVERS'] = "0"
    elif os.path.exists('/'.join([inpath, "/etc/debian_version"])):
        with open('/'.join([inpath, "/etc/debian_version"]), 'r') as FH:
            meta['DISTRO'] = 'debian'
            for line in FH.readlines():
                line = line.strip()
                patt = re.match("(\d+)\..*", line)
                if patt:
                    meta['DISTROVERS'] = patt.group(1)

    if not meta['DISTRO']:
        meta['DISTRO'] = "Unknown"
    if not meta['DISTROVERS']:
        meta['DISTROVERS'] = "0"
    if not meta['LIKEDISTRO']:
        meta['LIKEDISTRO'] = meta['DISTRO']

    return(meta)

def get_distro_flavor(distro, version, likedistro=None):
    ret = {
        'flavor':'Unknown',
        'version':'0',
        'fullversion':version,
        'distro':distro,
        'likedistro':distro,
        'likeversion':version
    }

    if distro in ['centos', 'rhel']:
        ret['flavor'] = "RHEL"
        ret['likedistro'] = 'centos'
    elif distro in ['debian', 'ubuntu']:
        ret['flavor'] = "DEB"
    elif distro in ['busybox']:
        ret['flavor'] = "BUSYB"
    elif distro in ['alpine']:
        ret['flavor'] = "ALPINE"
    elif distro in ['ol']:
        ret['flavor'] = "RHEL"
        ret['likedistro'] = 'centos'

    if ret['flavor'] == 'Unknown' and likedistro:
        for distro in likedistro:
            if distro in ['centos', 'rhel']:
                ret['flavor'] = "RHEL"
                ret['likedistro'] = 'centos'
            elif distro in ['debian', 'ubuntu']:
                ret['flavor'] = "DEB"
            elif distro in ['busybox']:
                ret['flavor'] = "BUSYB"
            elif distro in ['alpine']:
                ret['flavor'] = "ALPINE"
            elif distro in ['ol']:
                ret['flavor'] = "RHEL"
                ret['likedistro'] = 'centos'

            if ret['flavor'] != 'Unknown':
                break

    (vmaj, vmin) = re.match("(\d*)\.*(\d*)", version).group(1,2)
    if vmaj:
        ret['version'] = vmaj
        ret['likeversion'] = vmaj

    return(ret)

def cve_load_data(image, cve_data_context=None):
    import anchore_feeds
    cve_data = None

    idistro = image.get_distro()
    idistrovers = image.get_distro_vers()

    distrodict = get_distro_flavor(idistro, idistrovers)

    distro = distrodict['distro']
    distrovers = distrodict['version']
    likedistro = distrodict['likedistro']
    likeversion = distrodict['likeversion']
    fulldistro = distrodict['distro']
    fullversion = distrodict['fullversion']
    
    distrolist = [(distro,distrovers), (likedistro, likeversion), (fulldistro, fullversion)]
    for f in distrolist:
        dstr = ':'.join([f[0], f[1]])
        if cve_data_context and dstr in cve_data_context:
            cve_data = cve_data_context[dstr]
            break
        else:
            feeddata = anchore_feeds.load_anchore_feed('vulnerabilities', ':'.join([f[0], f[1]]))
            if feeddata['success']:
                cve_data = feeddata['data']
                if cve_data_context != None and dstr not in cve_data_context:
                    cve_data_context[dstr] = cve_data
                break

    if not cve_data:
        raise ValueError("cannot find CVE data associated with the input container distro: ("+str(distrolist)+")")

    return (cve_data)

def cve_scanimage(cve_data, image):
    if not cve_data:
        return ({})

    #all_packages = {}
    #analysis_report = image.get_analysis_report().copy()

    all_packages = load_analysis_output(image.meta['imageId'], 'package_list', 'pkgs.all')
    pkgsplussource = load_analysis_output(image.meta['imageId'], 'package_list', 'pkgs_plus_source.all')

    idistro = image.get_distro()
    idistrovers = image.get_distro_vers()

    distrodict = get_distro_flavor(idistro, idistrovers)

    flavor = distrodict['flavor']

    for p in pkgsplussource.keys():
        if p not in all_packages:
            all_packages[p] = pkgsplussource[p]

    results = {}
    for v in cve_data:
        outel = {}
        vuln = v['Vulnerability']
        #print "cve-scan: CVE: " + vuln['Name']
        if 'FixedIn' in vuln:
            for fixes in vuln['FixedIn']:
                isvuln = False
                vpkg = fixes['Name']
                #print "cve-scan: Vulnerable Package: " + vpkg
                if vpkg in all_packages:
                    ivers = all_packages[fixes['Name']]
                    vvers = re.sub(r'^[0-9]*:', '', fixes['Version'])
                    #print "cve-scan: " + vpkg + "\n\tfixed vulnerability package version: " + vvers + "\n\timage package version: " + ivers

                    if flavor == 'RHEL':
                        if vvers != 'None':
                            fixfile = vpkg + "-" + vvers + ".arch.rpm"
                            imagefile = vpkg + "-" + ivers + ".arch.rpm"
                            (n1, v1, r1, e1, a1) = splitFilename(imagefile)
                            (n2, v2, r2, e2, a2) = splitFilename(fixfile)
                            if rpm.labelCompare(('1', v1, r1), ('1', v2, r2)) < 0:
                                isvuln = True
                        else:
                            isvuln = True

                    elif flavor == 'DEB':
                        if vvers != 'None':
                            if ivers != vvers:
                                comp_rc = dpkg_compare_versions(ivers, 'lt', vvers)
                                if comp_rc == 0:
                                    isvuln = True
                        else:
                            isvuln = True

                    if isvuln:
                        #print "cve-scan: Found vulnerable package: " + vpkg
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

def image_context_add(imagelist, allimages, docker_cli=None, dockerfile=None, anchore_datadir=None, tmproot='/tmp', anchore_db=None, docker_images=None, must_be_analyzed=False, usertype=None, must_load_all=False):
    retlist = list()
    for i in imagelist:
        if i in allimages:
            retlist.append(i)
        elif must_be_analyzed and not anchore_db.is_image_analyzed(i):
            errorstr = "Image(s) must be analyzed before operation can be performed.\n\tImage: " + str(i)
            raise Exception(errorstr)
        else:
            try:
                newimage = anchore_image.AnchoreImage(i, anchore_datadir, docker_cli=docker_cli, allimages=allimages, dockerfile=dockerfile, tmpdirroot=tmproot, usertype=usertype, anchore_db=anchore_db, docker_images=docker_images)
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

    return (retlist)


def diff_images(imageId, baseimageId):
    ret = {}

    areport = contexts['anchore_db'].load_analysis_report(imageId)
    breport = contexts['anchore_db'].load_analysis_report(baseimageId)
    
    for module_name in areport.keys():
        if module_name in breport:
            for module_value in areport[module_name].keys():
                if module_value in breport[module_name]:
                    for module_type in areport[module_name][module_value].keys():
                        output = {}

                        adata = areport[module_name][module_value][module_type]
                        bdata = breport[module_name][module_value][module_type]

                        for akey in adata.keys():
                            if akey not in bdata:
                                output[akey] = "INIMG_NOTINBASE"
                            elif adata[akey] != bdata[akey]:
                                output[akey] = "VERSION_DIFF"
                        for bkey in bdata.keys():
                            if bkey not in adata:
                                output[bkey] = "INBASE_NOTINIMG"
                        if module_name not in ret:
                            ret[module_name] = {}
                        if module_value not in ret[module_name]:
                            ret[module_name][module_value] = {}

                        ret[module_name][module_value][module_type] = output

    return(ret)

def update_file_list(listbuf, outfile, backup=False):
    src = listbuf
    if not os.path.exists(outfile):
        write_plainfile_fromlist(outfile, src)
    else:
        dst = read_plainfile_tolist(outfile)
        if src != dst:
            if backup:
                hfile = outfile + "." + str(int(time.time()))
                os.rename(outfile, hfile)

            write_plainfile_fromlist(outfile, src)

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
        if l:
            row = l.split()
            for i in range(0, len(row)):
                row[i] = re.sub("____", " ", row[i])
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
        if l:
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
        if l:
            (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
            k = re.sub("____", " ", k)
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

def write_kvfile_fromlist(file, list, delim=' '):
    OFH = open(file, 'w')
    for l in list:
        for i in range(0,len(l)):
            l[i] = re.sub("\s", "____", l[i])
        thestr = delim.join(l) + "\n"
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def write_kvfile_fromdict(file, indict):
    dict = indict.copy()
    OFH = open(file, 'w')
    for k in dict.keys():
        if not dict[k]:
            dict[k] = "none"
        cleank = re.sub("\s+", "____", k)
        thestr = ' '.join([cleank, dict[k], '\n'])
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def touch_file(file):
    return(open(file, 'a').close())

def run_command_in_container(image=None, cmd="echo HELLO WORLD", fileget=None, fileput=None):
    if not image or not cmd:
        raise Exception("Invalid input: image="+str(image)+" cmd="+str(cmd))

    try:
        imageId = discover_imageId(image)
    except Exception as err:
        print str(err)
        return(list())

    olines = list()
    fbuf = ""

    try:
        docker_cli = contexts['docker_cli']
        
        container = docker_cli.create_container(image=image, command="/bin/bash -c '"+cmd+"'", tty=False)

        docker_cli.create_container(image=image, command="/bin/bash -c '"+cmd+"'", tty=False)
        if fileput:
            try:
                TFH=open(fileput, 'r')
                dat = TFH.read()
                TFH.close()
                docker_cli.put_archive(container.get('Id'), "/", dat)
            except Exception as err:
                import traceback
                traceback.print_exc()
                print str(err)
                pass
        response = docker_cli.start(container=container.get('Id'))
        output = docker_cli.logs(container=container.get('Id'), stdout=True, stderr=True, stream=True)
        for l in output:
            olines.append(l)

        if fileget:
            try:
                tstream,stat = docker_cli.get_archive(container, fileget)
                TFH = io.BytesIO(tstream.data)
                tar=tarfile.open(fileobj=TFH, mode='r', format=tarfile.PAX_FORMAT)
                for member in tar.getmembers():
                    fbuf = tar.extractfile(member).read()
                tar.close()
                TFH.close()
            except Exception as err:
                fbuf = ""
                pass

    except Exception as err:
        raise err
    finally:
        try:
            docker_cli.remove_container(container=container.get('Id'), force=True)
        except:
            pass

    return(olines, fbuf)

def get_files_from_tarfile(intarfile):
    allfiles = {}

    try:
        tar = tarfile.open(intarfile)
        for member in tar.getmembers():
            finfo = {}
            finfo['name'] = re.sub("^\./", "/", member.name.decode('utf8'))
            finfo['fullpath'] = os.path.normpath(finfo['name'])
            finfo['size'] = member.size
            finfo['mode'] = member.mode

            finfo['linkdst'] = None
            if member.isfile():
                finfo['type'] = 'file'
            elif member.isdir():
                finfo['type'] = 'dir'
            elif member.issym():
                finfo['type'] = 'slink'
                finfo['linkdst'] = re.sub("^\./", "/", member.linkname.decode('utf8'))
            elif member.islnk():
                finfo['type'] = 'hlink'
                finfo['linkdst'] = re.sub("^\./", "/", member.linkname.decode('utf8'))
            elif member.isdev():
                finfo['type'] = 'dev'
            else:
                finfo['type'] = 'UNKNOWN'

            if finfo['type'] == 'slink' or finfo['type'] == 'hlink':
                if re.match("^/", finfo['linkdst']):
                    fullpath = finfo['linkdst']
                else:
                    dstlist = finfo['linkdst'].split('/')
                    srclist = finfo['name'].split('/')
                    srcpath = srclist[0:-1]
                    fullpath = '/'.join(srcpath + dstlist)
                    fullpath = os.path.normpath('/'.join(srcpath + dstlist))
                finfo['fullpath'] = fullpath

            if finfo['name'] in allfiles:
                allfiles[finfo['name']] = allfiles[finfo['name']] + [finfo]
            else:
                allfiles[finfo['name']] = [finfo]

        tar.close()
    except:
        pass

    return(allfiles)

def get_files_from_path(inpath):
    filemap = {}
    allfiles = {}
    real_root = os.open('/', os.O_RDONLY)

    try:
        os.chroot(inpath)
        #for root, dirs, files in os.walk('/', followlinks=True):
        for root, dirs, files in os.walk('/', followlinks=False):
            for name in dirs + files:
                filename = os.path.join(root, name).decode('utf8')
                fstat = os.lstat(filename)

                finfo = {}
                finfo['name'] = filename
                finfo['fullpath'] = os.path.normpath(finfo['name'])
                finfo['size'] = fstat.st_size
                finfo['mode'] = fstat.st_mode
                
                mode = finfo['mode']
                finfo['linkdst'] = None
                finfo['linkdst_fullpath'] = None
                if S_ISREG(mode):
                    finfo['type'] = 'file'
                elif S_ISDIR(mode):
                    finfo['type'] = 'dir'
                elif S_ISLNK(mode):
                    finfo['type'] = 'slink'
                    finfo['linkdst'] = os.readlink(finfo['name'].encode('utf8')).decode('utf8')
                elif S_ISCHR(mode) or S_ISBLK(mode):
                    finfo['type'] = 'dev'
                else:
                    finfo['type'] = 'UNKNOWN'

                if finfo['type'] == 'slink' or finfo['type'] == 'hlink':
                    if re.match("^/", finfo['linkdst']):
                        fullpath = finfo['linkdst']
                    else:
                        dstlist = finfo['linkdst'].split('/')
                        srclist = finfo['name'].split('/')
                        srcpath = srclist[0:-1]
                        fullpath = '/'.join(srcpath + dstlist)
                        fullpath = os.path.normpath('/'.join(srcpath + dstlist))
                    finfo['linkdst_fullpath'] = fullpath

                fullpath = os.path.realpath(filename)

                finfo['othernames'] = {}
                for f in [fullpath, finfo['linkdst_fullpath'], finfo['linkdst'], finfo['name']]:
                    if f:
                        finfo['othernames'][f] = True

                allfiles[finfo['name']] = finfo

        # first pass, set up the basic file map
        for name in allfiles.keys():
            finfo = allfiles[name]
            finfo['othernames'][name] = True

            filemap[name] = finfo['othernames']
            for oname in finfo['othernames']:
                filemap[oname] = finfo['othernames']

        # second pass, include second order
        newfmap = {}
        count = 0
        while newfmap != filemap or count > 5:
            count += 1
            filemap.update(newfmap)
            newfmap.update(filemap)
            for mname in newfmap.keys():
                for oname in newfmap[mname].keys():
                    newfmap[oname].update(newfmap[mname])

    except Exception as err:
        import traceback
        traceback.print_exc()
        print str(err)
        pass

    os.fchdir(real_root)
    os.chroot('.')

    return(filemap, allfiles)

def grouper(inlist, chunksize):
    return (inlist[pos:pos + chunksize] for pos in xrange(0, len(inlist), chunksize))

