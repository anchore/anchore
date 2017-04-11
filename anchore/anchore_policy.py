import os
import json
import re
import sys
import logging
import hashlib
import controller
import anchore_utils
from anchore.util import contexts

_logger = logging.getLogger(__name__)

# interface operations

def check():
    if not load_policymeta():
        return (False, "policys are not initialized: please run 'anchore policys sync' and try again")

    #if not load_anchore_policys_list():
    #    return (False, "policys list is empty: please run 'anchore policys sync' and try again")

    return (True, "success")

def sync_policymeta(bundlefile=None):
    ret = {'success': False, 'text': "", 'status_code': 1}

    policyurl = contexts['anchore_config']['policy_url']
    policy_timeout = contexts['anchore_config']['policy_conn_timeout']
    policy_maxretries = contexts['anchore_config']['policy_max_retries']

    policymeta = {}

    # temporary read from FS
    if bundlefile:
        if not os.path.exists(bundlefile):
            ret['text'] = "no such file ("+str(bundlefile)+")"
            return(False, ret)
        try:
            with open(bundlefile, 'r') as FH:
                policymeta = json.loads(FH.read())
        except Exception as err:
            ret['text'] = "synced policy bundle cannot be read/is not valid JSON: exception - " +str(err)
            return(False, ret)
    else:
        ret['text'] = "download sync not yet available: use anchore sync --bundlefile <bundle.json>"
        return(False, ret)

        #record = anchore.anchore_auth.anchore_auth_get(contexts['anchore_auth'], policyurl, timeout=policy_timeout, retries=policy_maxretries)
        #if record['success']:
        #    policymeta = json.loads(record['text'])
        #else:
        #    ret['text'] = "failed to download policybundle: message from server - " + record['text']
        #    return(False, ret)

    for bundlename in policymeta.keys():
        if not verify_policy_bundle(policymeta[bundlename]):
            ret['text'] = "could not verify policy found in bundle input: ("+str(bundlename)+")"
            return(False, ret)

    record = {'text': 'unimplemented'}
    if not contexts['anchore_db'].save_policymeta(policymeta):
        ret['text'] = "cannot get list of policies from service\nMessage from server: " + record['text']
        return (False, ret)

    return(True, ret)

def load_policymeta(policymetafile=None):
    if policymetafile:
        with open(policymetafile, 'r') as FH:
            ret = json.loads(FH.read())
    else:
        ret = contexts['anchore_db'].load_policymeta()
    return(ret)

def save_policymeta(policymeta):
    return(contexts['anchore_db'].save_policymeta(policymeta))

# bundle

# C
def create_policy_bundle(name=None, policies={}, policy_version='v1', whitelists={}, whitelist_version='v1', global_whitelist={}, global_whitelist_version='v1', mappings=[]):
    ret = {
        'name':name,
        'policies':{},
        'whitelists':{},
        #'global_whitelists':{},
        'mappings':[]
    }
        
    for f in policies:
        if f not in ret['policies']:
            ret['policies'][f] = {}
        ret['policies'][f]['anchore_policy_version'] = policy_version
        ret['policies'][f]['data'] = policies[f]
        key = hashlib.md5(' '.join(sorted(json.dumps(ret['policies'][f]['data'], indent=4, sort_keys=True).splitlines()))).hexdigest()
        ret['policies'][f]['id'] = key
    

    for f in whitelists:
        if f not in ret['whitelists']:
            ret['whitelists'][f] = {}
        ret['whitelists'][f]['anchore_whitelist_version'] = whitelist_version
        ret['whitelists'][f]['data'] = whitelists[f]
        key = hashlib.md5(' '.join(sorted(json.dumps(ret['whitelists'][f]['data'], indent=4, sort_keys=True).splitlines()))).hexdigest()
        ret['whitelists'][f]['id'] = key

    #for f in global_whitelist:
    #    if f not in ret['global_whitelists']:
    #        ret['global_whitelists'][f] = {}
    #    ret['global_whitelists'][f]['anchore_global_whitelist_version'] = global_whitelist_version
    #    ret['global_whitelists'][f]['data'] = global_whitelist[f]
    #    key = hashlib.md5(' '.join(sorted(json.dumps(ret['global_whitelists'][f]['data'], indent=4, sort_keys=True).splitlines()))).hexdigest()
    #    ret['global_whitelists'][f]['id'] = key

    for m in mappings:
        ret['mappings'].append(m)

    key = hashlib.md5(' '.join(sorted(json.dumps(ret, indent=4, sort_keys=True).splitlines()))).hexdigest()
    ret['id'] = key
    _logger.debug("created bundle: ("+str(name)+") : " + json.dumps(ret.keys(), indent=4))
    return(ret)

# R
def read_policy_bundle(bundle_file=None):
    ret = {}
    with open(bundle_file, 'r') as FH:
        ret = json.loads(FH.read())

    if not verify_policy_bundle(bundle=ret):
        raise Exception("cannot verify loaded policy bundle: " + str(bundle_file))

    return(ret)

# V
def verify_policy_bundle(bundle={}):

    if 'name' not in bundle:
        return(False)
    if 'policies' not in bundle:
        return(False)
    if 'whitelists' not in bundle:
        return(False)
    if 'mappings' not in bundle:
        return(False)

    return(True)

# U
def update_policy_bundle(bundle={}, name=None, policies={}, whitelists={}, mappings={}):
    if not verify_policy_bundle(bundle):
        raise Exception("input bundle is incomplete - cannot update bad bundle: " + json.dumps(bundle, indent=4))

    ret = {}
    ret.update(bundle)

    new_bundle = create_policy_bundle(name=name, policies=policies, whitelists=whitelists, mappings=mappings)
    for key in ['name', 'policies', 'whitelists', 'mappings']:
        if new_bundle[key]:
            ret[key] = new_bundle.pop(key, ret[key])

    return(ret)

# SAVE
def write_policy_bundle(bundle_file=None, bundle={}):
    
    if not verify_policy_bundle(bundle=bundle):
        raise Exception("cannot verify input policy bundle, skipping write: " + str(bundle_file))

    with open(bundle_file, 'w') as OFH:
        OFH.write(json.dumps(bundle))

    return(True)

# mapping

# C
def create_mapping(map_name=None, policy_name=None, whitelists=[], repotagstring=None):
    ret = {}

    ret['name'] = map_name
    ret['policy'] = policy_name
    ret['whitelists'] = whitelists

    image_info = anchore_utils.get_all_image_info(repotagstring)
    registry = image_info.pop('registry', "N/A")
    repo = image_info.pop('repo', "N/A")
    tag = image_info.pop('tag', "N/A")
    imageId = image_info.pop('imageId', "N/A")
    digest = image_info.pop('digest', "N/A")

    ret['registry'] = registry
    ret['repo'] = repo
    ret['tag'] = tag
    ret['digest'] = digest
    ret['imageId'] = imageId

    return(ret)

# policy/wl

# V
def verify_whitelist(whitelistdata=[], version='v1'):
    ret = True

    if not isinstance(whitelistdata, list):
        ret = False

    if version == 'v1':
        # do v1 format/checks
        pass

    return(ret)


def read_whitelist(name=None, file=None, version='v1'):
    if not name:
        raise Exception("bad input: " + str(name) + " : " + str(file))

    if file:
        if not os.path.exists(file):
            raise Exception("input file does not exist: " + str(file))

        wdata = anchore_utils.read_plainfile_tolist(file)
        if not verify_whitelist(whitelistdata=wdata, version=version):
            raise Exception("cannot verify whitelist data read from file as valid")
    else:
        wdata = []

    ret = {}
    ret[name] = wdata

    return(ret)


def verify_policy(policydata=[], version='v1'):
    ret = True

    if not isinstance(policydata, list):
        ret = False

    if version == 'v1':
        # do v1 format/checks
        pass

    return(ret)

def read_policy(name=None, file=None, version='v1'):
    if not name or not file:
        raise Exception("input error")

    if not os.path.exists(file):
        raise Exception("input file does not exist: " + str(file))

    pdata = anchore_utils.read_plainfile_tolist(file)
    if not verify_policy(policydata=pdata, version=version):
        raise Exception("cannot verify policy data read from file as valid")

    ret = {}
    ret[name] = pdata

    return(ret)

def get_mapping_actions(image=None, imageId=None, in_digests=[], bundle={}):
    if not image or not bundle or not verify_policy_bundle(bundle=bundle):
        raise Exception("input error")

    ret = []
    
    image_infos = []

    image_info = anchore_utils.get_all_image_info(image)
    if image_info and image_info not in image_infos:
        image_infos.append(image_info)

    #print "IINFO: " + json.dumps(image_info, indent=4)

    #else:
    #    image_report = anchore_utils.load_image_report(imageId)
    #    if image_report:
    #        for tag in image_report['anchore_all_tags']:
    #            #image_info = anchore_utils.parse_dockerimage_string(tag)
    #            image_info = anchore_utils.get_all_image_info(tag)
    #            if image_info and image_info not in image_infos:
    #                image_infos.append(image_info)

    #_logger.info("II: " + json.dumps(image_info, indent=4))
        
    for m in bundle['mappings']:
        polname = m['policy_id']
        wlnames = m['whitelist_ids']

        for image_info in image_infos:
            #_logger.info("IMAGE INFO: " + str(image_info))
            ii = {}
            ii.update(image_info)
            registry = ii.pop('registry', "N/A")
            repo = ii.pop('repo', "N/A")

            tags = []
            fulltag = ii.pop('fulltag', "N/A")
            if fulltag != 'N/A':
                tinfo = anchore_utils.parse_dockerimage_string(fulltag)
                if 'tag' in tinfo and tinfo['tag']:
                    tag = tinfo['tag']

            for t in [image, fulltag]:
                tinfo = anchore_utils.parse_dockerimage_string(t)
                if 'tag' in tinfo and tinfo['tag'] and tinfo['tag'] not in tags:
                    tags.append(tinfo['tag'])

            #tags = [image, tag]
            #for t in image_info['tags']:
            #    tinfo = anchore_utils.parse_dockerimage_string(t)
            #    if 'tag' in tinfo and tinfo['tag']:
            #        tags.append(tinfo['tag'])

            digest = ii.pop('digest', "N/A")
            digests = [digest]
            for d in image_info['digests']:
                dinfo = anchore_utils.parse_dockerimage_string(d)
                if 'digest' in dinfo and dinfo['digest']:
                    digests.append(dinfo['digest'])
                                
            p_ids = []
            p_names = []
            for p in bundle['policies']:
                p_ids.append(p['id'])
                p_names.append(p['name'])

            wl_ids = []
            wl_names = []
            for wl in bundle['whitelists']:
                wl_ids.append(wl['id'])
                wl_names.append(wl['name'])
                
            if polname not in p_ids:
                _logger.info("policy not in bundle: " + str(polname))
                continue

            skip=False
            for wlname in wlnames:
                if wlname not in wl_ids:
                    _logger.info("whitelist not in bundle" + str(wlname))
                    skip=True
            if skip:
                continue

            #print "TAGS: " + str(tags)
            #print "IINFO: " + json.dumps([repo, registry, tag], indent=4)
            #print "MREG: " + json.dumps(m, indent=4)

            mname = m['name']
            mregistry = m['registry']
            mrepo = m['repository']
            if m['image']['type'] == 'tag':
                mtag = m['image']['value']
                mdigest = None
                mimageId = None
            elif m['image']['type'] == 'digest':
                mdigest = m['image']['value']
                mtag = None
                mimageId = None
            elif m['image']['type'] == 'id':
                mimageId = m['image']['value']
                mtag = None
                mdigest = None
            else:
                mtag = mdigest = mimageId = None

            if registry == mregistry or mregistry == '*':
                _logger.debug("checking mapping for image ("+str(image_info)+") match.")

                if repo == mrepo or mrepo == '*':
                    doit = False
                    matchstring = mname + ": N/A"
                    if tag and (mtag == '*' or mtag == tag or mtag in tags):
                        matchstring = mname + ":" + ','.join([mregistry, mrepo, mtag])
                        doit = True
                    elif digest and (mdigest == digest or mdigest in in_digests or mdigest in digests):
                        matchstring = mname + ":" + ','.join([mregistry, mrepo, mdigest])
                        doit = True
                    elif imageId and (mimageId == imageId):
                        matchstring = mname + ":" + ','.join([mregistry, mrepo, mimageId])
                        doit = True

                    if doit:
                        _logger.info("match found for image ("+str(image_info['pullstring'])+") match: " + str(matchstring))

                        wldata = []
                        wldataset = set()
                        for wlname in wlnames:
                            #wldataset = set(list(wldataset) + bundle['whitelists'][wlname]['data'])
                            wldataset = set(list(wldataset) + extract_whitelist_data(bundle, wlname))
                        wldata = list(wldataset)

                        poldata = extract_policy_data(bundle, polname)
                        #print "PDATA: " + json.dumps(poldata, indent=4)
                        ret.append( ( poldata, wldata, polname,wlnames, matchstring) )
                        return(ret)
                    else:
                        _logger.debug("no match found for image ("+str(image_info)+") match.")
                else:
                    _logger.debug("no match found for image ("+str(image_info)+") match.")

    return(ret)

def extract_policy_data(bundle, polid):
    for pol in bundle['policies']:
        if polid == pol['id']:
            return(format_policy_data(pol))

def format_policy_data(poldata):
    ret = []
    version = poldata['version']
    if poldata['version'] == '1_0':
        for item in poldata['rules']:
            #print json.dumps(item, indent=4)
            polline = ':'.join([item['gate'], item['trigger'], item['action'], ""])

            if 'params' in item:
                for param in item['params']:
                    polline = polline + param['name'] + '=' + param['value'] + " "
            ret.append(polline)
            
    return(ret)

def format_whitelist_data(wldata):
    ret = []
    version = wldata['version']
    if wldata['version'] == '1_0':
        for item in wldata['items']:
            ret.append(' '.join([item['gate'], item['trigger_id']]))

    return(ret)
        

def extract_whitelist_data(bundle, wlid):
    for wl in bundle['whitelists']:
        if wlid == wl['id']:
            return(format_whitelist_data(wl))
            

def run_bundle(anchore_config=None, bundle={}, imagelist=[], matchtag=None):
    if not anchore_config or not bundle or not imagelist or not verify_policy_bundle(bundle=bundle):
        raise Exception("input error")

    ret = {}
    for image in imagelist:
        if image not in ret:
            ret[image] = {}
            ret[image]['bundle_name'] = bundle['name']
            ret[image]['evaluations'] = []

        imageId = anchore_utils.discover_imageId(image)

        con = controller.Controller(anchore_config=anchore_config, imagelist=[imageId], allimages=contexts['anchore_allimages'], force=True)
        try:
            anchore_image = contexts['anchore_allimages'][imageId]
            digests = anchore_image.get_digests()
        except:
            digests = []

        if matchtag:
            matchimage = matchtag
        else:
            matchimage = image

        result = get_mapping_actions(image=matchimage, imageId=imageId, in_digests=digests, bundle=bundle)
        if result:
            for pol,wl,polname,wlnames,mapmatch in result:
                fnames = {}
                for (fname, data) in [('tmppol', pol), ('tmpwl', wl)]:
                    thefile = os.path.join(anchore_config['tmpdir'], fname)
                    fnames[fname] = thefile
                    with open(thefile, 'w') as OFH:
                        for l in data:
                            OFH.write(l + "\n")

                try:
                    gate_result = con.run_gates(policy=fnames['tmppol'], global_whitelist=fnames['tmpwl'], show_triggerIds=True, show_whitelisted=True)
                    evalel = {
                        'results': list(),
                        'policy_name':"N/A",
                        'whitelist_names':"N/A",
                        'policy_data':list(),
                        'whitelist_data':list(),
                        'mapmatch':"N/A",
                    }
                    
                    evalel['results'] = gate_result
                    evalel['policy_name'] = polname
                    evalel['whitelist_names'] = wlnames
                    evalel['policy_data'] = pol
                    evalel['whitelist_data'] = wl
                    evalel['mapmatch'] = mapmatch
                    ret[image]['evaluations'].append(evalel)

                except Exception as err:
                    _logger.error("policy evaluation error: " + str(err))
                finally:
                    for f in fnames.keys():
                        if os.path.exists(fnames[f]):
                            os.remove(fnames[f])

        else:
            ret[image]['result'] = {}
            _logger.info("no match found in bundle ("+str(bundle['name'])+") policy mappings for image " + str(image) + " ("+str(imageId)+"): nothing to do.")

    return(ret)

if __name__ == '__main__':
    policies = {}
    whitelists = {}
    mappings = []

    pol0 = read_policy(name='default', file='/root/.anchore/conf/anchore_gate.policy')
    pol1 = read_policy(name='default0', file='/root/.anchore/conf/anchore_gate.policy')
    policies.update(pol0)
    policies.update(pol1)

    gl0 = read_whitelist(name="global")
    wl0 = read_whitelist(name='default', file='/root/.anchore/conf/anchore_global.whitelist')
    whitelists.update(gl0)
    whitelists.update(wl0)

    map0 = create_mapping(map_name="default", policy_name='default', whitelists=['default'], repotagstring='centos:*')
    mappings.append(map0)


    bundle = create_policy_bundle(name='default', policies=policies, policy_version='v1', whitelists=whitelists, whitelist_version='v1', mappings=mappings)
    print "CREATED BUNDLE: " + json.dumps(bundle, indent=4)

    rc = write_policy_bundle(bundle_file="/tmp/bun.json", bundle=bundle)
    newbun = read_policy_bundle(bundle_file="/tmp/bun.json")

    if newbun != bundle:
        print "BUNDLE RESULT DIFFERENT AFTER SAVE/LOAD"


    
