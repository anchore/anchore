import os
import json
import re
import sys
import logging
import hashlib
import uuid
import jsonschema

import controller
import anchore_utils
from anchore.util import contexts

_logger = logging.getLogger(__name__)

# interface operations

def check():
    if not load_policymeta():
        return (False, "policys are not initialized: please run 'anchore policys sync' and try again")

    return (True, "success")

def sync_policymeta(bundlefile=None, outfile=None):
    ret = {'success': False, 'text': "", 'status_code': 1}

    policyurl = contexts['anchore_config']['policy_url']
    policy_timeout = contexts['anchore_config']['policy_conn_timeout']
    policy_maxretries = contexts['anchore_config']['policy_max_retries']

    policymeta = {}

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

    if not verify_policy_bundle(bundle=policymeta):
        ret['text'] = "input bundle does not conform to bundle schema"
        return(False, ret)

    if outfile and outfile != '-':
        try:
            with open(outfile, 'w') as OFH:
                OFH.write(json.dumps(policymeta))
        except Exception as err:
            ret['text'] = "could not write downloaded policy bundle to specified file ("+str(outfile)+") - exception: " + str(err)
            return(False, ret)
    else:
        record = {'text': 'unimplemented'}
        if not contexts['anchore_db'].save_policymeta(policymeta):
            ret['text'] = "cannot get list of policies from service\nMessage from server: " + record['text']
            return (False, ret)

    if policymeta:
        ret['text'] = json.dumps(policymeta, indent=4)

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

# Convert
def convert_to_policy_bundle(name="default", version='v1', policy_file=None, policy_version='v1', whitelist_files=[], whitelist_version='v1'):
    policies = {}
    p = read_policy(name=str(uuid.uuid4()), file=policy_file)
    policies.update(p)

    whitelists = {}
    for wf in whitelist_files:
        w = read_whitelist(name=str(uuid.uuid4()), file=wf)
        whitelists.update(w)

    m = create_mapping(map_name="default", policy_name=policies.keys()[0], whitelists=whitelists.keys(), repotagstring='*:*')
    mappings.append(m)

    bundle = create_policy_bundle(name='default', policies=policies, policy_version=policy_version, whitelists=whitelists, whitelist_version=whitelist_version, mappings=mappings)
    
    if not verify_policy_bundle(bundle=bundle):
        return({})

    return(bundle)

# C
def create_policy_bundle(name=None, version='v1', policies={}, policy_version='v1', whitelists={}, whitelist_version='v1', mappings=[]):
    ret = {
        'id': str(uuid.uuid4()),
        'name':name,
        'version':version,
        'policies':[],
        'whitelists':[],
        'mappings':[]
    }
        
    for f in policies:
        el = {
            'version':policy_version,
            'id':f,
            'name':f,
            'rules':[]
        }
        
        el['rules'] = unformat_policy_data(policies[f])
        ret['policies'].append(el)

    for f in whitelists:
        el = {
            'version':whitelist_version,
            'id':f,
            'name':f,
            'items':[]
        }
        
        el['items'] = unformat_whitelist_data(whitelists[f])
        ret['whitelists'].append(el)

    for m in mappings:
        ret['mappings'].append(m)

    _logger.debug("created bundle: ("+str(name)+") : " + json.dumps(ret.keys(), indent=4))
    return(ret)

# R
def read_policy_bundle(bundle_file=None):
    ret = {}
    with open(bundle_file, 'r') as FH:
        ret = json.loads(FH.read())
        cleanstr = json.dumps(ret).encode('utf8')
        ret = json.loads(cleanstr)

    if not verify_policy_bundle(bundle=ret):
        raise Exception("input bundle does not conform to bundle schema")

    return(ret)

# V
def verify_policy_bundle(bundle={}):
    bundle_schema = {}

    bundle_schema_file = os.path.join(contexts['anchore_config']['pkg_dir'], 'schemas', 'anchore-bundle.schema')
    try:
        if os.path.exists(bundle_schema_file):
            with open (bundle_schema_file, "r") as FH:
                bundle_schema = json.loads(FH.read())
    except Exception as err:
        _logger.error("could not load bundle schema: " + str(bundle_schema_file))
        return(False)

    if not bundle_schema:
        _logger.error("could not load bundle schema: " + str(bundle_schema_file))
        return(False)
    else:
        try:
            jsonschema.validate(bundle, schema=bundle_schema)
        except Exception as err:
            return(False)

    return(True)

# U
def update_policy_bundle(bundle={}, name=None, policies={}, whitelists={}, mappings={}):
    if not verify_policy_bundle(bundle=bundle):
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
    ret['policy_id'] = policy_name
    ret['whitelist_ids'] = whitelists

    image_info = anchore_utils.get_all_image_info(repotagstring)
    registry = image_info.pop('registry', "N/A")
    repo = image_info.pop('repo', "N/A")
    tag = image_info.pop('tag', "N/A")
    imageId = image_info.pop('imageId', "N/A")
    digest = image_info.pop('digest', "N/A")

    ret['registry'] = registry
    ret['repository'] = repo
    ret['image'] = {
        'type':'tag',
        'value':tag
    }
    ret['id'] = str(uuid.uuid4())

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

# R
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

def structure_whitelist(whitelistdata):
    ret = []
        
    for item in whitelistdata:
        try:
            (k,v) = re.match("([^\s]*)\s*([^\s]*)", item).group(1,2)
            if not re.match("^\s*#.*", k):
                ret.append([k, v])
        except Exception as err:
            pass

    return(ret)

def unformat_whitelist_data(wldata):
    ret = []

    whitelists = structure_whitelist(wldata)
    for wlitem in whitelists:
        gate, triggerId = wlitem
        el = {
            'gate':gate,
            'trigger_id':triggerId,
            'id':str(uuid.uuid4())
        }
        ret.append(el)
    return(ret)
            
def format_whitelist_data(wldata):
    ret = []
    version = wldata['version']
    if wldata['version'] == 'v1':
        for item in wldata['items']:
            ret.append(' '.join([item['gate'], item['trigger_id']]))
    else:
        raise Exception ("detected whitelist version format in bundle not supported: " + str(version))

    return(ret)
        

def extract_whitelist_data(bundle, wlid):
    for wl in bundle['whitelists']:
        if wlid == wl['id']:
            return(format_whitelist_data(wl))

# R
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

def structure_policy(policydata):
    policies = {}
    for l in policydata:
        l = l.strip()
        patt = re.compile('^\s*#')

        if (l and not patt.match(l)):
            polinput = l.split(':')
            module = polinput[0]
            check = polinput[1]
            action = polinput[2]
            modparams = ""
            if (len(polinput) > 3):
                modparams = ':'.join(polinput[3:])

            if module not in policies:
                policies[module] = {}

            if check not in policies[module]:
                policies[module][check] = {}

            if 'aptups' not in policies[module][check]:
                policies[module][check]['aptups'] = []

            aptup = [action, modparams]
            if aptup not in policies[module][check]['aptups']:
                policies[module][check]['aptups'].append(aptup)

            policies[module][check]['action'] = action
            policies[module][check]['params'] = modparams

    return(policies)

# return a give policyId from a bundle in raw poldata format
def extract_policy_data(bundle, polid):
    for pol in bundle['policies']:
        if polid == pol['id']:
            return(format_policy_data(pol))

# convert from policy bundle policy format to raw poldata format
def format_policy_data(poldata):
    ret = []
    version = poldata['version']
    if poldata['version'] == 'v1':
        for item in poldata['rules']:
            polline = ':'.join([item['gate'], item['trigger'], item['action'], ""])

            if 'params' in item:
                for param in item['params']:
                    polline = polline + param['name'] + '=' + param['value'] + " "
            ret.append(polline)
            
    else:
        raise Exception ("detected policy version format in bundle not supported: " + str(version))

    return(ret)

# convert from raw poldata format to bundle format
def unformat_policy_data(poldata):
    ret = []
    policies = structure_policy(poldata)

    for gate in policies.keys():
        try:
            for trigger in policies[gate].keys():
                action = policies[gate][trigger]['action']
                params = policies[gate][trigger]['params']

                el = {
                    'gate':gate,
                    'trigger':trigger,
                    'action':action,
                    'params':[]
                }

                for p in params.split():
                    (k,v) = p.split("=")
                    el['params'].append({'name':k, 'value':v})
                
                ret.append(el)
        except Exception as err:
            print str(err)
            pass

    return(ret)

# V
def verify_policy(policydata=[], version='v1'):
    ret = True

    if not isinstance(policydata, list):
        ret = False

    if version == 'v1':
        # do v1 format/checks
        pass

    return(ret)


def run_bundle(anchore_config=None, bundle={}, imagelist=[], matchtag=None):
    if not anchore_config or not bundle or not imagelist:
        raise Exception("input error")

    if not verify_policy_bundle(bundle=bundle):
        raise Exception("input bundle does not conform to bundle schema")

    ret = {}
    retecode = 0
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
                    ecode = con.result_get_highest_action(gate_result)
                    if ecode == 1:
                        retecode = 1
                    elif retecode == 0 and ecode > retecode:
                        retecode = ecode

                except Exception as err:
                    _logger.error("policy evaluation error: " + str(err))
                finally:
                    for f in fnames.keys():
                        if os.path.exists(fnames[f]):
                            os.remove(fnames[f])

        else:
            ret[image]['result'] = {}
            _logger.info("no match found in bundle ("+str(bundle['name'])+") policy mappings for image " + str(image) + " ("+str(imageId)+"): nothing to do.")

    return(ret, retecode)

def get_mapping_actions(image=None, imageId=None, in_digests=[], bundle={}):
    if not image or not bundle:
        raise Exception("input error")

    if not verify_policy_bundle(bundle=bundle):
        raise Exception("input bundle does not conform to bundle schema")

    ret = []
    
    image_infos = []

    image_info = anchore_utils.get_all_image_info(image)
    if image_info and image_info not in image_infos:
        image_infos.append(image_info)

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

                    matchstring = matchstring.encode('utf8')
                    if doit:
                        _logger.info("match found for image ("+str(matchstring)+")")

                        wldata = []
                        wldataset = set()
                        for wlname in wlnames:
                            #wldataset = set(list(wldataset) + bundle['whitelists'][wlname]['data'])
                            wldataset = set(list(wldataset) + extract_whitelist_data(bundle, wlname))
                        wldata = list(wldataset)

                        poldata = extract_policy_data(bundle, polname)

                        ret.append( ( poldata, wldata, polname,wlnames, matchstring) )
                        return(ret)
                    else:
                        _logger.debug("no match found for image ("+str(image_info)+") match.")
                else:
                    _logger.debug("no match found for image ("+str(image_info)+") match.")

    return(ret)

# small test
if __name__ == '__main__':
    import docker
    contexts['docker_cli'] = docker.Client()
    contexts['anchore_config'] = {'pkg_dir':'./'}

    policies = {}
    whitelists = {}
    mappings = []

    pol0 = read_policy(name=str(uuid.uuid4()), file='/root/.anchore/conf/anchore_gate.policy')
    pol1 = read_policy(name=str(uuid.uuid4()), file='/root/.anchore/conf/anchore_gate.policy')
    policies.update(pol0)
    policies.update(pol1)

    gl0 = read_whitelist(name=str(uuid.uuid4()))
    wl0 = read_whitelist(name=str(uuid.uuid4()), file='/root/wl0')
    whitelists.update(gl0)
    whitelists.update(wl0)

    map0 = create_mapping(map_name="default", policy_name=policies.keys()[0], whitelists=whitelists.keys(), repotagstring='*:*')
    mappings.append(map0)

    bundle = create_policy_bundle(name='default', policies=policies, policy_version='v1', whitelists=whitelists, whitelist_version='v1', mappings=mappings)
    print "CREATED BUNDLE: " + json.dumps(bundle, indent=4)

    rc = write_policy_bundle(bundle_file="/tmp/bun.json", bundle=bundle)
    newbun = read_policy_bundle(bundle_file="/tmp/bun.json")

    if newbun != bundle:
        print "BUNDLE RESULT DIFFERENT AFTER SAVE/LOAD"

    thebun = convert_to_policy_bundle(name='default', policy_file='/root/.anchore/conf/anchore_gate.policy', policy_version='v1', whitelist_files=['/root/wl0'], whitelist_version='v1')
    rc = write_policy_bundle(bundle_file="/tmp/bun1.json", bundle=thebun)

