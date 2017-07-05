import os
import json
import re
import sys
import logging
import hashlib
import uuid
import jsonschema
import tempfile

import controller
import anchore_utils
import anchore_auth
from anchore.util import contexts

_logger = logging.getLogger(__name__)

default_policy_version = '1_0'
default_whitelist_version = '1_0'
default_bundle_version = '1_0'

supported_whitelist_versions = [default_whitelist_version]
supported_bundle_versions = [default_bundle_version]
supported_policy_versions = [default_bundle_version]

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
        record = anchore_auth.anchore_auth_get(contexts['anchore_auth'], policyurl, timeout=policy_timeout, retries=policy_maxretries)
        if record['success']:
            try:
                bundleraw = json.loads(record['text'])
                policymeta = bundleraw['bundle']
            except Exception as err:
                ret['text'] = 'failed to parse bundle response from service - exception: ' + str(err)
                return(False, ret)
        else:
            _logger.debug("failed to download policybundle: message from server - " + str(record))
            themsg = "unspecificied failure while attempting to download bundle from anchore.io"
            try:
                if record['status_code'] == 404:
                    themsg = "no policy bundle found on anchore.io - please create and save a policy using the policy editor in anchore.io and try again"
                elif record['status_code'] == 401:
                    themsg = "cannot download a policy bundle from anchore.io - current user does not have access rights to download custom policies"
            except Exception as err:
                themsg = "exception while inspecting response from server - exception: " +  str(err)

            ret['text'] = "failed to download policybundle: " + str(themsg)
            return(False, ret)

    if not verify_policy_bundle(bundle=policymeta):
        _logger.debug("downloaded policy bundle failed to verify: " +str(policymeta))
        ret['text'] = "input policy bundle does not conform to policy bundle schema"
        return(False, ret)

    if outfile:
        if outfile != '-':
            try:
                with open(outfile, 'w') as OFH:
                    OFH.write(json.dumps(policymeta))
            except Exception as err:
                ret['text'] = "could not write downloaded policy bundle to specified file ("+str(outfile)+") - exception: " + str(err)
                return(False, ret)
    else:
        if not contexts['anchore_db'].save_policymeta(policymeta):
            ret['text'] = "cannot get list of policies from service\nMessage from server: " + record['text']
            return (False, ret)

    if policymeta:
        ret['text'] = json.dumps(policymeta, indent=4)

    return(True, ret)

def load_policymeta(policymetafile=None):
    ret = {}
    if policymetafile:
        with open(policymetafile, 'r') as FH:
            ret = json.loads(FH.read())
    else:
        ret = contexts['anchore_db'].load_policymeta()
        if not ret:
            # use the system default
            default_policy_bundle_file = os.path.join(contexts['anchore_config'].config_dir, 'anchore_default_bundle.json')
            try:
                if os.path.exists(default_policy_bundle_file):
                    with open(default_policy_bundle_file, 'r') as FH:
                        ret = json.loads(FH.read())
                else:
                    raise Exception("no such file: " + str(default_policy_bundle_file))
            except Exception as err:
                _logger.warn("could not load default bundle (" + str(default_policy_bundle_file) + ") - exception: " + str(err))
                raise err

    return(ret)

def save_policymeta(policymeta):
    return(contexts['anchore_db'].save_policymeta(policymeta))

# bundle

# Convert
def convert_to_policy_bundle(name="default", version=default_bundle_version, policy_file=None, policy_version=default_policy_version, whitelist_files=[], whitelist_version=default_whitelist_version):
    policies = {}
    p = read_policy(name=str(uuid.uuid4()), file=policy_file)
    policies.update(p)

    whitelists = {}
    for wf in whitelist_files:
        w = read_whitelist(name=str(uuid.uuid4()), file=wf)
        whitelists.update(w)

    m = create_mapping(map_name="default", policy_name=policies.keys()[0], whitelists=whitelists.keys(), repotagstring='*/*:*')
    mappings.append(m)

    bundle = create_policy_bundle(name='default', policies=policies, policy_version=policy_version, whitelists=whitelists, whitelist_version=whitelist_version, mappings=mappings)
    
    if not verify_policy_bundle(bundle=bundle):
        return({})

    return(bundle)

# C
def create_policy_bundle(name=None, version=default_bundle_version, policies={}, policy_version=default_policy_version, whitelists={}, whitelist_version=default_whitelist_version, mappings=[]):
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

    try:
        bundle_schema_file = os.path.join(contexts['anchore_config']['pkg_dir'], 'schemas', 'anchore-bundle.schema')
    except:
        from pkg_resources import Requirement, resource_filename
        bundle_schema_file = os.path.join(resource_filename("anchore", ""), 'schemas', 'anchore-bundle.schema')

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
            _logger.error("could not validate bundle against schema: " + str(err))
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
def verify_whitelist(whitelistdata=[], version=default_whitelist_version):
    ret = True

    if not isinstance(whitelistdata, list):
        ret = False

    if version in supported_whitelist_versions:
        # do 1_0 format/checks
        pass

    return(ret)

# R
def read_whitelist(name=None, file=None, version=default_whitelist_version):
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
    if wldata['version'] == default_whitelist_version:
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
def read_policy(name=None, file=None, version=default_bundle_version):
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
    if poldata['version'] == default_policy_version:
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
def verify_policy(policydata=[], version=default_policy_version):
    ret = True

    if not isinstance(policydata, list):
        ret = False

    if version in supported_policy_versions:
        # do 1_0 format/checks
        pass

    return(ret)


def run_bundle(anchore_config=None, bundle={}, image=None, matchtags=[], stateless=False, show_whitelisted=True, show_triggerIds=True):
    retecode = 0

    if not anchore_config or not bundle or not image:
        raise Exception("input error")

    if not verify_policy_bundle(bundle=bundle):
        raise Exception("input bundle does not conform to bundle schema")

    imageId = anchore_utils.discover_imageId(image)
    digests = []

    if not matchtags:
        matchtags = [image]

    evalmap = {}
    evalresults = {}
    for matchtag in matchtags:
        _logger.info("evaluating tag: " + str(matchtag))

        mapping_results = get_mapping_actions(image=matchtag, imageId=imageId, in_digests=digests, bundle=bundle)
        for pol,wl,polname,wlnames,mapmatch,match_json,evalhash in mapping_results:
            evalmap[matchtag] = evalhash
            _logger.debug("attempting eval: " + evalhash + " : " + matchtag)
            if evalhash not in evalresults:
                fnames = {}
                try:
                    if stateless:

                        policies = structure_policy(pol)
                        whitelists = structure_whitelist(wl)
                        rc = execute_gates(imageId, policies)
                        result, fullresult = evaluate_gates_results(imageId, policies, {}, whitelists)
                        eval_result = structure_eval_results(imageId, fullresult, show_whitelisted=show_whitelisted, show_triggerIds=show_triggerIds, imageName=matchtag)
                        gate_result = {}
                        gate_result[imageId] = eval_result

                    else:
                        con = controller.Controller(anchore_config=anchore_config, imagelist=[imageId], allimages=contexts['anchore_allimages'], force=True)
                        for (fname, data) in [('tmppol', pol), ('tmpwl', wl)]:
                            fh, thefile = tempfile.mkstemp(dir=anchore_config['tmpdir'])
                            fnames[fname] = thefile
                            try:
                                with open(thefile, 'w') as OFH:
                                    for l in data:
                                        OFH.write(l + "\n")
                            except Exception as err:
                                raise err
                            finally:
                                os.close(fh)

                        gate_result = con.run_gates(policy=fnames['tmppol'], global_whitelist=fnames['tmpwl'], show_triggerIds=show_triggerIds, show_whitelisted=show_whitelisted)

                    evalel = {
                        'results': list(),
                        'policy_name':"N/A",
                        'whitelist_names':"N/A",
                        'policy_data':list(),
                        'whitelist_data':list(),
                        'mapmatch':"N/A",
                        'matched_mapping_rule': {}
                    }

                    evalel['results'] = gate_result
                    evalel['policy_name'] = polname
                    evalel['whitelist_names'] = wlnames
                    evalel['policy_data'] = pol
                    evalel['whitelist_data'] = wl
                    evalel['mapmatch'] = mapmatch
                    evalel['matched_mapping_rule'] = match_json

                    _logger.debug("caching eval result: " + evalhash + " : " + matchtag)
                    evalresults[evalhash] = evalel
                    ecode = result_get_highest_action(gate_result)
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
                _logger.debug("skipping eval, result already cached: " + evalhash + " : " + matchtag)

    ret = {}
    for matchtag in matchtags:
        ret[matchtag] = {}
        ret[matchtag]['bundle_name'] = bundle['name']
        try:
            evalresult = evalresults[evalmap[matchtag]]
            ret[matchtag]['evaluations'] = [evalresult]        
        except Exception as err:
            raise err

    return(ret, retecode)

def result_get_highest_action(results):
    highest_action = 0
    for k in results.keys():
        action = results[k]['result']['final_action']
        if action == 'STOP':
            highest_action = 1
        elif highest_action == 0 and action == 'WARN':
            highest_action = 2

    return(highest_action)

def get_mapping_actions(image=None, imageId=None, in_digests=[], bundle={}):
    """
    Given an image, image_id, digests, and a bundle, determine which policies and whitelists to evaluate.
    
    :param image: Image obj 
    :param imageId: image id string
    :param in_digests: candidate digests
    :param bundle: bundle dict to evaluate
    :return: tuple of (policy_data, whitelist_data, policy_name, whitelist_names, matchstring, mapping_rule_json obj, evalhash)
    """

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

            mregistry_rematch = mregistry
            mrepo_rematch = mrepo
            mtag_rematch = mtag
            try:
                matchtoks = []
                for tok in mregistry.split("*"):
                    matchtoks.append(re.escape(tok))
                mregistry_rematch = "^" + '(.*)'.join(matchtoks) + "$"

                matchtoks = []
                for tok in mrepo.split("*"):
                    matchtoks.append(re.escape(tok))
                mrepo_rematch = "^" + '(.*)'.join(matchtoks) + "$"

                matchtoks = []
                for tok in mtag.split("*"):
                    matchtoks.append(re.escape(tok))
                mtag_rematch = "^" + '(.*)'.join(matchtoks) + "$"
            except Exception as err:
                _logger.error("could not set up regular expression matches for mapping check - exception: " + str(err))

            _logger.debug("matchset: " + str([mregistry_rematch, mrepo_rematch, mtag_rematch]) + " : " + str([mregistry, mrepo, mtag]) + " : " + str([registry, repo, tag, tags]))

            if registry == mregistry or mregistry == '*' or re.match(mregistry_rematch, registry):
                _logger.debug("checking mapping for image ("+str(image_info)+") match.")

                if repo == mrepo or mrepo == '*' or re.match(mrepo_rematch, repo):
                    doit = False
                    matchstring = mname + ": N/A"
                    if tag:
                        if False and (mtag == tag or mtag == '*' or mtag in tags or re.match(mtag_rematch, tag)):
                            matchstring = mname + ":" + ','.join([mregistry, mrepo, mtag])
                            doit = True
                        else:
                            for t in tags:
                                if re.match(mtag_rematch, t):
                                    matchstring = mname + ":" + ','.join([mregistry, mrepo, mtag])
                                    doit = True
                                    break
                    if not doit and (digest and (mdigest == digest or mdigest in in_digests or mdigest in digests)):
                        matchstring = mname + ":" + ','.join([mregistry, mrepo, mdigest])
                        doit = True
                    
                    if not doit and (imageId and (mimageId == imageId)):
                        matchstring = mname + ":" + ','.join([mregistry, mrepo, mimageId])
                        doit = True

                    matchstring = matchstring.encode('utf8')
                    if doit:
                        _logger.debug("match found for image ("+str(image_info)+") matchstring ("+str(matchstring)+")")

                        wldata = []
                        wldataset = set()
                        for wlname in wlnames:
                            wldataset = set(list(wldataset) + extract_whitelist_data(bundle, wlname))
                        wldata = list(wldataset)

                        poldata = extract_policy_data(bundle, polname)
                        
                        wlnames.sort()
                        evalstr = ','.join([polname] + wlnames)
                        evalhash = hashlib.md5(evalstr).hexdigest()
                        ret.append( ( poldata, wldata, polname,wlnames, matchstring, m, evalhash) )
                        return(ret)
                    else:
                        _logger.debug("no match found for image ("+str(image_info)+") match.")
                else:
                    _logger.debug("no match found for image ("+str(image_info)+") match.")

    return(ret)

def execute_gates(imageId, policies, refresh=True):
    import random

    success = True
    anchore_config = contexts['anchore_config']

    imagename = imageId
    gatesdir = '/'.join([anchore_config["scripts_dir"], "gates"])
    workingdir = '/'.join([anchore_config['anchore_data_dir'], 'querytmp'])
    outputdir = workingdir

    _logger.info(imageId + ": evaluating policies...")
    
    for d in [outputdir, workingdir]:
        if not os.path.exists(d):
            os.makedirs(d)

    imgfile = '/'.join([workingdir, "queryimages." + str(random.randint(0, 99999999))])
    anchore_utils.write_plainfile_fromstr(imgfile, imageId)
    
    try:
        gmanifest, failedgates = anchore_utils.generate_gates_manifest()
        if failedgates:
            _logger.error("some gates failed to run - check the gate(s) modules for errors: "  + str(','.join(failedgates)))
            success = False
        else:
            success = True
            for gatecheck in policies.keys():
                # get all commands that match the gatecheck
                gcommands = []
                for gkey in gmanifest.keys():
                    if gmanifest[gkey]['gatename'] == gatecheck:
                        gcommands.append(gkey)

                # assemble the params from the input policy for this gatecheck
                params = []
                for trigger in policies[gatecheck].keys():
                    if 'params' in policies[gatecheck][trigger] and policies[gatecheck][trigger]['params']:
                        params.append(policies[gatecheck][trigger]['params'])

                if not params:
                    params = ['all']

                if gcommands:
                    for command in gcommands:
                        cmd = [command] + [imgfile, anchore_config['image_data_store'], outputdir] + params
                        _logger.debug("running gate command: " + str(' '.join(cmd)))

                        (rc, sout, cmdstring) = anchore_utils.run_command(cmd)
                        if rc:
                            _logger.error("FAILED")
                            _logger.error("\tCMD: " + str(cmdstring))
                            _logger.error("\tEXITCODE: " + str(rc))
                            _logger.error("\tOUTPUT: " + str(sout))
                            success = False
                        else:
                            _logger.debug("")
                            _logger.debug("\tCMD: " + str(cmdstring))
                            _logger.debug("\tEXITCODE: " + str(rc))
                            _logger.debug("\tOUTPUT: " + str(sout))
                            _logger.debug("")
                else:
                    _logger.warn("WARNING: gatecheck ("+str(gatecheck)+") line in policy, but no gates were found that match this gatecheck")
    except Exception as err:
        _logger.error("gate evaluation failed - exception: " + str(err))
    finally:
        if imgfile and os.path.exists(imgfile):
            try:
                os.remove(imgfile)
            except:
                _logger.error("could not remove tempfile: " + str(imgfile))

    if success:
        report = generate_gates_report(imageId)
        contexts['anchore_db'].save_gates_report(imageId, report)
        _logger.info(imageId + ": evaluated.")

    return(success)

def generate_gates_report(imageId):
    # this routine reads the results of image gates and generates a formatted report
    report = {}

    outputs = contexts['anchore_db'].list_gate_outputs(imageId)
    for d in outputs:
        report[d] = contexts['anchore_db'].load_gate_output(imageId, d)

    return(report)

def evaluate_gates_results(imageId, policies, image_whitelist, global_whitelist):
    ret = list()
    fullret = list()
    final_gate_action = 'GO'

    for m in policies.keys():
        gdata = contexts['anchore_db'].load_gate_output(imageId, m)
        for l in gdata:
            (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
            imageId = imageId
            check = m
            trigger = k
            output = v
            triggerId = hashlib.md5(''.join([check,trigger,output])).hexdigest()                

            # if the output is structured (i.e. decoded as an
            # anchore compatible json string) then extract the
            # elements for display
            try:
                json_output = json.loads(output)
                if 'id' in json_output:
                    triggerId = str(json_output['id'])
                if 'desc' in json_output:
                    output = str(json_output['desc'])
            except:
                pass

            if k in policies[m]:
                trigger = k
                action = policies[check][trigger]['action']

                r = {'imageId':imageId, 'check':check, 'triggerId':triggerId, 'trigger':trigger, 'output':output, 'action':action}
                # this is where whitelist check should go
                whitelisted = False
                whitelist_type = "none"

                if global_whitelist and ([m, triggerId] in global_whitelist):
                    whitelisted = True
                    whitelist_type = "global"
                elif image_whitelist and 'ignore' in image_whitelist and (r in image_whitelist['ignore']):
                    whitelisted = True
                    whitelist_type = "image"
                else:
                    # look for prefix wildcards
                    try:
                        for [gmod, gtriggerId] in global_whitelist:
                            if gmod == m:                                    
                                # special case for backward compat
                                try:
                                    if gmod == 'ANCHORESEC' and not re.match(".*\*.*", gtriggerId) and re.match("^CVE.*|^RHSA.*", gtriggerId):
                                        gtriggerId = gtriggerId + "*"
                                except Exception as err:
                                    _logger.warn("problem with backward compat modification of whitelist trigger - exception: " + str(err))

                                matchtoks = []
                                for tok in gtriggerId.split("*"):
                                    matchtoks.append(re.escape(tok))
                                rematch = "^" + '(.*)'.join(matchtoks) + "$"
                                _logger.debug("checking regexp wl<->triggerId for match: " + str(rematch) + " : " + str(triggerId))
                                if re.match(rematch, triggerId):
                                    _logger.debug("found wildcard whitelist match")
                                    whitelisted = True
                                    whitelist_type = "global"
                                    break

                    except Exception as err:
                        _logger.warn("problem with prefix wildcard match routine - exception: " + str(err))

                fullr = {}
                fullr.update(r)
                fullr['whitelisted'] = whitelisted
                fullr['whitelist_type'] = whitelist_type
                fullret.append(fullr)

                if not whitelisted:
                    if policies[m][k]['action'] == 'STOP':
                        final_gate_action = 'STOP'
                    elif final_gate_action != 'STOP' and policies[m][k]['action'] == 'WARN':
                        final_gate_action = 'WARN'
                    ret.append(r)
                else:
                    # whitelisted, skip evaluation
                    pass

    ret.append({'imageId':imageId, 'check':'FINAL', 'trigger':'FINAL', 'output':"", 'action':final_gate_action})
    fullret.append({'imageId':imageId, 'check':'FINAL', 'trigger':'FINAL', 'output':"", 'action':final_gate_action, 'whitelisted':False, 'whitelist_type':"none", 'triggerId':"N/A"})

    return(ret, fullret)

def structure_eval_results(imageId, evalresults, show_triggerIds=False, show_whitelisted=False, imageName=None):
    if not imageName:
        imageName = imageId

    record = {}
    record['result'] = {}

    record['result']['header'] = ['Image_Id', 'Repo_Tag']
    if show_triggerIds:
        record['result']['header'].append('Trigger_Id')
    record['result']['header'] += ['Gate', 'Trigger', 'Check_Output', 'Gate_Action']
    if show_whitelisted:
        record['result']['header'].append('Whitelisted')

    record['result']['rows'] = list()

    for m in evalresults:
        id = imageId
        name = imageName
        gate = m['check']
        trigger = m['trigger']
        output = m['output']
        triggerId = m['triggerId']
        action = m['action']

        row = [id[0:12], name]
        if show_triggerIds:
            row.append(triggerId)
        row += [gate, trigger, output, action]
        if show_whitelisted:
            row.append(m['whitelist_type'])

        if not m['whitelisted'] or show_whitelisted:
            record['result']['rows'].append(row)

        if gate == 'FINAL':
            record['result']['final_action'] = action

    return(record)

# small test
if __name__ == '__main__':
    from anchore.configuration import AnchoreConfiguration
    config = AnchoreConfiguration(cliargs={})
    anchore_utils.anchore_common_context_setup(config)

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

    map0 = create_mapping(map_name="default", policy_name=policies.keys()[0], whitelists=whitelists.keys(), repotagstring='*/*:*')
    mappings.append(map0)

    bundle = create_policy_bundle(name='default', policies=policies, policy_version=default_policy_version, whitelists=whitelists, whitelist_version=default_whitelist_version, mappings=mappings)
    print "CREATED BUNDLE: " + json.dumps(bundle, indent=4)

    rc = write_policy_bundle(bundle_file="/tmp/bun.json", bundle=bundle)
    newbun = read_policy_bundle(bundle_file="/tmp/bun.json")

    if newbun != bundle:
        print "BUNDLE RESULT DIFFERENT AFTER SAVE/LOAD"

    thebun = convert_to_policy_bundle(name='default', policy_file='/root/.anchore/conf/anchore_gate.policy', policy_version=default_policy_version, whitelist_files=['/root/wl0'], whitelist_version=default_whitelist_version)
    rc = write_policy_bundle(bundle_file="/tmp/bun1.json", bundle=thebun)

    pol0 = read_policy(name="meh", file='/root/.anchore/conf/anchore_gate.policy')
    policies = structure_policy(pol0['meh'])

    #rc = execute_gates("4a415e3663882fbc554ee830889c68a33b3585503892cc718a4698e91ef2a526", policies)

    result, image_ecode = run_bundle(anchore_config=config, image='alpine', matchtags=[], bundle=thebun)
    with open("/tmp/a", 'w') as OFH:
        OFH.write(json.dumps(result, indent=4))

    try:
        result, image_ecode = run_bundle_stateless(anchore_config=config, image='alpine', matchtags=[], bundle=thebun)
        with open("/tmp/b", 'w') as OFH:
            OFH.write(json.dumps(result, indent=4))

    except Exception as err:
        import traceback
        traceback.print_exc()
        print str(err)
