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

# bundle

# C
def create_policy_bundle(name=None, policies={}, policy_version='v1', whitelists={}, whitelist_version='v1', global_whitelist={}, global_whitelist_version='v1', mappings=[]):
    ret = {
        'name':name,
        'policies':{},
        'whitelists':{},
        'global_whitelists':{},
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

    for f in global_whitelist:
        if f not in ret['global_whitelists']:
            ret['global_whitelists'][f] = {}
        ret['global_whitelists'][f]['anchore_global_whitelist_version'] = global_whitelist_version
        ret['global_whitelists'][f]['data'] = global_whitelist[f]
        key = hashlib.md5(' '.join(sorted(json.dumps(ret['global_whitelists'][f]['data'], indent=4, sort_keys=True).splitlines()))).hexdigest()
        ret['global_whitelists'][f]['id'] = key

    for m in mappings:
        ret['mappings'].append(m)

    key = hashlib.md5(' '.join(sorted(json.dumps(ret, indent=4, sort_keys=True).splitlines()))).hexdigest()
    ret['id'] = key
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
def create_mapping(policy_name=None, whitelist_name=None, repotagstrings=[], apply_global=False):
    ret = {}
    ret['policy_name'] = policy_name
    ret['whitelist_name'] = whitelist_name
    ret['apply_global'] = apply_global
    ret['targets'] = {}
    for i in repotagstrings:
        (host, port, repo, tag, hostport, repotag, fulltag) = anchore_utils.parse_dockerimage_string(i)            
        if hostport not in ret['targets']:
            ret['targets'][hostport] = []
        ret['targets'][hostport].append({'repo':repo, 'tag':tag})

    return(ret)

# policy/wl

# V
def verify_whitelist(whitelistdata=[], version='v1'):
    ret = True

    if not whitelistdata or not isinstance(whitelistdata, list):
        ret = False

    if version == 'v1':
        # do v1 format/checks
        pass

    return(ret)


def read_whitelist(name=None, file=None, version='v1'):
    if not name or not file:
        raise Exception("bad input: " + str(name) + " : " + str(file))

    if not os.path.exists(file):
        raise Exception("input file does not exist: " + str(file))

    wdata = anchore_utils.read_plainfile_tolist(file)
    if not verify_whitelist(whitelistdata=wdata, version=version):
        raise Exception("cannot verify whitelist data read from file as valid")

    ret = {}
    ret[name] = wdata

    return(ret)


def verify_policy(policydata=[], version='v1'):
    ret = True

    if not policydata or not isinstance(policydata, list):
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

def get_mapping_actions(image=None, bundle={}):
    if not image or not bundle or not verify_policy_bundle(bundle=bundle):
        raise Exception("input error")

    ret = []
    (host, port, repo, tag, hostport, repotag, fulltag) = anchore_utils.parse_dockerimage_string(image)
    for m in bundle['mappings']:
        polname = m['policy_name']
        wlname = m['whitelist_name']
        apply_global = m['apply_global']

        if polname not in bundle['policies']:
            _logger.info("policy not in bundle: " + str(polname))
            continue
        if wlname not in bundle['whitelists']:
            _logger.info("whitelist not in bundle" + str(wlname))
            continue

        for registry in m['targets'].keys():
            if hostport == registry:
                for rt in m['targets'][registry]:
                    if repo == rt['repo']:
                        if rt['tag'] == '*' or rt['tag'] == tag:
                            wldata = []
                            if apply_global:
                                wldata = bundle['global_whitelists']['global']['data']
                            wldata = list(set(wldata + bundle['whitelists'][wlname]['data']))
                            ret.append( ( bundle['policies'][polname]['data'], wldata ) )

    return(ret)

def run_bundle(anchore_config=None, bundle={}, imagelist=[]):
    if not anchore_config or not bundle or not imagelist or not verify_policy_bundle(bundle=bundle):
        raise Exception("input error")

    ret = {}
    for image in imagelist:
        if image not in ret:
            ret[image] = {}
            ret[image]['bundle_id'] = bundle['id']

        imageId = anchore_utils.discover_imageId(image)
        result = get_mapping_actions(image=image, bundle=bundle)

        #with open("/tmp/mapping_actions.json", 'w') as OFH:
        #    OFH.write(json.dumps(result, indent=4))

        if result:
            for pol,wl in result:
                fnames = {}
                for (fname, data) in [('tmppol', pol), ('tmpwl', wl)]:
                    thefile = os.path.join(anchore_config['tmpdir'], fname)
                    fnames[fname] = thefile
                    with open(thefile, 'w') as OFH:
                        for l in data:
                            OFH.write(l + "\n")

                try:
                    con = controller.Controller(anchore_config=anchore_config, imagelist=[imageId], allimages=contexts['anchore_allimages'], force=True)
                    gate_result = con.run_gates(policy=fnames['tmppol'], global_whitelist=fnames['tmpwl'], show_triggerIds=True, show_whitelisted=True)
                    ret[image]['result'] = gate_result
                except Exception as err:
                    _logger.error("policy evaluation error: " + str(err))
                finally:
                    for f in fnames.keys():
                        if os.path.exists(fnames[f]):
                            os.remove(fnames[f])

        else:
            ret[image]['result'] = {}
            print "no match found in bundle policy mappings for image " + str(image) + " ("+str(imageId)+"): nothing to do."
            
    return(ret)

if __name__ == '__main__':
    policies = {}
    whitelists = {}
    mappings = []

    pol0 = read_policy(name='default', file='/root/.anchore/conf/anchore_gate.policy')
    pol1 = read_policy(name='default0', file='/root/.anchore/conf/anchore_gate.policy')
    policies.update(pol0)
    policies.update(pol1)

    wl0 = read_whitelist(name='default', file='/root/.anchore/conf/anchore_global.whitelist')
    whitelists.update(wl0)

    map0 = create_mapping(policy_name='default', whitelist_name='default', repotagstrings=['centos:*', 'alpine', 'ubuntu:16.10', 'myanchore.com:5000/alpine:latest'])
    mappings.append(map0)


    bundle = create_policy_bundle(name='default', policies=policies, policy_version='v1', whitelists=whitelists, whitelist_version='v1', mappings=mappings)
    print "CREATED BUNDLE: " + json.dumps(bundle, indent=4)

    rc = write_policy_bundle(bundle_file="/tmp/bun.json", bundle=bundle)
    newbun = read_policy_bundle(bundle_file="/tmp/bun.json")

    if newbun != bundle:
        print "BUNDLE RESULT DIFFERENT AFTER SAVE/LOAD"


    
