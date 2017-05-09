import copy
import subprocess

import sys
import os
import re
import json 
import random 
import shutil
import hashlib

#from anchore import anchore_utils#, anchore_policy
import anchore_policy, anchore_utils

import logging

from anchore.util import scripting, contexts

DEVNULL=open(os.devnull, 'wb')

class Controller(object):
    """
    Component that manages gate execution on images.
    """

    _logger = logging.getLogger(__name__)

    def __init__(self, anchore_config, imagelist, allimages, force=False):
        self.config = anchore_config
        self.allimages = allimages
        
        if len(imagelist) <= 0:
            raise Exception("No images given to evaluate")

        self.images = anchore_utils.image_context_add(imagelist, allimages, docker_cli=contexts['docker_cli'], tmproot=self.config['tmpdir'], anchore_db=contexts['anchore_db'], docker_images=contexts['docker_images'], must_be_analyzed=True, must_load_all=True)

        self.anchoreDB = contexts['anchore_db']

        self.default_gatepol = '/'.join([self.config.config_dir, "anchore_gate.policy"])
        self.default_global_whitelist = os.path.join(self.config.config_dir, "anchore_global.whitelist")

        self.policy_override = None
        self.global_whitelist_override = None
        self.show_triggerIds = False

    def merge_policies(self, poldst, polsrc):
        polret = copy.deepcopy(poldst)
        for sk in polsrc.keys():
            if sk not in polret:
                polret[sk] = polsrc[sk]

            for smk in polsrc[sk].keys():
                if smk not in polret[sk]:
                    polret[sk] = polsrc[sk]
        
        return(polret)

    def save_policy(self, imageId, policy):
        outlist = list()

        for k in policy.keys():
            for c in policy[k].keys():
                if policy[k][c]['params']:
                    outline = k + ":" + c + ":" + policy[k][c]['action'] + ":" + policy[k][c]['params']
                else:
                    outline = k + ":" + c + ":" + policy[k][c]['action']
                outlist.append(outline)

        self.anchoreDB.save_gate_policy(imageId, outlist)
        return(True)

    def get_images(self):
        return(self.images)

    def get_image_policies(self, image):
        # load default and image override policies, merge (if new
        # checks are in default), and save (if there is a diff after
        # the merge)

        try:
            policy = anchore_policy.read_policy(name='default', file=self.default_gatepol)
            policy_data = policy['default']
        except Exception as err:
            policy_data = []
        default_policies = anchore_policy.structure_policy(policy_data)

        policy_data = self.anchoreDB.load_gate_policy(image.meta['imageId'])
        image_policies = anchore_policy.structure_policy(policy_data)

        if image_policies and default_policies:
            policies = self.merge_policies(image_policies, default_policies)
            if policies != image_policies:
                self.save_policy(image.meta['imageId'], policies)
        else:
            policies = default_policies
            self.save_policy(image.meta['imageId'], policies)

        return(policies)

    def load_global_whitelist(self):
        ret = []
        whitelist_data = []
        whitelist_file = None

        if self.global_whitelist_override and os.path.exists(self.global_whitelist_override):
            whitelist_file = self.global_whitelist_override
        elif self.default_global_whitelist and os.path.exists(self.default_global_whitelist):
            whitelist_file = self.default_global_whitelist
        else:
            self._logger.debug("no global whitelist can be found, skipping")

        if whitelist_file:
            whitelist_data = anchore_policy.read_whitelist(name='default', file=whitelist_file)
            ret = anchore_policy.structure_whitelist(whitelist_data['default'])
            
        return(ret)

    def load_whitelist(self, image):
        ret = {'ignore':[], 'enforce':[]}

        data = self.anchoreDB.load_gate_whitelist(image.meta['imageId'])
        if not data:
            return(ret)

        for l in data:
            try:
                if re.match("^#.*", l):
                    l = re.sub("^#", "", l)
                    json_dict = json.loads(l)
                    ret['ignore'].append(json_dict)
                else:
                    json_dict = json.loads(l)
                    ret['enforce'].append(json_dict)
            except:
                pass

        return(ret)

    def save_whitelist(self, image, loaded, latest):
        new = {'ignore':list(loaded['ignore']), 'enforce':loaded['enforce']}

        whitelist = self.anchoreDB.load_gate_whitelist(image.meta['imageId'])
        if not whitelist:
            outlist = list()
            for i in latest:
                if 'check' in i and i['check'] == 'FINAL':
                    continue
                outlist.append(json.dumps(i))
            self.anchoreDB.save_gate_whitelist(image.meta['imageId'], outlist)
        else:
            newpol = False
            for i in latest:
                if 'check' in i and i['check'] == 'FINAL':
                    continue
                # add evaled policy if not in the loaded whitelist
                if i not in new['ignore'] and i not in new['enforce']:
                    new['enforce'].append(i)
                    newpol = True

            # write the new whitelist, adding any new policies
            if newpol:
                outlist = list()
                for i in new['ignore']:
                    outlist.append("#"+json.dumps(i))
                for i in new['enforce']:
                    outlist.append(json.dumps(i))
                self.anchoreDB.save_gate_whitelist(image.meta['imageId'], outlist)
        return(True)

    def load_policies(self, image):
        policies = {}
        if self.policy_override:
            try:
                policy = anchore_policy.read_policy(name='default', file=self.policy_override)
                policy_data = policy['default']
                
            except Exception as err:
                policy_data = []

            policies = anchore_policy.structure_policy(policy_data)
        else:
            policies = self.get_image_policies(image)

        return(policies)

    def evaluate_gates_results(self, image):
        ret = list()
        fullret = list()
        final_gate_action = 'GO'

        # prep the input
        policies = self.load_policies(image)
        policies_whitelist = self.load_whitelist(image)
        global_whitelist = self.load_global_whitelist()

        # perform the evaluation
        ret, fullret = anchore_policy.evaluate_gates_results(image.meta['imageId'], policies, policies_whitelist, global_whitelist)

        # save the results
        self.save_whitelist(image, policies_whitelist, ret)
        for i in ret:
            self.anchoreDB.del_gate_eval_output(image.meta['imageId'], i['check'])

        evals = {}
        for i in ret:
            if i['check'] not in evals:
                evals[i['check']] = list()
            evals[i['check']].append(' '.join([i['trigger'], i['action']]))

        for i in evals.keys():
            self.anchoreDB.save_gate_eval_output(image.meta['imageId'], i, evals[i])

        self.anchoreDB.save_gates_eval_report(image.meta['imageId'], ret)
        return(ret, fullret)

    def execute_gates(self, image, refresh=True):
        self._logger.debug("gate policy evaluation for image "+str(image.meta['imagename'])+": begin")

        imageId = image.meta['imageId']
        policies = self.load_policies(image)
        success = True
        
        success = anchore_policy.execute_gates(imageId, policies)
        if success:
            report = self.generate_gates_report(image)
            self.anchoreDB.save_gates_report(image.meta['imageId'], report)
            self._logger.info(image.meta['shortId'] + ": evaluated.")

        self._logger.debug("gate policy evaluation for image "+str(image.meta['imagename'])+": end")
        return(success)

    def generate_gates_report(self, image):
        # this routine reads the results of image gates and generates a formatted report
        report = {}

        outputs = self.anchoreDB.list_gate_outputs(image.meta['imageId'])
        for d in outputs:
            report[d] = self.anchoreDB.load_gate_output(image.meta['imageId'], d)

        return(report)

    def result_get_highest_action(self, results):
        return(anchore_policy.result_get_highest_action(results))

    def run_gates(self, policy=None, refresh=True, global_whitelist=None, show_triggerIds=False, show_whitelisted=False):
        # actually run the gates
        ret = {}

        if policy:
            self.policy_override = policy

        if global_whitelist:
            self.global_whitelist_override = global_whitelist

        self.show_triggerIds = show_triggerIds
        self.show_whitelisted = show_whitelisted

        for imageId in self.images:
            image = self.allimages[imageId]
            
            rc = self.execute_gates(image, refresh=refresh)
            if not rc:
                raise Exception("one or more gates failed to execute")

            results, fullresults = self.evaluate_gates_results(image)
                
            record = anchore_policy.structure_eval_results(imageId, fullresults, show_triggerIds=self.show_triggerIds, show_whitelisted=self.show_whitelisted, imageName=image.get_human_name())

            ret[imageId] = record
        return(ret)

    def editpolicy(self):
        return(self.edit_policy_file(editpolicy=True))

    def editwhitelist(self):
        return(self.edit_policy_file(whitelist=True))

    def listpolicy(self):
        ret = {}
        for imageId in self.images:
            if imageId in self.allimages:
                policy_data = self.anchoreDB.load_gate_policy(imageId)
                image_pol = anchore_policy.structure_policy(policy_data)
                ret[imageId] = image_pol
        return(ret)

    def rmpolicy(self):
        for imageId in self.images:
            if imageId in self.allimages:
                self.anchoreDB.del_gate_policy(imageId)

        return(True)

    def updatepolicy(self, newpolicyfile):
        #policy_data = anchore_utils.read_plainfile_tolist(newpolicyfile)
        try:
            policy = anchore_policy.read_policy(name='default', file=newpolicyfile)
            policy_data = policy['default']
        except Exception as err:
            policy_data = []

        newpol = anchore_policy.structure_policy(policy_data)
        for imageId in self.images:
            if imageId in self.allimages:
                try:
                    self.save_policy(imageId, newpol)
                except Exception as err:
                    self._logger.error("failed to update policy for image ("+imageId+"). bailing out: " + str(err))
                    return(False)
        return(True)

    def edit_policy_file(self, editpolicy=False, whitelist=False):
        ret = True

        if not editpolicy and not whitelist:
            # nothing to do
            return(ret)

        for imageId in self.images:
            if editpolicy:
                data = self.anchoreDB.load_gate_policy(imageId)
            else:
                data = self.anchoreDB.load_gate_whitelist(imageId)

            if not data:
                self._logger.info("Cannot find existing data to edit, skipping: " + str(imageId))
            else:
                tmpdir = anchore_utils.make_anchoretmpdir("/tmp")
                try:
                    thefile = os.path.join(tmpdir, "anchorepol."+imageId)
                    anchore_utils.write_plainfile_fromlist(thefile, data)
                    if "EDITOR" in os.environ:
                        cmd = os.environ["EDITOR"].split()
                        cmd.append(thefile)
                        try:
                            subprocess.check_output(cmd, shell=False)
                        except:
                            ret = False
                    elif os.path.exists("/bin/vi"):
                        try:
                            rc = os.system("/bin/vi " + thefile)
                            if rc:
                                ret = False
                        except:
                            ret = False
                    else:
                        self._logger.info("Cannot find editor to use: please set the EDITOR environment variable and try again")
                        break

                    #newdata = anchore_utils.read_plainfile_tolist(thefile)
                    try:
                        policy = anchore_policy.read_policy(name='default', file=thefile)
                        newdata = policy['default']
                    except Exception as err:
                        newdata = []

                    if editpolicy:
                        self.anchoreDB.save_gate_policy(imageId, newdata)
                    else:
                        self.anchoreDB.save_gate_whitelist(imageId, newdata)
                except Exception as err:
                    pass
                finally:
                    if tmpdir:
                        shutil.rmtree(tmpdir)

        return(ret)
