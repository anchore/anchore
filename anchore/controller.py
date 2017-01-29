import copy
import subprocess

import sys
import os
import re
import json 
import random 
import shutil
import hashlib

from anchore import anchore_utils
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
        self.force = force        
        self.anchore_datadir = self.config['image_data_store']
        
        if len(imagelist) <= 0:
            raise Exception("No images given to evaluate")

        self.images = anchore_utils.image_context_add(imagelist, allimages, docker_cli=contexts['docker_cli'], anchore_datadir=self.anchore_datadir, tmproot=self.config['tmpdir'], anchore_db=contexts['anchore_db'], docker_images=contexts['docker_images'], must_be_analyzed=True, must_load_all=True)

        self.anchoreDB = contexts['anchore_db']

        self.default_gatepol = '/'.join([self.config.config_dir, "anchore_gate.policy"])
        self.default_global_whitelist = os.path.join(self.config.config_dir, "anchore_global.whitelist")

        self.policy_override = None
        self.global_whitelist_override = None
        self.show_triggerIds = False

    def read_policy(self, policydata):
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

                policies[module][check]['action'] = action
                policies[module][check]['params'] = modparams

        return(policies)

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

        policy_data = anchore_utils.read_plainfile_tolist(self.default_gatepol)
        default_policies = self.read_policy(policy_data)

        policy_data = self.anchoreDB.load_gate_policy(image.meta['imageId'])
        image_policies = self.read_policy(policy_data)

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
            whitelist_data = anchore_utils.read_kvfile_tolist(whitelist_file)

        for item in whitelist_data:
            if item[0] and not re.match("^#", item[0]) and len(item) > 1:
                store = item[0:2]
                ret.append(store)

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
                outlist.append(json.dumps(i))
            self.anchoreDB.save_gate_whitelist(image.meta['imageId'], outlist)
        else:
            newpol = False
            for i in latest:
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

    def evaluate_gates_results(self, image):
        ret = list()
        fullret = list()
        final_gate_action = 'GO'

        policies_whitelist = self.load_whitelist(image)
        global_whitelist = self.load_global_whitelist()

        if self.policy_override:
            policy_data = anchore_utils.read_plainfile_tolist(self.policy_override)
            policies = self.read_policy(policy_data)
        else:
            policies = self.get_image_policies(image)

        for m in policies.keys():
            gdata = self.anchoreDB.load_gate_output(image.meta['imageId'], m)
            for l in gdata:
                (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
                imageId = image.meta['imageId']
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
                        #output = output + " description="+outputdesc
                        output = str(json_output['desc'])
                except:
                    pass
                
                if k in policies[m]:
                    trigger = k
                    action = policies[check][trigger]['action']

                    #r = {'imageId':image.meta['imageId'], 'check':m, 'trigger':k, 'output':v, 'action':policies[m][k]['action']}
                    r = {'imageId':imageId, 'check':check, 'triggerId':triggerId, 'trigger':trigger, 'output':output, 'action':action}
                    # this is where whitelist check should go
                    whitelisted = False
                    whitelist_type = "none"

                    if [m, triggerId] in global_whitelist:
                        whitelisted = True
                        whitelist_type = "global"
                    elif r in policies_whitelist['ignore']:
                        whitelisted = True
                        whitelist_type = "image"
                    
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
        
        self.save_whitelist(image, policies_whitelist, ret)

        ret.append({'imageId':image.meta['imageId'], 'check':'FINAL', 'trigger':'FINAL', 'output':"", 'action':final_gate_action})
        fullret.append({'imageId':image.meta['imageId'], 'check':'FINAL', 'trigger':'FINAL', 'output':"", 'action':final_gate_action, 'whitelisted':False, 'whitelist_type':"none", 'triggerId':"N/A"})
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
        success = True

        imagename = image.meta['imageId']
        imagedir = image.anchore_imagedir
        gatesdir = '/'.join([self.config["scripts_dir"], "gates"])
        workingdir = '/'.join([self.config['anchore_data_dir'], 'querytmp'])
        outputdir = workingdir
        
        if not self.force and os.path.exists(imagedir + "/gates.done"):
            self._logger.info(image.meta['shortId'] + ": evaluated.")
            return(True)

        self._logger.info(image.meta['shortId'] + ": evaluating policies ...")
        
        for d in [outputdir, workingdir]:
            if not os.path.exists(d):
                os.makedirs(d)

        imgfile = '/'.join([workingdir, "queryimages." + str(random.randint(0, 99999999))])
        anchore_utils.write_plainfile_fromstr(imgfile, image.meta['imageId'])

        if self.policy_override:
            policy_data = anchore_utils.read_plainfile_tolist(self.policy_override)
            policies = self.read_policy(policy_data)
        else:
            policies = self.get_image_policies(image)

        paramlist = list()
        for p in policies.keys():
            for t in policies[p].keys():
                if 'params' in policies[p][t] and policies[p][t]['params']:
                    paramlist.append(policies[p][t]['params'])
        if len(paramlist) <= 0:
            paramlist.append('all')

        path_overrides = ['/'.join([self.config['user_scripts_dir'], 'gates'])]
        if self.config['extra_scripts_dir']:
            path_overrides = path_overrides + ['/'.join([self.config['extra_scripts_dir'], 'gates'])]

        results = scripting.ScriptSetExecutor(path=gatesdir, path_overrides=path_overrides).execute(capture_output=True, fail_fast=True, cmdline=' '.join([imgfile, self.config['image_data_store'], outputdir, ' '.join(paramlist)]))

        os.remove(imgfile)

        for r in results:
            (cmd, retcode, output) = r
            if retcode:
                self._logger.error("FAILED")
                self._logger.error("\tCMD: " + cmd)
                self._logger.error("\tEXITCODE: " + str(retcode))
                self._logger.error("\tOUTPUT: " + output)
                success = False
            else:
                self._logger.debug("")
                self._logger.debug("\tCMD: " + cmd)
                self._logger.debug("\tEXITCODE: " + str(retcode))
                self._logger.debug("\tOUTPUT: " + output)
                self._logger.debug("")

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
        highest_action = 0
        for k in results.keys():
            action = results[k]['result']['final_action']
            if action == 'STOP':
                highest_action = 1
            elif highest_action == 0 and action == 'WARN':
                highest_action = 2
            
        return(highest_action)

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

            if not self.execute_gates(image, refresh=refresh):
                raise Exception("One or more gates failed to execute")

            results, fullresults = self.evaluate_gates_results(image)

            record = {}
            record['result'] = {}

            #record['result']['header'] = ['Image_Id', 'Repo_Tag', 'Gate', 'Trigger', 'Check_Output', 'Gate_Action']        
            record['result']['header'] = ['Image_Id', 'Repo_Tag']
            if self.show_triggerIds:
                record['result']['header'].append('Trigger_Id')
            record['result']['header'] += ['Gate', 'Trigger', 'Check_Output', 'Gate_Action']
            if self.show_whitelisted:
                record['result']['header'].append('Whitelisted')

            record['result']['rows'] = list()

            for m in fullresults:
                id = image.meta['imageId']
                name = image.get_human_name()
                gate = m['check']
                trigger = m['trigger']
                output = m['output']
                triggerId = m['triggerId']
                action = m['action']

                row = [id[0:12], name]
                if self.show_triggerIds:
                    row.append(triggerId)
                row += [gate, trigger, output, action]
                if self.show_whitelisted:
                    row.append(m['whitelist_type'])

                if not m['whitelisted'] or show_whitelisted:
                    record['result']['rows'].append(row)

                if gate == 'FINAL':
                    record['result']['final_action'] = action

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
                image = self.allimages[imageId]
                image_pol = self.get_image_policies(image)
                ret[imageId] = image_pol
        return(ret)

    def rmpolicy(self):
        for imageId in self.images:
            if imageId in self.allimages:
                self.anchoreDB.del_gate_policy(imageId)

        return(True)

    def updatepolicy(self, newpolicyfile):
        policy_data = anchore_utils.read_plainfile_tolist(newpolicyfile)
        newpol = self.read_policy(policy_data)
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
                        ret = False

                    newdata = anchore_utils.read_plainfile_tolist(thefile)

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
