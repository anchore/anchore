import copy
import subprocess

import sys
import os
import re
import json 
import random 
import shutil

from anchore import anchore_utils
import logging
import anchore_image_db

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

        self.policy_override = None

    def read_policyfile(self, policyfile):
        FH=open(policyfile, 'r')
        policies = {}
        for l in FH.readlines():
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

        FH.close()
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

    def save_policyfile(self, policy, outpolicyfile):
        FH=open(outpolicyfile, 'w')
        for k in policy.keys():
            for c in policy[k].keys():
                if policy[k][c]['params']:
                    outline = k + ":" + c + ":" + policy[k][c]['action'] + ":" + policy[k][c]['params']
                else:
                    outline = k + ":" + c + ":" + policy[k][c]['action']
                FH.writelines(outline + "\n")
        FH.close()
        return(True)

    def get_images(self):
        return(self.images)

    def get_image_policies(self, image):
        # load default and image override policies, merge (if new
        # checks are in default), and save (if there is a diff after
        # the merge)

        image_gatepol = image.anchore_imagedir + "/anchore_gate.policy"

        default_policies = self.read_policyfile(self.default_gatepol)
        image_policies = False

        if os.path.exists(image_gatepol):
            image_policies = self.read_policyfile(image_gatepol)

        if image_policies and default_policies:
            policies = self.merge_policies(image_policies, default_policies)
            if policies != image_policies:
                self.save_policyfile(policies, image_gatepol)
        else:
            policies = default_policies
            self.save_policyfile(policies, image_gatepol)

        return(policies)

    def load_whitelist(self, image):
        ret = {'ignore':[], 'enforce':[]}

        whitelist = '/'.join([image.get_imagedir(), "/anchore_gate.whitelist"])
        if not os.path.exists(whitelist):
            return(ret)

        FH=open(whitelist, 'r')
        for l in FH.readlines():
            l = l.strip()
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
        FH.close()        
        return(ret)

    def save_whitelist(self, image, loaded, latest):
        new = {'ignore':list(loaded['ignore']), 'enforce':loaded['enforce']}

        whitelist = '/'.join([image.get_imagedir(), "/anchore_gate.whitelist"])
        if not os.path.exists(whitelist):
            FH=open(whitelist, 'w')
            for i in latest:
                FH.write(json.dumps(i) + "\n\n")
            FH.close()
        else:
            newpol = False
            for i in latest:
                # add evaled policy if not in the loaded whitelist
                if i not in new['ignore'] and i not in new['enforce']:
                    new['enforce'].append(i)
                    newpol = True

            # write the new whitelist, adding any new policies
            if newpol:
                FH=open(whitelist, 'w')
                for i in new['ignore']:
                    FH.write("#"+json.dumps(i) + "\n\n")
                for i in new['enforce']:
                    FH.write(json.dumps(i) + "\n\n")
                FH.close()
        return(True)

    def evaluate_gates_results(self, image):
        ret = list()
        final_gate_action = 'GO'

        policies_whitelist = self.load_whitelist(image)

        if self.policy_override:
            policies = self.read_policyfile(self.policy_override)
        else:
            policies = self.get_image_policies(image)
        for m in policies.keys():
            opath = image.anchore_imagedir + "/gates_output/" + m
            if os.path.exists(opath):
                FH=open(opath, 'r')
                for l in FH.readlines():
                    l = l.strip()
                    (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
                    if k in policies[m]:
                        r = {'imageId':image.meta['imageId'], 'check':m, 'trigger':k, 'output':v, 'action':policies[m][k]['action']}
                        # this is where whitelist check should go
                        if r not in policies_whitelist['ignore']:
                            if policies[m][k]['action'] == 'STOP':
                                final_gate_action = 'STOP'
                            elif final_gate_action != 'STOP' and policies[m][k]['action'] == 'WARN':
                                final_gate_action = 'WARN'
                            ret.append(r)
                        else:
                            # whitelisted, skip evaluation
                            pass
                FH.close()
        
        self.save_whitelist(image, policies_whitelist, ret)

        ret.append({'imageId':image.meta['imageId'], 'check':'FINAL', 'trigger':'FINAL', 'output':"", 'action':final_gate_action})
        
        for i in ret:
            if os.path.exists(image.get_imagedir() + "/gates_output/" + i['check'] + ".eval"):
                os.remove(image.get_imagedir() + "/gates_output/" + i['check'] + ".eval")

        for i in ret:
            FH=open(image.get_imagedir() + "/gates_output/" + i['check'] + ".eval", 'a')
            FH.write(i['trigger'] + " " + i['action'] + "\n")
            FH.close()

        self.anchoreDB.save_gates_eval_report(image.meta['imageId'], ret)
        return(ret)

    def execute_gates(self, image, refresh=True):
        self._logger.debug("gate policy evaluation for image "+str(image.meta['imagename'])+": begin")
        success = True

        imagename = image.meta['imageId']
        imagedir = image.anchore_imagedir
        gatesdir = '/'.join([self.config["scripts_dir"], "gates"])
        outputdir = imagedir + "/gates_output"
        workingdir = '/'.join([self.config['anchore_data_dir'], 'querytmp'])
        
        if not self.force and os.path.exists(imagedir + "/gates.done"):
            self._logger.info(image.meta['shortId'] + ": evaluated.")
            return(True)

        self._logger.info(image.meta['shortId'] + ": evaluating policies ...")
        
        if not os.path.exists(imagedir):
            os.makedirs(imagedir)

        if not os.path.exists(outputdir):
            os.makedirs(outputdir)

        if not os.path.exists(workingdir):
            os.makedirs(workingdir)

        imgfile = '/'.join([workingdir, "queryimages." + str(random.randint(0, 99999999))])
        anchore_utils.write_plainfile_fromstr(imgfile, image.meta['imageId'])

        if self.policy_override:
            policies = self.read_policyfile(self.policy_override)
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

        analysisdir = image.anchore_imagedir + "/gates_output/"
        for d in os.listdir(analysisdir):
            if re.match(".*\.eval$", d) or re.match(".*\.help$", d):
                continue

            if d not in report:
                report[d] = list()

            report[d] = anchore_utils.read_plainfile_tolist('/'.join([analysisdir, d]))

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

    def run_gates(self, policy=None, refresh=True):
        # actually run the gates
        ret = {}

        if policy:
            self.policy_override = policy

        for imageId in self.images:
            image = self.allimages[imageId]

            if not self.execute_gates(image, refresh=refresh):
                raise Exception("One or more gates failed to execute")

            results = self.evaluate_gates_results(image)

            record = {}
            record['result'] = {}
            record['result']['header'] = ['Image_Id', 'Repo_Tag', 'Gate', 'Trigger', 'Check_Output', 'Gate_Action']
            record['result']['rows'] = list()
            report = results
            for m in report:
                id = image.meta['imageId']
                name = image.get_human_name()
                gate = m['check']
                trigger = m['trigger']
                output = m['output']
                action = m['action']
                row = [id[0:12], name, gate, trigger, output, action]
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
                image = self.allimages[imageId]
                image_gatepol = image.anchore_imagedir + "/anchore_gate.policy"
                if os.path.exists(image_gatepol):
                    try:
                        os.remove(image_gatepol)
                    except Exception as err:
                        self._logger.error("failed to remove policy for image ("+imageId+").  bailing out: " + str(err))
                        return(False)
        return(True)

    def updatepolicy(self, newpolicyfile):
        newpol = self.read_policyfile(newpolicyfile)
        for imageId in self.images:
            if imageId in self.allimages:
                try:
                    image = self.allimages[imageId]
                    image_gatepol = image.anchore_imagedir + "/anchore_gate.policy"
                    self.save_policyfile(newpol, image_gatepol)
                except Exception as err:
                    self._logger.error("failed to update policy for image ("+imageId+"). bailing out: " + str(err))
                    return(False)
        return(True)

    def edit_policy_file(self, editpolicy=False, whitelist=False):
        ret = True

        if editpolicy:
            polfile = "anchore_gate.policy"
        elif whitelist:
            polfile = "anchore_gate.whitelist"
        else:
            # nothing to do
            return(ret)

        for imageId in self.images:
            image = self.allimages[imageId]            
            policies = self.get_image_policies(image)        

            thefile = '/'.join([image.anchore_imagedir, polfile])
                
            if not os.path.exists(thefile):
                self._logger.info("Cannot find file to edit, skipping: " + str(thefile))
            else:
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

        return(ret)

