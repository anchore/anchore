import re
import os
import sys
import subprocess
import shutil
import tempfile
import hashlib
import time
import logging

import controller
from anchore import anchore_utils
from anchore.util import scripting
from anchore.util import contexts

class Analyzer(object):
    _logger = logging.getLogger(__name__)

    def __init__(self, anchore_config, imagelist, allimages, force, args=None):
        self._logger.debug("analyzer initialization: begin")

        self.config = anchore_config
        self.allimages = allimages
        self.force = force

        self.dockerfile = None
        try:
            self.dockerfile = args['dockerfile']
        except:
            pass

        self.skipgates = False
        try:
            self.skipgates = args['skipgates']
        except:
            pass

        try:
            if 'isbase' in args and args['isbase']:
                usertype = 'base'
            elif 'anchorebase' in args and args['anchorebase']:
                usertype = 'anchorebase'
            else:
                usertype = None
        except:
            usertype = None

        self._logger.debug("init input processed, loading input images: " + str(imagelist))
        
        self.images = anchore_utils.image_context_add(imagelist, allimages, docker_cli=contexts['docker_cli'], dockerfile=self.dockerfile, tmproot=self.config['tmpdir'], anchore_db=contexts['anchore_db'], docker_images=contexts['docker_images'], usertype=usertype, must_load_all=True)

        self._logger.debug("loaded input images, checking that all input images have been loaded " + str(self.images))

        self.anchoreDB = contexts['anchore_db']

        self._logger.debug("analyzer initialization: end")

    def get_images(self):
        return(self.images)

    def script_is_runnable(self, script):
        suffix_list = ['.py', '.sh']
        match = False
        for s in suffix_list:
            if re.match(".*"+re.escape(s)+"$", script):
                match = True
                break
        if match and os.access(script, os.R_OK ^ os.X_OK):
            return(True)
        return(False)

    def list_analyzers(self):
        analyzerdir = '/'.join([self.config["scripts_dir"], "analyzers"])
        overrides = ['extra_scripts_dir', 'user_scripts_dir']

        scripts = {'base':list()}
        for override in overrides:
            scripts[override] = list()

        if not os.path.exists(analyzerdir):
            raise Exception("No base analyzers found - please check anchore insallation for completeness")
        else:
            for f in os.listdir(analyzerdir):
                script = os.path.join(analyzerdir, f)
                # check the script to make sure its ready to run
                if self.script_is_runnable(script):
                    scripts['base'].append(script)

        for override in overrides:
            scripts[override] = list()
            if self.config[override]:
                opath = os.path.join(self.config[override], 'analyzers')
                if os.path.exists(opath):
                    for f in os.listdir(opath):
                        script = os.path.join(opath, f)
                        if self.script_is_runnable(script):
                            scripts[override].append(script)
        return(scripts)

    def run_analyzers(self, image):
        success = True
        analyzers = self.list_analyzers()
        imagename = image.meta['imagename']
        #outputdir = image.anchore_imagedir
        shortid = image.meta['shortId']
        imagedir = None

        analyzer_status = self.anchoreDB.load_analyzer_manifest(image.meta['imageId'])
        
        analyzer_config = {}
        analyzer_config_csum = None
        try:
            analyzer_config, analyzer_config_csum = anchore_utils.load_analyzer_config(self.config.config_dir)
        except:
            pass

        if 'analyzer_config_csum' in analyzer_status:
            try:
                if analyzer_status['analyzer_config_csum']['csum'] != analyzer_config_csum:
                    self._logger.debug("anchore analyzer config has been updating, forcing re-analysis")
                    self.force = True
                    analyzer_status['analyzer_config_csum']['csum'] = analyzer_config_csum
            except:
                pass
        else:
            script = 'analyzer_config_csum'
            analyzer_status[script] = {}
            analyzer_status[script]['command'] = "ANALYZER_CONFIG_META"
            analyzer_status[script]['returncode'] = 0
            analyzer_status[script]['output'] = ""
            analyzer_status[script]['outputdir'] = ""
            analyzer_status[script]['atype'] = 'base'
            analyzer_status[script]['csum'] = analyzer_config_csum
            analyzer_status[script]['timestamp'] = time.time()
            analyzer_status[script]['status'] = 'SUCCESS'
            

        results = {}
        outputdirs = {}
        torun = list()
        skip = False
        atypes = ['user_scripts_dir', 'extra_scripts_dir', 'base']

        for atype in atypes:
            for script in analyzers[atype]:
                try:
                    with open(script, 'r') as FH:
                        csum = hashlib.md5(FH.read()).hexdigest()
                except:
                    csum = "N/A"

                # decide whether or not to run the analyzer
                dorun = True
                if self.force:
                    dorun = True
                elif script in analyzer_status:
                    if csum == analyzer_status[script]['csum'] and analyzer_status[script]['returncode'] == 0:
                        dorun = False

                outputdir = cmdstr = outstr = ""
                if dorun:
                    if not skip:
                        if not imagedir:
                            self._logger.info(image.meta['shortId'] + ": analyzing ...")                            
                            imagedir = image.unpack()
                            if not imagedir:
                                self._logger.error("could not unpack image")
                                return(False)
                            
                        outputdir = tempfile.mkdtemp(dir=imagedir)
                        cmdline = ' '.join([imagename, self.config['image_data_store'], outputdir, imagedir])
                        cmdstr = script + " " + cmdline
                        cmd = cmdstr.split()
                        try:
                            self._logger.debug("running analyzer: " + cmdstr)
                            timer = time.time()
                            outstr = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                            self._logger.debug("analyzer time (seconds): " + str(time.time() - timer))
                            rc = 0
                            self._logger.debug("analyzer status: success")
                            self._logger.debug("analyzer exitcode: " + str(rc))
                            self._logger.debug("analyzer output: " + outstr)
                        except subprocess.CalledProcessError as err:
                            rc = err.returncode
                            outstr = err.output
                        outstr = outstr.decode('utf8')
                        if rc:
                            status = 'FAILED'
                            skip = True
                            success = False
                            self._logger.error("analyzer status: failed")
                            self._logger.error("analyzer exitcode: " + str(rc))
                            self._logger.error("analyzer output: " + outstr)
                        else:
                            status = 'SUCCESS'
                    else:
                        # this means that a prior analyzer failed, so we skip the rest
                        self._logger.debug("skipping analyzer (due to prior analyzer failure): " + script)
                        outstr = ""
                        rc = 1
                        status = 'SKIPPED'

                    mtype = "base"
                    if atype == 'user_scripts_dir':
                        mtype = 'user'
                    elif atype == 'extra_scripts_dir':
                        mtype = 'extra'

                    results[script] = {}
                    results[script]['command'] = cmdstr
                    results[script]['returncode'] = rc
                    results[script]['output'] = outstr
                    results[script]['outputdir'] = outputdir
                    results[script]['atype'] = atype
                    results[script]['csum'] = csum
                    results[script]['timestamp'] = time.time()
                    results[script]['status'] = status

                    if os.path.exists(os.path.join(outputdir, 'analyzer_output')):
                        for d in os.listdir(os.path.join(outputdir, 'analyzer_output')):
                            if os.path.exists(os.path.join(outputdir, 'analyzer_output', d)):
                                for dd in os.listdir(os.path.join(outputdir, 'analyzer_output', d)):
                                    module_name = d
                                    module_value = dd
                                    if 'analyzer_outputs' not in results[script]:
                                        #results[script]['analyzer_outputs'] = {}
                                        results[script]['analyzer_outputs'] = list()

                                    aoutput = {'module_name':module_name, 'module_value':module_value, 'module_type':mtype}
                                    if os.path.isdir(os.path.join(outputdir, 'analyzer_output', d, dd)):
                                        aoutput['data_type'] = 'dir'
                                    else:
                                        aoutput['data_type'] = 'file'
                                    results[script]['analyzer_outputs'].append(aoutput)

                    analyzer_status[script] = {}
                    analyzer_status[script].update(results[script])
                else:
                    self._logger.debug("skipping analyzer (no change in analyzer/config and prior run succeeded): " + script)

        # process and store analyzer outputs
        didsave = False
        for script in results.keys():
            result = results[script]
            if result['status'] == 'SUCCESS':
                mtype = None
                if result['atype'] == 'user_scripts_dir':
                    mtype = 'user'
                elif result['atype'] == 'extra_scripts_dir':
                    mtype = 'extra'

                if os.path.exists(os.path.join(result['outputdir'], 'analyzer_output')):
                    for d in os.listdir(os.path.join(result['outputdir'], 'analyzer_output')):
                        if os.path.exists(os.path.join(result['outputdir'], 'analyzer_output', d)):
                            for dd in os.listdir(os.path.join(result['outputdir'], 'analyzer_output', d)):
                                dfile = os.path.join(result['outputdir'], 'analyzer_output', d, dd)
                                module_name = d
                                module_value = dd
                                if os.path.isfile(dfile):
                                    adata = anchore_utils.read_kvfile_todict(dfile)
                                    self.anchoreDB.save_analysis_output(image.meta['imageId'], module_name, module_value, adata, module_type=mtype)
                                    didsave = True
                                elif os.path.isdir(dfile):
                                    self.anchoreDB.save_analysis_output(image.meta['imageId'], module_name, module_value, dfile, module_type=mtype, directory_data=True)
                                    didsave = True

        self.anchoreDB.save_analyzer_manifest(image.meta['imageId'], analyzer_status)

        if success:
            self._logger.debug("analyzer commands all finished with successful exit codes")

            if didsave:
                self._logger.debug("generating analysis report from analyzer outputs and saving")                
                report = self.generate_analysis_report(image)
                self.anchoreDB.save_analysis_report(image.meta['imageId'], report)

            self._logger.debug("saving image information with updated analysis data")
            image.save_image()

            self._logger.info(image.meta['shortId'] + ": analyzed.")


        self._logger.debug("running analyzers on image: " + str(image.meta['imagename']) + ": end")

        return(success)

    def generate_analysis_report(self, image):
        # this routine reads the results of image analysis and generates a formatted report
        report = {}
        amanifest = self.anchoreDB.load_analyzer_manifest(image.meta['imageId'])
        for amodule in amanifest.keys():
            if 'analyzer_outputs' in amanifest[amodule]:
                for aoutput in amanifest[amodule]['analyzer_outputs']:
                    module_name = aoutput['module_name']
                    module_value = aoutput['module_value']
                    module_type = aoutput['module_type']
                    data_type = aoutput['data_type']
                    if module_name not in report:
                        report[module_name] = {}
                    if module_value not in report[module_name]:
                        report[module_name][module_value] = {}

                    if data_type == 'file':
                        adata = self.anchoreDB.load_analysis_output(image.meta['imageId'], module_name, module_value, module_type=module_type)
                    else:
                        adata = {}

                    report[module_name][module_value][module_type] = adata
        return(report)

    def run(self):
        self._logger.debug("main image analysis on images: " + str(self.images) + ": begin")
        # analyze image and all of its family members
        success = True
        toanalyze = {}
        comparehash = {}
        linkhash = {}

        # calculate all images to be analyzed
        for imageId in self.images:
            coreimage = self.allimages[imageId]

            toanalyze[coreimage.meta['imageId']] = coreimage

            base = False
            lastimage = coreimage
            for i in coreimage.anchore_familytree:
                image = self.allimages[i]
                toanalyze[image.meta['imageId']] = image

                if (image.meta['shortId'] != coreimage.meta['shortId'] and not image.is_intermediate()):
                    comparehash[coreimage.meta['shortId'] + image.meta['shortId']] = [coreimage, image]
                    comparehash[lastimage.meta['shortId'] + image.meta['shortId']] = [lastimage, image]
                    if not base and image.is_base():
                        base = image
                    lastimage = image

            if base:
                linkhash[image.meta['imageId']] = base.meta['imageId']

        # execute analyzers
        self._logger.debug("images to be analyzed: " + str(toanalyze.keys()))
        for imageId in toanalyze.keys():
            image = toanalyze[imageId]
            success = self.run_analyzers(image)
            if not success:
                self._logger.error("analyzer failed to run on image " + str(image.meta['imagename']) + ", skipping the rest")
                break

        if not success:
            self._logger.error("analyzers failed to run on one or more images.")
            return (False)

        #if not self.skipgates:
        #    # execute gates
        #    self._logger.debug("running gates post-analysis: begin")
        #    for imageId in toanalyze.keys():
        #        c = controller.Controller(anchore_config=self.config, imagelist=[imageId], allimages=self.allimages).run_gates(refresh=True)
        #    self._logger.debug("running gates post-analysis: end")

        self._logger.debug("main image analysis on images: " + str(self.images) + ": end")
        return (success)
