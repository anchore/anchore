import re
import os
import sys
import subprocess
import shutil
import tempfile
import hashlib
import time
import logging

import anchore_image_db
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
        self.anchore_datadir = self.config['image_data_store']

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
        
        self.images = anchore_utils.image_context_add(imagelist, allimages, docker_cli=contexts['docker_cli'], dockerfile=self.dockerfile, anchore_datadir=self.anchore_datadir, tmproot=self.config['tmpdir'], anchore_db=contexts['anchore_db'], usertype=usertype, must_load_all=True)

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
        outputdir = image.anchore_imagedir
        shortid = image.meta['shortId']
        imagedir = None

        analyzer_status = self.anchoreDB.load_analyzer_manifest(image.meta['imageId'])

        results = {}
        outputdirs = {}
        torun = list()
        skip = False
        for atype in ['user_scripts_dir', 'extra_scripts_dir', 'base']:
            for script in analyzers[atype]:
                try:
                    with open(script, 'r') as FH:
                        csum = hashlib.md5(FH.read()).hexdigest()
                except:
                    csum = "NA"

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

                        outputdir = tempfile.mkdtemp(dir=imagedir)
                        cmdline = ' '.join([imagename, self.config['image_data_store'], outputdir, imagedir])
                        cmdstr = script + " " + cmdline
                        cmd = cmdstr.split()
                        try:
                            self._logger.debug("running analyzer: " + cmdstr)
                            outstr = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
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
                                        results[script]['analyzer_outputs'] = {}
                                    results[script]['analyzer_outputs']['module_name'] = module_name
                                    results[script]['analyzer_outputs']['module_value'] = module_value
                                    results[script]['analyzer_outputs']['module_type'] = mtype


                    analyzer_status[script] = {}
                    analyzer_status[script].update(results[script])
                else:
                    self._logger.debug("skipping analyzer (no change in analyzer/config and prior run succeeded): " + script)

        # process and store analyzer outputs
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
                                adata = anchore_utils.read_kvfile_todict(dfile)
                                self.anchoreDB.save_analysis_output(image.meta['imageId'], module_name, module_value, adata, module_type=mtype)

        if success:
            self._logger.debug("analyzer commands all finished with successful exit codes")

            self._logger.debug("generating analysis report from analyzer outputs and saving")
            report = self.generate_analysis_report(image)
            self.anchoreDB.save_analysis_report(image.meta['imageId'], report)

            self._logger.debug("saving image information with updated analysis data")
            image.save_image()

            self._logger.info(image.meta['shortId'] + ": analyzed.")

        self.anchoreDB.save_analyzer_manifest(image.meta['imageId'], analyzer_status)
        self._logger.debug("running analyzers on image: " + str(image.meta['imagename']) + ": end")

        return(success)

    def run_analyzers_orig(self, image):
        self._logger.debug("running analyzers on image: " + str(image.meta['imagename']) + ": begin")

        imagename = image.meta['imagename']
        outputdir = image.anchore_imagedir
        shortid = image.meta['shortId']
        analyzerdir = '/'.join([self.config["scripts_dir"], "analyzers"])

        path_overrides = ['/'.join([self.config['user_scripts_dir'], 'analyzers'])]
        if self.config['extra_scripts_dir']:
            path_overrides = path_overrides + ['/'.join([self.config['extra_scripts_dir'], 'analyzers'])]
        se = scripting.ScriptSetExecutor(path=analyzerdir, path_overrides=path_overrides)
        
        doexec = False
        lastcsums = None
        csums = se.csums()
        if self.force:
            doexec = True
        else:
            if os.path.exists(outputdir + "/analyzers.done"):
                lastcsums = anchore_utils.read_kvfile_todict(outputdir + "/analyzers.done")
                if csums != lastcsums:
                    doexec = True
            else:
                doexec = True
        
        if not doexec:
            self._logger.info(image.meta['shortId'] + ": analyzed.")
            return(True)

        self._logger.info(image.meta['shortId'] + ": analyzing ...")

        if not os.path.exists(outputdir):
            self._logger.debug("outputdir '" + str(outputdir) + "'not found, creating")
            os.makedirs(outputdir)

        self._logger.debug("unpacking image")
        imagedir = image.unpack()
        self._logger.debug("finished unpacking image to directory: " + str(imagedir))

        self._logger.debug("running all analyzers")

        results = se.execute(capture_output=True, fail_fast=True, cmdline=' '.join([imagename, self.config['image_data_store'], outputdir, imagedir]), lastcsums=lastcsums)

        self._logger.debug("analyzers done running: " + str(len(results)))

        success = True
        for r in results:
            (cmd, retcode, output) = r
            if retcode:
                # something failed
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

        self._logger.debug("analyzer commands all finished with successful exit codes")
        if success:
            self._logger.debug("generating analysis report from analyzer outputs and saving")
            report = self.generate_analysis_report(image)
            self.anchoreDB.save_analysis_report(image.meta['imageId'], report)

            self._logger.debug("saving image information with updated analysis data")
            image.save_image()

            #anchore_utils.touch_file(outputdir + "/analyzers.done")
            anchore_utils.write_kvfile_fromdict(outputdir + "/analyzers.done", csums)

            self._logger.info(image.meta['shortId'] + ": analyzed.")

        self._logger.debug("running analyzers on image: " + str(image.meta['imagename']) + ": end")
        return (success)

    def generate_analysis_report(self, image):
        # this routine reads the results of image analysis and generates a formatted report
        report = {}

        analysisdir = image.anchore_imagedir + "/analyzer_output/"
        for d in os.listdir(analysisdir):
            if d not in report:
                report[d] = {}

            moduledir = analysisdir + "/" + d
            for o in os.listdir(moduledir):
                datafile = moduledir + "/" + o
                if o not in report[d]:
                    report[d][o] = list()
                report[d][o] = anchore_utils.read_plainfile_tolist(datafile)
        return (report)

    def generate_compare_report(self, image):
        # this routine reads the results of image compare and generates a formatted report
        report = {}

        rootdir = image.anchore_imagedir + "/compare_output/"
        for b in os.listdir(rootdir):
            if b not in report:
                report[b] = {}

            comparedir = rootdir + "/" + b + "/"
            for d in os.listdir(comparedir):
                if d == 'differs.done':
                    continue

                if d not in report[b]:
                    report[b][d] = {}

                moduledir = comparedir + "/" + d
                for o in os.listdir(moduledir):
                    datafile = moduledir + "/" + o
                    
                    if o not in report[b][d]:
                        report[b][d][o] = list()
                    report[b][d][o] = anchore_utils.read_plainfile_tolist(datafile)

        return (report)

    def run_differs(self, image, baseimage):
        self._logger.debug("comparison of " + str(image.meta['imagename']) + " to " + str(image.meta['imagename']) + ": begin")
        shortida = image.meta['shortId']
        shortidb = baseimage.meta['shortId']

        if not image.is_analyzed():
            self._logger.error("cannot compare image " + shortida + " - need to analyze first.")
            return (False)

        if not baseimage.is_analyzed():
            self._logger.error("cannot compare image " + shortidb + " - need to analyze first")
            return (False)

        outputdir = image.anchore_imagedir

        if not self.force and os.path.exists(outputdir + "/compare_output/" + baseimage.meta['imageId'] + "/differs.done"):
            self._logger.debug("images already compared and --force not specified, nothing to do")
            self._logger.info(shortida + " to " + shortidb + ": compared.")
            return (True)

        self._logger.info(shortida + " to " + shortidb + ": comparing ...")

        if not os.path.exists(outputdir):
            self._logger.debug("output directory '" + str(outputdir) + "' does not exist, creating")
            os.makedirs(outputdir)

        thedir = outputdir + "/compare_output/" + baseimage.meta['imageId'] + "/"
        if not os.path.exists(thedir):
            self._logger.debug("output directory '" + str(thedir) + "' does not exist, creating")
            os.makedirs(thedir)

        compares = anchore_utils.diff_images(image, baseimage)
        for azkey in compares.keys():
            for aokey in compares[azkey].keys():
                outputdict = compares[azkey][aokey]
                thedir = outputdir + "/compare_output/" + baseimage.meta['imageId'] + "/" + azkey + "/"
                if not os.path.exists(thedir):
                    os.makedirs(thedir)
                        
                thefile = thedir + "/" + aokey
                anchore_utils.write_kvfile_fromdict(thefile, outputdict)
                
        self._logger.debug("all comparisons completed")

        anchore_utils.touch_file(outputdir + "/compare_output/" + baseimage.meta['imageId'] + "/differs.done")

        self._logger.info(shortida + " to " + shortidb + ": compared.")

        self._logger.debug("comparison of " + str(image.meta['imagename']) + " to " + str(image.meta['imagename']) + ": end")
        return (True)

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

            if os.path.exists(image.tmpdir):
                shutil.rmtree(image.tmpdir)

        if not success:
            self._logger.error("analyzers failed to run on one or more images.")
            return (False)

        # execute differs
        for k in comparehash.keys():
            a = comparehash[k][0]
            b = comparehash[k][1]
            if a.meta['imageId'] != b.meta['imageId']:
                self.run_differs(a, b)

            self._logger.debug("generating and saving comparison report")
            report = self.generate_compare_report(a)
            self.anchoreDB.save_compare_report(a.meta['imageId'], report)

        for k in linkhash.keys():
            image = self.allimages[k]
            base = self.allimages[linkhash[k]]
            if image.meta['imageId'] != base.meta['imageId']:
                self._logger.debug("found image (" + image.meta['imageId'] + ") base (" + base.meta[
                    'imageId'] + "), creating softlink 'base'")
                dpath = image.anchore_imagedir + "/compare_output/base"
                if os.path.exists(dpath):
                    os.remove(dpath)
                os.symlink(image.anchore_imagedir + "/compare_output/" + base.meta['imageId'], dpath)

        if not self.skipgates:
            # execute gates
            self._logger.debug("running gates post-analysis: begin")
            for imageId in toanalyze.keys():
                c = controller.Controller(anchore_config=self.config, imagelist=[imageId], allimages=self.allimages).run_gates(refresh=True)
            self._logger.debug("running gates post-analysis: end")

        self._logger.debug("main image analysis on images: " + str(self.images) + ": end")
        return (success)
