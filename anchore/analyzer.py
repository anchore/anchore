import os
import logging

import anchore_image_db
import controller
from anchore import anchore_utils
from anchore.util import scripting
from anchore.util import contexts


class Analyzer(object):
    _logger = logging.getLogger(__name__)

    def __init__(self, anchore_config, imagelist, allimages, force, args=None, docker_cli=None):
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
        
        self.images = anchore_utils.image_context_add(imagelist, allimages, docker_cli=docker_cli, dockerfile=self.dockerfile, anchore_datadir=self.anchore_datadir, tmproot=self.config['tmpdir'], anchore_db=contexts['anchore_db'], usertype=usertype, must_load_all=True)

        self._logger.debug("loaded input images, checking that all input images have been loaded " + str(self.images))

        self.anchoreDB = contexts['anchore_db']

        self._logger.debug("analyzer initialization: end")

    def get_images(self):
        return(self.images)

    def run_analyzers(self, image):
        self._logger.debug("running analyzers on image: " + str(image.meta['imagename']) + ": begin")

        imagename = image.meta['imagename']
        outputdir = image.anchore_imagedir
        shortid = image.meta['shortId']
        analyzerdir = '/'.join([self.config["scripts_dir"], "analyzers"])

        if not self.force and os.path.exists(outputdir + "/analyzers.done"):
            self._logger.debug("image already analyzed and --force was not specified, nothing to do")
            self._logger.info(image.meta['shortId'] + ": analyzed.")

            return (True)

        self._logger.info(image.meta['shortId'] + ": analyzing ...")

        if not os.path.exists(outputdir):
            self._logger.debug("outputdir '" + str(outputdir) + "'not found, creating")
            os.makedirs(outputdir)

        self._logger.debug("unpacking image")
        imagedir = image.unpack()
        self._logger.debug("finished unpacking image to directory: " + str(imagedir))

        self._logger.debug("running all analyzers on image")
        results = scripting.ScriptSetExecutor(path=analyzerdir).execute(capture_output=True, fail_fast=True,
                                                                        cmdline=' '.join(
                                                                            [imagename, self.config['image_data_store'], outputdir, imagedir]))
        self._logger.debug("analyzers done running" + str(len(results)))

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

            anchore_utils.touch_file(outputdir + "/analyzers.done")

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

        if not self.force and os.path.exists(
                                        outputdir + "/compare_output/" + baseimage.meta['imageId'] + "/differs.done"):
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

        self._logger.debug("getting analysis reports for images")
        areport = image.get_analysis_report()
        breport = baseimage.get_analysis_report()

        self._logger.debug("performing comparison")
        for azkey in areport.keys():
            if azkey in breport:
                for aokey in areport[azkey].keys():
                    if aokey in breport[azkey]:
                        outputdict = {}

                        adatadict = {}
                        for l in areport[azkey][aokey]:
                            l = l.strip()
                            (k, v) = l.split()
                            adatadict[k] = v

                        bdatadict = {}
                        for l in breport[azkey][aokey]:
                            l = l.strip()
                            (k, v) = l.split()
                            bdatadict[k] = v

                        for dkey in adatadict.keys():
                            if not dkey in bdatadict:
                                outputdict[dkey] = "INIMG_NOTINBASE"
                            elif adatadict[dkey] != bdatadict[dkey]:
                                outputdict[dkey] = "VERSION_DIFF"

                        for dkey in bdatadict.keys():
                            if not dkey in adatadict:
                                outputdict[dkey] = "INBASE_NOTINIMG"

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
