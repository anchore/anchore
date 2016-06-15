import json
import random
import shutil
import subprocess
from textwrap import fill

import docker
import sys
import os
import re
from prettytable import PrettyTable

import logging

import anchore_image_db
import anchore_utils

DEVNULL = open(os.devnull, 'wb')

class AnchoreImage(object):
    """
    Represents a single image in the Anchore DB. On construction of the object the db is read and data loaded.
    """
    _logger = logging.getLogger(__name__)

    """ Constructors and Destructors"""

    def __del__(self):
        if self.initialized:
            self.save_image()

        if self.tmpdir and self.docleanup and os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def __init__(self, imagename, anchore_image_datadir, allimages, tmpdirroot="/tmp", dockerfile=None, docker_cli=None, anchore_db=None, usertype=None):
        # all members
        self.allimages = allimages
        self.initialized = False
        self.docleanup = True
        self.tmpdirroot = tmpdirroot
        self.tmpdir = '/'.join([self.tmpdirroot, str(random.randint(0, 9999999)) + ".anchoretmp"])

        self.dockerfile = dockerfile
        self.dockerfile_contents = None
        self.dockerfile_mode = None
        self.docker_cli = None
        self.docker_data = {}
        self.docker_data_json = ""

        self.meta = {'imagename': imagename,
                     'shortname': None,
                     'humanname': None,
                     'imageId': None,
                     'shortId': None,
                     'parentId': None,
                     'shortparentId': None,
                     'usertype': usertype}

        self.anchore_image_datadir = None
        self.anchore_imagedir = None

        self.anchore_data = {}
        self.anchore_data_json = ""
        self.anchore_allfiles = {}
        self.anchore_allpkgs = {}
        self.anchore_familytree = None
        self.anchore_layers = None
        self.anchore_current_tags = []
        self.anchore_all_tags = []
        self.anchore_tag_history = []

        self.anchore_analyzer_meta_json = None
        self.anchore_analyzer_meta = None

        self.anchore_analysis_report = None
        self.anchore_compare_report = None
        self.anchore_gates_report = None
        self.anchore_gates_eval_report = None
        self.anchore_image_report = None

        self.anchore_db = None

        # do some setup
        patt = re.compile('[0-9a-fA-F]+')
        if (len(self.meta['imagename']) == 64 and patt.match(self.meta['imagename'])):
            # imagename is a docker long uuid
            self.meta['shortname'] = self.meta['imagename'][0:12]
        else:
            # image name is a non-uuid or a short uuid
            self.meta['shortname'] = self.meta['imagename']

        if docker_cli:
            self.docker_cli = docker_cli
        else:
            self.docker_cli = docker.Client(base_url='unix://var/run/docker.sock')

        self.anchore_image_datadir = anchore_image_datadir
        if not os.path.exists(self.anchore_image_datadir):
            os.makedirs(self.anchore_image_datadir)

        if anchore_db:
            self.anchore_db = anchore_db
        else: 
            self.anchore_db = anchore_image_db.AnchoreImageDB(imagerootdir=self.anchore_image_datadir)

        # set up metadata about the image from anchore and docker
        if not self.load_image():
            raise Exception("could not load image from Docker or Anchore")

        # set up image directory structure
        try:
            self.outputdirs = {'image': 'image_output', 'analyzer': 'analyzer_output', 'compare': 'compare_output', 'gate': 'gates_output'}
            for d in self.outputdirs.keys():
                thedir = '/'.join([self.anchore_imagedir, self.outputdirs[d]])
                if not os.path.exists(thedir):
                    os.makedirs(thedir)
        except Exception as err:
            raise err

        # set up any additional internal members
        self.initialized = True

        self.discover_layers()
        self.discover_familytree()

        newlist = list(self.anchore_familytree)
        while self.meta['imageId'] in newlist: newlist.remove(self.meta['imageId'])
        anchore_utils.image_context_add(newlist, self.allimages, docker_cli=self.docker_cli, anchore_datadir=self.anchore_image_datadir, tmproot=self.tmpdirroot, anchore_db=self.anchore_db)

        # Dockerfile handling
        if self.dockerfile:
            shutil.copy(self.dockerfile, self.anchore_imagedir + "/Dockerfile")

        if os.path.exists(self.anchore_imagedir + "/Dockerfile"):
            self.dockerfile_contents = anchore_utils.read_plainfile_tostr(self.anchore_imagedir + "/Dockerfile")
            self.dockerfile_mode = 'Actual'
            self.meta['usertype'] = 'user'
        elif os.path.exists(self.anchore_imagedir + "/Dockerfile.guessed"):
            self.dockerfile_contents = anchore_utils.read_plainfile_tostr(self.anchore_imagedir + "/Dockerfile.guessed")
            self.dockerfile_mode = 'Guessed'
        else:
            self.dockerfile_contents = self.discover_dockerfile_contents()
            self.dockerfile_mode = 'Guessed'

    """ Image loading, discovering and saving """

    def load_image(self):
        if os.path.exists('/'.join([self.anchore_image_datadir,self.meta['imagename']])):
            self.meta['imageId'] = self.meta['imagename']

        try:
            self.load_image_from_docker()
        except:
            pass

        self.sync_image_meta()

        if not self.meta['imageId']:
            return (False)

        self.anchore_imagedir = '/'.join([self.anchore_image_datadir, self.meta['imageId']])
        if not os.path.exists(self.anchore_imagedir):
            os.makedirs(self.anchore_imagedir)

        self.load_image_from_anchore()
        self.sync_image_meta()

        return (True)

    def load_image_from_anchore(self):
        #anchore_data = anchore_image_db.AnchoreImageDB(imagerootdir=self.anchore_image_datadir).load_image(self.meta['imageId'])
        anchore_data = self.anchore_db.load_image(self.meta['imageId'])

        self.anchore_data = anchore_data.pop('meta', {})
        self.anchore_data_json = json.dumps(self.anchore_data)

        val = anchore_data.pop('all_tags', [])
        if len(val) > 0:
            for v in val:
                if v not in self.anchore_all_tags:
                    self.anchore_all_tags.append(v)

        self.anchore_allfiles = anchore_data.pop('allfiles', {})

        self.anchore_allpkgs = anchore_data.pop('allpkgs', {})

        val = anchore_data.pop('familytree', [])
        if len(val) > 0:
            self.anchore_familytree = val

        val = anchore_data.pop('layers', [])
        if len(val) > 0:
            self.anchore_layers = val

        val = anchore_data.pop('tag_history', [])
        if len(val) > 0:
            self.anchore_tag_history = val

        self.anchore_analyzer_meta = anchore_data.pop('analyzer_meta', {})

        self.anchore_other = {}
        if (len(anchore_data.keys()) > 0):
            self.anchore_other = anchore_data.copy()

        return (True)

    def load_image_from_docker(self):
        imagename = self.meta['imagename']
        shortname = self.meta['shortname']

        self.docker_data = self.docker_cli.inspect_image(shortname)
        self.docker_data_json = json.dumps(self.docker_data)

        for t in self.docker_data['RepoTags']:
            if t not in self.anchore_current_tags:
                self.anchore_current_tags.append(t)
            if t not in self.anchore_all_tags:
                self.anchore_all_tags.append(t)

        return (True)

    def sync_image_meta(self):
        for k in self.anchore_data.keys():
            if not k in self.meta or not self.meta[k]:
                self.meta[k] = self.anchore_data[k]

        if self.docker_data:
            self.meta['imageId'] = self.docker_data['Id'].replace("sha256:", "", 1)
            self.meta['shortId'] = self.meta['imageId'][0:12]
            self.meta['parentId'] = self.docker_data['Parent'].replace("sha256:", "", 1)
            self.meta['shortparentId'] = self.meta['parentId'][0:12]

        self.meta['humanname'] = self.get_human_name()
        return (True)

    def save_image(self):
        # Dockerfile handling
        if self.dockerfile_contents:
            if self.dockerfile_mode == 'Guessed':
                anchore_utils.update_file_str(self.dockerfile_contents, self.anchore_imagedir + "/Dockerfile.guessed", backup=False)
            elif self.dockerfile_mode == 'Actual':
                anchore_utils.update_file_str(self.dockerfile_contents, self.anchore_imagedir + "/Dockerfile", backup=False)
                if os.path.exists(self.anchore_imagedir + "/Dockerfile.guessed"):
                    os.remove(self.anchore_imagedir + "/Dockerfile.guessed")

        # Image output dir populate
        imageoutputdir = self.anchore_imagedir + "/image_output/image_info"
        if not os.path.exists(imageoutputdir):
            os.makedirs(imageoutputdir)

        anchore_utils.write_kvfile_fromdict(imageoutputdir + "/image.meta", self.meta)

        level = 0
        tagdict = {}
        for t in self.anchore_current_tags:
            tagdict[t] = str(level)
            level = level + 1
        anchore_utils.write_kvfile_fromdict(imageoutputdir + "/image_current.tags", tagdict)


        level = 0
        tagdict = {}
        for t in self.anchore_all_tags:
            tagdict[t] = str(level)
            level = level + 1
        anchore_utils.write_kvfile_fromdict(imageoutputdir + "/image_all.tags", tagdict)

        dfile = self.get_dockerfile()
        if dfile:
            shutil.copy(dfile, imageoutputdir + "/Dockerfile")

        if not os.path.exists(self.anchore_imagedir + "/image_output/image_familytree/"):
            os.makedirs(self.anchore_imagedir + "/image_output/image_familytree/")

        level = 0
        ldict = {}
        for fid in self.get_layers():
            ldict[fid] = str(level)
            level = level + 1
        anchore_utils.write_kvfile_fromdict(self.anchore_imagedir + "/image_output/image_familytree/layers", ldict)

        level = 0
        ldict = {}
        for fid in self.get_familytree():
            ldict[fid] = str(level)
            src = '/'.join([self.anchore_image_datadir, fid])
            dst = '/'.join([self.anchore_imagedir, "/image_output/image_familytree/", fid])
            try:
                os.remove(dst)
            except:
                pass
            os.symlink(src, dst)

            level = level + 1
            if self.get_earliest_base() == fid:
                src = '/'.join([self.anchore_image_datadir, fid])
                dst = '/'.join([self.anchore_imagedir, "/image_output/image_familytree/base"])
                try:
                    os.remove(dst)
                except:
                    pass
                os.symlink(src, dst)
        anchore_utils.write_kvfile_fromdict(self.anchore_imagedir + "/image_output/image_familytree/familytree", ldict)

        # generate and save image report
        report = self.generate_image_report()
        self.anchore_db.save_image_report(self.meta['imageId'], report)

    def discover_dockerfile_contents(self):
        dbuf = ""
        try:
            history = self.docker_cli.history(self.meta['imageId'])
        except:
            return (False)
        lbase = None
        cmds = list()
        for h in history:
            lid = cmd = None
            if 'Id' in h:
                lid = h['Id'].replace("sha256:", "", 1)
            if 'CreatedBy' in h:
                cmd = h['CreatedBy']

            if lid and cmd:
                if lid in self.allimages:
                    limage = self.allimages[lid]
                    if lid != self.meta['imageId'] and (limage.is_anchore_base() or limage.was_anchore_base()):
                        if not lbase:
                            lbase = limage.meta['imageId']
                if not lbase:
                    cmds.append(cmd)

        cmds.reverse()
        if lbase:
            limage = self.allimages[lbase]
            thetag = None
            patt = re.compile(".*latest.*")
            for t in limage.get_alltags_ever():
                if patt.match(t):
                    thetag = t
                    break
                thetag = t
            if thetag:
                dbuf = dbuf + "FROM " + thetag + "\n"
            else:
                dbuf = dbuf + "FROM <UNKNOWN>\n"
        else:
            dbuf = dbuf + "FROM scratch\n"

        if len(cmds) > 0:
            patt = re.compile(".*#\(nop\).*")
            for c in cmds:
                if not patt.match(c):
                    dbuf = dbuf + "RUN " + c + "\n"
                else:
                    c = re.sub(r"^/bin/sh -c #\(nop\) ", "", c)
                    dbuf = dbuf + c + "\n"
        return (dbuf)

    def discover_familytree(self):
        familytree = list()

        if self.anchore_familytree and len(self.anchore_familytree) > 0:
            return (True)

        nextimage = self
        done = 0
        while not done:
            image_id = nextimage.meta['imageId']
            parent_id = nextimage.meta['parentId']
            if image_id: familytree.append(image_id)
            if parent_id:
                if parent_id not in self.allimages:
                    self.allimages[parent_id] = AnchoreImage(parent_id,
                                                             anchore_image_datadir=self.anchore_image_datadir,
                                                             allimages=self.allimages, tmpdirroot=self.tmpdirroot,
                                                             docker_cli=self.docker_cli)
                nextimage = self.allimages[parent_id]
            else:
                done = 1

        self.anchore_familytree = list(familytree)
        self.anchore_familytree.reverse()

        return (True)

    def discover_layers(self):
        imagename = self.meta['imageId']
        imagedir = self.tmpdir
        layers = list()

        if self.anchore_layers and len(self.anchore_layers) > 0:
            return (True)

        imagedir = self.unpack()

        l = imagename

        skiptraverse = False
        if os.path.exists(imagedir + "/repositories"):
            inputf = imagedir + "/repositories"
            FH = open(inputf, 'r')
            json_dict = json.loads(FH.read())
            FH.close()
            l = json_dict[imagename]["latest"]
        elif (os.path.exists(imagedir + "/manifest.json")):
            inputf = imagedir + "/manifest.json"
            FH = open(inputf, 'r')
            json_dict = json.loads(FH.read())
            FH.close()
            layerfiles = json_dict[0]["Layers"]
            for layer in layerfiles:
                (l, tfile) = layer.split('/')
                layers.append(l)
                skiptraverse = True

        if not skiptraverse:
            done = 0
            while not done:
                layers.append(l)
                inputf = imagedir + "/" + l + "/json"
                FH = open(inputf, 'r')
                json_dict = json.loads(FH.read())
                if "parent" in json_dict:
                    l = json_dict["parent"]
                else:
                    done = 1
                    FH.close()

        self.anchore_layers = list(layers)

        if self.tmpdir and os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

        return (True)

    """ is_ and was_ checkers """

    # if image is or was ever and Anchore base image
    def is_base(self):
        if self.meta['usertype'] == 'base' or self.meta['usertype'] == 'anchorebase':
            return (True)
        return (False)

    def is_anchore_base(self):
        # returns true only if image is the current anchore base
        if os.path.exists(self.anchore_image_datadir + "/analysis_mapping.json"):
            FH = open(self.anchore_image_datadir + "/analysis_mapping.json", 'r')
            latest_anchore_images = json.loads(FH.read())
            FH.close()
        else:
            latest_anchore_images = self.docker_cli.images(all=True, filters={'dangling': False})

        if self.meta['usertype'] == 'anchorebase':
            for i in latest_anchore_images:
                patt = re.compile('.*' + self.meta['imageId'] + '.*')
                if patt.match(i['Id']):
                    return (True)
            self.meta['usertype'] == 'oldanchorebase'
        return (False)

    def was_anchore_base(self):
        # returns True if image was an anchore base image, but is no longer
        if self.meta['usertype'] == 'oldanchorebase':
            return (True)

        return (False)

    # if image ever was analyzed with a given dockerfile
    def is_user(self):
        if self.meta['usertype'] == 'user':
            return (True)
        return (False)

    def is_intermediate(self):
        if not self.meta['usertype'] or self.meta['usertype'] == 'none':
            return (True)
        return (False)

    def is_analyzed(self):
        return os.path.exists(self.anchore_imagedir + "/analyzers.done")

    """ get_ routines """

    def get_analysis_report(self):
        if not self.anchore_analysis_report:
            self.anchore_analysis_report = self.anchore_db.load_analysis_report(self.meta['imageId'])

        return self.anchore_analysis_report

    def get_compare_report(self):
        if not self.anchore_compare_report:
            self.anchore_compare_report = self.anchore_db.load_compare_report(self.meta['imageId'])

        return self.anchore_compare_report

    def get_image_report(self):
        if not self.anchore_image_report:
            self.anchore_image_report = self.anchore_db.load_image_report(self.meta['imageId'])

        return self.anchore_image_report

    def get_gates_report(self):
        if not self.anchore_gates_report:
            self.anchore_gates_report = self.anchore_db.load_gates_report(self.meta['imageId'])

        return self.anchore_gates_report

    def get_gates_eval_report(self):
        if not self.anchore_gates_eval_report:
            self.anchore_gates_eval_report = self.anchore_db.load_gates_eval_report(self.meta['imageId'])

        return self.anchore_gates_eval_report

    def get_distro(self):
        if not 'DISTRO' in self.anchore_analyzer_meta:
            return ("UNKNOWN")

        return (self.anchore_analyzer_meta['DISTRO'])

    def get_distro_vers(self):
        if not 'DISTROVERS' in self.anchore_analyzer_meta:
            return ("")

        return (self.anchore_analyzer_meta['DISTROVERS'])

    def get_latest_userimage(self):
        revtree = list(self.get_familytree())
        revtree.reverse()
        for i in revtree[1:]:
            image = self.allimages[i]
            if image.is_user():
                return (i)
        return (None)

    def get_earliest_anchore_base(self):
        for fid in self.get_familytree():
            if fid in self.allimages.keys():
                fimage = self.allimages[fid]
                if fimage.is_base():
                    return (fid)
        return None

    def get_earliest_base(self):
        # for i in self.get_familytree():
        #    image = self.allimages[i]
        #    if image.is_base():
        #        return(image['imageId'])
        # return(None)
        return (self.anchore_familytree[0])

    def get_allfiles(self):
        if not self.anchore_allfiles:
            self.load_image_from_anchore()

        return (self.anchore_allfiles)

    def get_allpkgs(self):
        if not self.anchore_allpkgs:
            self.load_image_from_anchore()

        return (self.anchore_allpkgs)

    def get_human_string(self):
        return (self.meta['shortId'] + " (" + self.get_human_name() + ")")

    def get_human_name(self):
        if self.meta['humanname']:
            return (self.meta['humanname'])

        alltags = self.get_alltags_ever()
        if len(alltags) > 0:
            patt = re.compile(".*latest.*")
            for t in alltags:
                othertag = t
                if patt.match(t):
                    self.meta['humanname'] = t
                    return (self.meta['humanname'])

            self.meta['humanname'] = othertag
            return (self.meta['humanname'])
        return (self.meta['shortId'])

    # gets list of all tags that anchore has ever seen
    def get_alltags_ever(self):
        return (self.anchore_all_tags)

    # gets all known tags from past (excluding current tags) anchore analysis data
    def get_alltags_past(self):
        return (list(set(self.anchore_all_tags) - set(self.anchore_current_tags)))

    # gets all current tags
    def get_alltags_current(self):
        return (self.anchore_current_tags)

    def get_tag_history(self):
        return (self.anchore_tag_history)

    def get_imagedir(self):
        return (self.anchore_imagedir)

    def get_layers(self):
        return (self.anchore_layers)

    def get_usertype(self):
        return (self.meta['usertype'])

    def get_familytree(self):
        return (self.anchore_familytree)

    def get_dockerfile(self):
        if os.path.exists(self.anchore_imagedir + "/Dockerfile"):
            return (self.anchore_imagedir + "/Dockerfile")
        elif os.path.exists(self.anchore_imagedir + "/Dockerfile.guessed"):
            return (self.anchore_imagedir + "/Dockerfile.guessed")
        return (False)

    """ Utilities and report generators """

    def squash(self, imagedir=None):
        if not imagedir:
            imagedir = self.tmpdir

        rootfsdir = imagedir + "/rootfs"

        if os.path.exists(imagedir + "/squashed.tar"):
            return (True)

        if not self.anchore_layers:
            return (False)

        if not os.path.exists(rootfsdir):
            os.makedirs(rootfsdir)

        revlayer = list(self.anchore_layers)
        revlayer.reverse()

        excludesfile = '/'.join([imagedir, 'tarexcludes'])
        open(excludesfile, 'w').close()

        for l in revlayer:
            layertar = imagedir + "/" + l + "/layer.tar"
            self._logger.debug("layer to squash: " + layertar)

            tarcmd = ["tar", "-C", rootfsdir, "-t", "-f", layertar]
            self._logger.debug("cmd: " + ' '.join(tarcmd))

            allfiles = subprocess.check_output(tarcmd)
            OFH=open(excludesfile, 'a')
            for f in allfiles.splitlines():
                if re.match('.*\.wh\..*', f):
                    fsub = re.sub(r"\.wh\.", "", f)
                    OFH.write(f + "\n")
                    OFH.write(fsub + "\n")
            OFH.close()

            tarcmd = ["tar", "-C", rootfsdir, "-X", excludesfile, "-x", "-v", "-f", layertar]
            self._logger.debug("cmd: " + ' '.join(tarcmd))

            try:
                allfiles = subprocess.check_output(tarcmd)
            except Exception as err:
                self._logger.warn("Warn: Untar of unpacked image layer failed - proceeding but not all files in image are present.")
                self._logger.warn("Command: " + ' '.join(tarcmd))
                self._logger.warn("Info: " + str(err))

            OFH=open(excludesfile, 'a')
            for f in allfiles.splitlines():
                OFH.write(f + "\n")
            OFH.close()

        self.squashtar = imagedir + "/squashed.tar"
        self.squashed_allfiles = subprocess.check_output(["tar", "-C", rootfsdir, "-c", "-v", "-f", self.squashtar, "."])
        return (True)

    def squash_orig(self, imagedir=None):
        if not imagedir:
            imagedir = self.tmpdir

        rootfsdir = imagedir + "/rootfs"

        if os.path.exists(imagedir + "/squashed.tar"):
            return (True)

        if not self.anchore_layers:
            return (False)

        if not os.path.exists(rootfsdir):
            os.makedirs(rootfsdir)

        for l in self.anchore_layers:
            layertar = imagedir + "/" + l + "/layer.tar"
            allfiles = subprocess.check_output(["tar", "-C", rootfsdir, "-x", "-v", "-f", layertar])
            for f in allfiles.splitlines():
                patt = re.compile('.*\.wh\..*')
                if (patt.match(f)):
                    fsub = re.sub(r"\.wh\.", "", f)
                    absfiles = list()
                    absfiles.append(rootfsdir + "/" + f)
                    absfiles.append(rootfsdir + "/" + fsub)

                    for absfile in absfiles:
                        if (os.path.exists(absfile)):
                            if (os.path.islink(absfile) or os.path.isfile(absfile)):
                                os.remove(absfile)
                            if (os.path.isdir(absfile)):
                                shutil.rmtree(absfile)

        self.squashtar = imagedir + "/squashed.tar"
        self.squashed_allfiles = subprocess.check_output(
            ["tar", "-C", rootfsdir, "-c", "-v", "-f", self.squashtar, "."])
        return (True)

    def unpack(self, docleanup=True, destdir=None):
        if destdir:
            imagedir = destdir + "/" + str(random.randint(0, 9999999)) + ".anchoretmp"
        else:
            imagedir = self.tmpdir

        shortid = self.meta['shortId']
        imagetar = imagedir + "/image.tar"

        self.docleanup = docleanup

        if not os.path.exists(imagedir):
            os.makedirs(imagedir)

        if not os.path.exists(imagetar):
            FH = open(imagetar, 'w')
            FH.write(self.docker_cli.get_image(shortid).data)
            FH.close()
            sout = subprocess.check_output(["tar", "-C", imagedir, "-x", "-f", imagetar], stderr=DEVNULL)

        self.squash(imagedir)
        return (imagedir)

    def generate_image_report(self):
        # this routine reads the results of image analysis and generates a formatted report
        report = {}

        report['meta'] = {}
        report['docker_data'] = {}
        report['anchore_current_tags'] = []
        report['anchore_all_tags'] = []
        report['familytree'] = []
        report['layers'] = []

        if self.meta: report['meta'] = self.meta
        if self.anchore_current_tags: report['anchore_current_tags'] = self.anchore_current_tags
        if self.anchore_all_tags: report['anchore_all_tags'] = self.anchore_all_tags
        if self.docker_data: report['docker_data'] = self.docker_data
        if self.get_familytree(): report['familytree'] = self.get_familytree()
        if self.get_layers(): report['layers'] = self.get_layers()

        return (report)

    def get_dockerfile_contents(self):
        ret = ["", "NA"]

        modestr = "NA"
        dbuf = ""
        if os.path.exists(self.anchore_imagedir + "/Dockerfile"):
            modestr = "Actual"
            dbuf = self.dockerfile_contents
            #dbuf = anchore_utils.read_plainfile_tostr(self.anchore_imagedir + "/Dockerfile")
        else:
            modestr = "Guessed"
            dbuf = self.dockerfile_contents
            #dbuf = self.discover_dockerfile_contents()

        return ([dbuf, modestr])
