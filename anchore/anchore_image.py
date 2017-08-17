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
import time
import tarfile

import logging

import anchore_utils

from anchore.util import contexts

DEVNULL = open(os.devnull, 'wb')

class AnchoreImage(object):
    """
    Represents a single image in the Anchore DB. On construction of the object the db is read and data loaded.
    """
    _logger = logging.getLogger(__name__)

    """ Constructors and Destructors"""

    def __del__(self):
        self._logger.debug("destructor called: " + str(self.meta))

        if self.initialized:
            self.save_image()

        if self.tmpdir and self.docleanup and os.path.exists(self.tmpdir):
            try:
                self._logger.debug("cleaning up tmpspace: " + str(self.tmpdir))
                shutil.rmtree(self.tmpdir)
            except:
                pass

    def __init__(self, imagename, allimages={}, tmpdirroot="/tmp", dockerfile=None, docker_cli=None, anchore_db=None, docker_images=None, usertype=None):
        self._logger.debug("initializing image: " + str(imagename))
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
        self.docker_history = {}

        self.meta = {'imagename': None,
                     'shortname': None,
                     'humanname': None,
                     'imageId': None,
                     'shortId': None,
                     'parentId': None,
                     'shortparentId': None,
                     'usertype': usertype,
                     'sizebytes':0}

        self.anchore_data = {}

        self.anchore_allfiles = {}
        self.anchore_allpkgs = {}
        self.anchore_familytree = None
        self.anchore_layers = None
        self.anchore_current_tags = []
        self.anchore_all_tags = []
        self.anchore_tag_history = []

        self.anchore_analyzer_meta = {}

        self.anchore_analysis_report = None
        self.anchore_gates_report = None
        self.anchore_gates_eval_report = None
        self.anchore_image_report = None

        # some contexts
        self.anchore_db = None
        self.docker_images = None
        self.anchore_config = None

        # do some setup
        # set up imageId
        try:
            result = anchore_utils.discover_imageId(imagename)
            if not result:
                raise Exception("could not locate image named ("+str(imagename)+") in anchore or local container system.")
        except Exception as err:
            raise Exception("input image name ("+str(imagename)+") is ambiguous. exception - " + str(err))

        self.meta['imageId'] = result

        if dockerfile and (os.stat(dockerfile).st_size <= 0 or not os.path.exists(dockerfile) or not os.path.isfile(dockerfile)):
            raise Exception("input dockerfile ("+str(dockerfile)+") is invalid.")

        # set up external contexts
        if docker_cli:
            self.docker_cli = docker_cli
        elif 'docker_cli' in contexts and contexts['docker_cli']:
            self.docker_cli = contexts['docker_cli']
        else:
            try:
                self.docker_cli = docker.Client(base_url='unix://var/run/docker.sock', version='auto', timeout=300)
            except Exception as err:
                self._logger.warn("could not establish connection with docker, some operations (analyze) may fail: exception: " + str(err))

        if anchore_db:
            self.anchore_db = anchore_db
        elif 'anchore_db' in contexts and contexts['anchore_db']:
            self.anchore_db = contexts['anchore_db']

        if not self.anchore_db:
            raise Exception("could not init/connect to anchoreDB")

        if docker_images:
            self.docker_images = docker_images
        elif 'docker_images' in contexts and contexts['docker_images']:
            self.docker_images = contexts['docker_images']
        else: 
            self.docker_images = anchore_utils.get_docker_images(self.docker_cli)

        if 'anchore_config' in contexts and contexts['anchore_config']:
            self.anchore_config = contexts['anchore_config']
            
        # set up metadata about the image from anchoreDB and docker
        if not self.load_image(dockerfile):
            raise Exception("could not load image information from Docker or AnchoreDB")

        # set up image directory structure
        try:
            self.anchore_db.create_image(self.meta['imageId'])
        except Exception as err:
            raise err

        # set up any additional internal members
        self.initialized = True

        self.discover_layers()
        self.discover_familytree()
        self.discover_dockerfile_contents()

        newlist = list(self.anchore_familytree)
        while self.meta['imageId'] in newlist: newlist.remove(self.meta['imageId'])
        anchore_utils.image_context_add(newlist, self.allimages, docker_cli=self.docker_cli, tmproot=self.tmpdirroot, anchore_db=self.anchore_db, docker_images=self.docker_images)

    """ Image loading, discovering and saving """
    def load_image(self, dockerfile=None):
        if self.anchore_db.is_image_present(self.meta['imageId']):
            self.load_image_from_anchore()
            self.sync_image_meta()

        # if a dockerfile is passed in, override that which is stored
        if dockerfile:
            self.dockerfile_contents = anchore_utils.read_plainfile_tostr(dockerfile)
            self.dockerfile_mode = "Actual"

        #if image is in docker, load the docker data and combine
        try:
            self.load_image_from_docker()
        except Exception as err:
            self._logger.debug("could not load image ("+str(self.meta['imageId']) + ") from docker: " + str(err))

        self.sync_image_meta()

        return (True)

    def load_image_from_anchore(self):
        anchore_data = self.anchore_db.load_image_report(self.meta['imageId'])

        self.anchore_data = anchore_data.pop('meta', {})

        self.docker_data = anchore_data.pop('docker_data', {})
        self.docker_history = anchore_data.pop('docker_history', {})
        self.dockerfile_contents = anchore_data.pop('dockerfile_contents', "")
        self.dockerfile_mode = anchore_data.pop('dockerfile_mode', None)
        
        val = anchore_data.pop('anchore_all_tags', [])
        if len(val) > 0:
            for v in val:
                if v not in self.anchore_all_tags:
                    self.anchore_all_tags.append(v)

        val = anchore_data.pop('familytree', [])
        if len(val) > 0:
            self.anchore_familytree = val

        val = anchore_data.pop('layers', [])
        if len(val) > 0:
            self.anchore_layers = val

        val = anchore_data.pop('tag_history', [])
        if len(val) > 0:
            self.anchore_tag_history = val

        return (True)

    def load_image_from_docker(self):
        try:
            ddata = {}
            hdata = {}
            Id = None

            # first get a list of docker images and search for the input image
            if self.meta['imageId'] not in self.docker_images.keys():
                self.docker_images = anchore_utils.get_docker_images(self.docker_cli)

            if self.meta['imageId'] in self.docker_images.keys():
                ddata = self.docker_cli.inspect_image(self.meta['imageId'])
                hdata = self.docker_cli.history(self.meta['imageId'])

        except Exception as err:
            raise err

        if not ddata:
            raise Exception("docker_inspect data empty")

        self.docker_data = ddata
        self.docker_history = hdata

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
            self.meta['parentId'] = self.docker_data['Parent'].replace("sha256:", "", 1)
            self.meta['shortparentId'] = self.meta['parentId'][0:12]
            if 'Size' in self.docker_data:
                self.meta['sizebytes'] = str(self.docker_data['Size'])

        self.meta['shortId'] = self.meta['imageId'][0:12]
        self.meta['imagename'] = self.meta['imageId']
        self.meta['shortname'] = self.meta['imagename'][0:12]
        self.meta['humanname'] = self.get_human_name()

        if self.dockerfile_mode == 'Actual':
            self.meta['usertype'] = 'user'
            
        return (True)

    def save_image(self):
        # generate and save image report
        report = self.generate_image_report()
        self.anchore_db.save_image_report(self.meta['imageId'], report)

    def discover_dockerfile_contents(self):
        if self.dockerfile_contents:
            return(True)

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
        self.dockerfile_contents = dbuf
        self.dockerfile_mode = "Guessed"
        return (True)

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
                    self.allimages[parent_id] = AnchoreImage(parent_id, allimages=self.allimages, tmpdirroot=self.tmpdirroot, docker_cli=self.docker_cli, anchore_db=self.anchore_db, docker_images=self.docker_images)
                nextimage = self.allimages[parent_id]
            else:
                done = 1

        self.anchore_familytree = list(familytree)
        self.anchore_familytree.reverse()

        return (True)

    def discover_layers(self):
        imagename = self.meta['imageId']
        imagedir = self.tmpdir
        layers = []

        try:
            #for i in self.docker_history:
            #    patt = re.match("sha256:(.*)", i['Id'])
            #    if patt:
            #        layers.append(patt.group(1))
            layers = [imagename]
            for i in self.docker_data['RootFS']['Layers']:
                patt = re.match("sha256:(.*)", i)
                if patt:
                    layers.append(patt.group(1))
                
        except:
            pass

        self.anchore_layers = layers
        return(True)

    def discover_layers_orig(self):
        imagename = self.meta['imageId']
        imagedir = self.tmpdir
        layers = []

        if self.anchore_layers and len(self.anchore_layers) > 0:
            return (True)

        imagedir = self.unpack()
        if not imagedir:
            self._logger.error("failed to unpack image")
            return(False)

        l = imagename

        skiptraverse = False
        if os.path.exists(imagedir + "/repositories"):
            inputf = imagedir + "/repositories"
            with open(inputf, 'r') as FH:
                json_dict = json.loads(FH.read())
            l = json_dict[imagename]["latest"]
        elif (os.path.exists(imagedir + "/manifest.json")):
            inputf = imagedir + "/manifest.json"
            with open(inputf, 'r') as FH:
                json_dict = json.loads(FH.read())
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
                with open(inputf, 'r') as FH:
                    json_dict = json.loads(FH.read())
                if "parent" in json_dict:
                    l = json_dict["parent"]
                else:
                    done = 1

        self.anchore_layers = list(layers)

        if self.tmpdir and os.path.exists(self.tmpdir):
            try:
                shutil.rmtree(self.tmpdir)
            except:
                pass

        return (True)

    """ is_ and was_ checkers """

    # if image is or was ever and Anchore base image
    def is_base(self):
        if self.meta['usertype'] == 'base' or self.meta['usertype'] == 'anchorebase':
            return (True)
        return (False)

    def is_anchore_base(self):
        # returns true only if image is the current anchore base
        if self.meta['usertype'] == 'anchorebase':
            return(True)
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
        return(self.anchore_db.is_image_analyzed(self.meta['imageId']))

    """ get_ routines """

    def get_analysis_report(self):
        if not self.anchore_analysis_report:
            self.anchore_analysis_report = self.anchore_db.load_analysis_report(self.meta['imageId'])

        return self.anchore_analysis_report

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

    def get_digests(self):
        if not self.docker_data:
            return([])

        ret = []
        if 'RepoDigests' in self.docker_data:
            for d in self.docker_data['RepoDigests']:
                ret.append(re.sub("^.*@", "", d))

        return(ret)

    def get_distro(self):
        if not self.anchore_analyzer_meta:
            self.anchore_analyzer_meta = anchore_utils.load_analysis_output(self.meta['imageId'], 'analyzer_meta', 'analyzer_meta')

        if not 'DISTRO' in self.anchore_analyzer_meta:
            return ("UNKNOWN")

        return (self.anchore_analyzer_meta['DISTRO'])

    def get_distro_vers(self):
        if not self.anchore_analyzer_meta:
            self.anchore_analyzer_meta = anchore_utils.load_analysis_output(self.meta['imageId'], 'analyzer_meta', 'analyzer_meta')

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
        return (self.anchore_familytree[0])

    def get_allfiles(self):
        if not self.anchore_allfiles:
            self.anchore_allfiles = anchore_utils.load_analysis_output(self.meta['imageId'], 'file_checksums', 'files.sha256sums')

        return (self.anchore_allfiles)

    def get_allpkgs(self):
        if not self.anchore_allpkgs:
            self.anchore_allpkgs = anchore_utils.load_analysis_output(self.meta['imageId'], 'package_list', 'pkgs.all')

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

    def get_layers(self):
        return (self.anchore_layers)

    def get_usertype(self):
        return (self.meta['usertype'])

    def get_familytree(self):
        return (self.anchore_familytree)

    """ Utilities and report generators """

    def squash(self, imagedir=None):
        driver = "docker_export"
        try:
            if self.anchore_config:
                driver = self.anchore_config['squash_driver']
        except:
            pass
            
        if driver not in ['docker_export', 'tarcmd_reverse', 'tarfile_reverse']:
            self._logger.error("invalid squash driver ("+str(driver)+") specified - please review configuration or reset to default by unsetting 'squash_driver'")
            return(False)

        if driver == 'docker_export':
            self._logger.debug("running with docker_export driver")
            return(self.squash_docker_export(imagedir))
        elif driver == 'tarcmd_reverse':
            self._logger.debug("running with tarcmd_reverse driver")
            return(self.squash_tarcmd_reverse(imagedir))
        elif driver == 'tarfile_reverse':
            self._logger.debug("running with tarfile_reverse driver")
            return(self.squash_tarfile_reverse(imagedir))

        self._logger.warn("no operation defined / squash driver found - returning success but no operation performed")
        return(True)

    def squash_docker_export(self, imagedir=None):
        if not imagedir:
            imagedir = self.tmpdir

        rootfsdir = imagedir + "/rootfs"

        if os.path.exists(imagedir + "/squashed.tar"):
            return (True)

        if not os.path.exists(rootfsdir):
            os.makedirs(rootfsdir)

        try:
            container = self.docker_cli.create_container(self.meta['imageId'], 'true')
        except Exception as err:
            self._logger.error("unable to run create container for exporting: " + str(self.meta['imageId']) + ": error: " + str(err))
            return(False)
        else:
            with open(imagedir + "/squashed.tar", 'w') as FH:
                tar = self.docker_cli.export(container.get('Id'))
                while not tar.closed:
                    FH.write(tar.read(4096*16))

        try:
            self.docker_cli.remove_container(container=container.get('Id'), force=True)
        except:
            self._logger.error("unable to delete (cleanup) temporary container - proceeding but zombie container may be left in docker: " + str(err))

        self.squashtar = imagedir + "/squashed.tar"
        
        tarcmd = ["tar", "-C", rootfsdir, "-x", "-f", self.squashtar]
        try:
            subprocess.check_output(tarcmd)
        except Exception as err:
            self._logger.error("Error: Untar of unpacked image layer failed.")
            self._logger.error("Command: " + ' '.join(tarcmd))
            self._logger.error("Exception: " + str(err))
            return(False)

        return (True)

    def squash_tarfile_reverse(self, imagedir=None):
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

        squashtarfile = tarfile.open(imagedir + '/squashed_tmp.tar', mode='w', format=tarfile.PAX_FORMAT)

        allfiles = list()
        lastexcludes = list()
        excludes = list()
        hlinks = {}
        hfiles = {}
        layerfiles = {}
        thetfile = {}

        for l in revlayer:
            layertar = imagedir + "/" + l + "/layer.tar"
            layerfiles[l] = {}

            self._logger.debug("layer to squash: " + layertar)
            layertarfile = tarfile.open(layertar, mode='r', format=tarfile.PAX_FORMAT)
            for member in layertarfile.getmembers():
                layerfiles[l][member.name] = True

                if re.match(".*\.wh\..*", member.name):
                    fsub = re.sub(r"\.wh\.", "", member.name)
                    if fsub not in allfiles:
                        if member.name not in excludes:
                            excludes.append(member.name)
                        if fsub not in excludes:
                            excludes.append(fsub)

                if member.islnk():
                    if member.linkname not in hlinks:
                        hlinks[member.linkname] = list()
                    hlinks[member.linkname].append(member.name)

                skip = False
                if member.name in allfiles:
                    skip = True
                else:
                    for p in excludes:
                        if re.match("^"+re.escape(p), member.name):
                            skip = True
                            break

                if not skip:
                    allfiles.append(member.name)
                    if member.isfile():
                        squashtarfile.addfile(member, layertarfile.extractfile(member))
                    else:
                        try:
                            squashtarfile.addfile(member, layertarfile.extractfile(member))
                        except:
                            squashtarfile.addfile(member)

            layertarfile.close()
            
        squashtarfile.close()

        newhlinkmap = {}
        if True:
            self.squashtar = imagedir + "/squashed.tar"
            squashtarfile = tarfile.open(imagedir + '/squashed_tmp.tar', mode='r', format=tarfile.PAX_FORMAT)
            finalsquashtarfile = tarfile.open(self.squashtar, mode='w', format=tarfile.PAX_FORMAT)

            for member in squashtarfile.getmembers():
                if member.islnk():
                    try:
                        testfile = squashtarfile.getmember(member.linkname)
                        finalsquashtarfile.addfile(member)
                    except:
                        if member.linkname in newhlinkmap:
                            member.linkname = newhlinkmap[member.linkname]
                            finalsquashtarfile.addfile(member)
                        else:
                            for l in revlayer:
                                if member.linkname in layerfiles[l]:
                                    layertar = imagedir + "/" + l + "/layer.tar"
                                    layertarfile = tarfile.open(layertar, mode='r', format=tarfile.PAX_FORMAT)
                                    try:
                                        testfile = layertarfile.getmember(member.linkname)
                                        testfile.name = hlinks[member.linkname][0]
                                        newhlinkmap[member.linkname] = testfile.name
                                        thefile = layertarfile.extractfile(testfile)
                                        finalsquashtarfile.addfile(testfile, thefile)
                                        break
                                    except:
                                        pass
                                    layertarfile.close()
                else:
                    try:
                        finalsquashtarfile.addfile(member, squashtarfile.extractfile(member.name))
                    except:
                        finalsquashtarfile.addfile(member)

            finalsquashtarfile.close()
            squashtarfile.close()

        self.squashtar = imagedir + "/squashed.tar"
        subprocess.check_output(["tar", "-C", rootfsdir, "-x", "-f", self.squashtar])
        return (True)

    def squash_tarcmd_reverse(self, imagedir=None):
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
        anchore_utils.touch_file(excludesfile)

        for l in revlayer:
            layertar = imagedir + "/" + l + "/layer.tar"
            self._logger.debug("layer to squash: " + layertar)

            tarcmd = ["tar", "-C", rootfsdir, "-t", "-f", layertar]
            self._logger.debug("cmd: " + ' '.join(tarcmd))
            allfiles = subprocess.check_output(tarcmd)

            with open(excludesfile, 'a') as OFH:
                for f in allfiles.splitlines():
                    if re.match('.*\.wh\..*', f):
                        fsub = re.sub(r"\.wh\.", "", f)
                        OFH.write(f + "\n")
                        OFH.write(fsub + "\n")

            tarcmd = ["tar", "-C", rootfsdir, "-X", excludesfile, "-x", "-v", "-f", layertar]
            self._logger.debug("cmd: " + ' '.join(tarcmd))

            try:
                allfiles = subprocess.check_output(tarcmd)
            except Exception as err:
                self._logger.warn("Warn: Untar of unpacked image layer failed - proceeding but not all files in image are present.")
                self._logger.warn("Command: " + ' '.join(tarcmd))
                self._logger.warn("Info: " + str(err))

            with open(excludesfile, 'a') as OFH:
                for f in allfiles.splitlines():
                    OFH.write(f + "\n")

            newfile = excludesfile + "." + l
            shutil.copy(excludesfile, newfile)
            self._logger.debug("EXCLUDES: " + newfile)

        self.squashtar = imagedir + "/squashed.tar"
        self.squashed_allfiles = subprocess.check_output(["tar", "-C", rootfsdir, "-c", "-v", "-f", self.squashtar, "."])
        return (True)

    def squash_orig_march(self, imagedir=None):
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
                            try:
                                if (os.path.islink(absfile) or os.path.isfile(absfile)):
                                    os.remove(absfile)
                                if (os.path.isdir(absfile)):
                                    shutil.rmtree(absfile)
                            except:
                                pass

        self.squashtar = imagedir + "/squashed.tar"
        self.squashed_allfiles = subprocess.check_output(
            ["tar", "-C", rootfsdir, "-c", "-v", "-f", self.squashtar, "."])
        return (True)

    def unpack(self, docleanup=True, destdir=None):
        # need docker to be up and running for this
        if not self.docker_cli:
            raise Exception("docker cli is not initialized - docker needs to be up and running before containers can be analyzed.")

        # create the work dir
        if destdir:
            imagedir = destdir + "/" + str(random.randint(0, 9999999)) + ".anchoretmp"
        else:
            imagedir = self.tmpdir

        imageId = self.meta['imageId']

        imagetar = imagedir + "/image.tar"

        self.docleanup = docleanup

        if not os.path.exists(imagedir):
            os.makedirs(imagedir)

        if False:
            # pull the image from docker and store/untar the tar
            if not os.path.exists(imagetar):
                try:
                    r = self.docker_cli.get_image(imageId)
                except:
                    try:
                        r = self.docker_cli.get_image("sha256:"+imageId)
                    except:
                        raise
                chunk_size = 1024 * 100000
                with open(imagetar, 'w') as OFH:
                    chunk = r.read(chunk_size)
                    while chunk:
                        OFH.write(chunk)
                        chunk = r.read(chunk_size)

                sout = subprocess.check_output(["tar", "-C", imagedir, "-x", "-f", imagetar], stderr=DEVNULL)

            # store some metadata and dockerfile if present
            self.meta['sizebytes'] = str(os.path.getsize(imagetar))

        if self.dockerfile_contents:
            anchore_utils.update_file_str(self.dockerfile_contents, os.path.join(imagedir, "Dockerfile"), backup=False)

        if self.docker_data:
            anchore_utils.update_file_str(json.dumps(self.docker_data), os.path.join(imagedir, "docker_inspect.json"), backup=False)

        if self.docker_history:
            anchore_utils.update_file_str(json.dumps(self.docker_history), os.path.join(imagedir, "docker_history.json"), backup=False)

        # cleanup
        if os.path.exists(imagetar):
            os.remove(imagetar)

        # squash the image layers into unpacked rootfs
        rc = self.squash(imagedir)

        if not rc:
            self._logger.error("image squash operation failed")
            return(False)

        #if self.squashtar and os.path.exists(self.squashtar):
        #    self.meta['sizebytes'] = str(os.path.getsize(self.squashtar))

        return (imagedir)

    def generate_image_report(self):
        # this routine reads the results of image analysis and generates a formatted report
        report = {}

        report['meta'] = {}
        report['docker_data'] = {}
        report['docker_history'] = {}
        report['anchore_current_tags'] = []
        report['anchore_all_tags'] = []
        report['familytree'] = []
        report['layers'] = []

        if self.meta: report['meta'] = self.meta
        if self.anchore_current_tags: report['anchore_current_tags'] = self.anchore_current_tags
        if self.anchore_all_tags: report['anchore_all_tags'] = self.anchore_all_tags
        if self.docker_data: report['docker_data'] = self.docker_data
        if self.docker_history: report['docker_history'] = self.docker_history
        if self.get_familytree(): report['familytree'] = self.get_familytree()
        if self.get_layers(): report['layers'] = self.get_layers()
        if self.dockerfile_contents: report['dockerfile_contents'] = self.dockerfile_contents
        if self.dockerfile_mode: report['dockerfile_mode'] = self.dockerfile_mode

        return (report)

    def get_dockerfile_contents(self):
        modestr = "N/A"
        dbuf = ""
        if self.dockerfile_contents:
            dbuf = self.dockerfile_contents
        if self.dockerfile_mode:
            modestr = self.dockerfile_mode

        return ([dbuf, modestr])
