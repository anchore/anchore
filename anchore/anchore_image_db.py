import json

import os
import time
import anchore_utils

DEVNULL = open(os.devnull, 'wb')


class AnchoreImageDB(object):
    _db_metadata_filename = 'anchore_db_meta.json'

    def __del__(self):
        if self.initialized:
            pass

    @staticmethod
    def exists(path, with_expected_db_version=None):
        """
        Does the db exist, optionally with the expected version
        :param path:
        :param with_expected_db_version:
        :return:
        """
        dbmetafile = os.path.join(path, AnchoreImageDB._db_metadata_filename)

        if not os.path.exists(path) or not os.path.exists(dbmetafile):
            return False

        if with_expected_db_version:
            with open(dbmetafile, 'r') as f:
                json_dict = json.load(f)

            if json_dict['anchore_db_version'] != with_expected_db_version:
                return False
        else:
            return True

    def __init__(self, imagerootdir):
        self.initialized = False
        self.imagerootdir = imagerootdir

        try:
            from anchore import version as anchore_version_string
            if not os.path.exists(self.imagerootdir):
                raise Exception("anchore DB: image root dir does not exist "+str(imagerootdir))

            # check that the software and DB are same version before continuing
            dbmetafile = '/'.join([self.imagerootdir, "anchore_db_meta.json"])
            if not os.path.exists(dbmetafile):
                FH=open(dbmetafile, 'w')
                FH.write(json.dumps({}))
                FH.close()

            update = False

            FH=open(dbmetafile, 'r')
            json_dict = json.loads(FH.read())
            FH.close()
            if 'anchore_version' not in json_dict:
                json_dict['anchore_version'] = anchore_version_string
                update = True
            if 'anchore_db_version' not in json_dict:
                json_dict['anchore_db_version'] = anchore_version_string
                update = True
            elif json_dict['anchore_db_version'] < anchore_version_string:
                # Check major version
                local_db_version = json_dict['anchore_db_version']
                db_version_tuple = tuple(local_db_version.split('.'))
                code_version_tuple = tuple(anchore_version_string.split('.'))
                if db_version_tuple[0] < code_version_tuple[0]:
                    raise Exception("Anchore DB version ("+local_db_version + ") " +
                                    "is at least one major-version behind the Anchore software version (" + anchore_version_string + ")")

            if update:
                FH=open(dbmetafile, 'w')
                FH.write(json.dumps(json_dict))
                FH.close()

        except Exception as err:
            raise err

        self.initialized = True

    def load_all_images(self):
        ret = []
        
        for d in os.listdir(self.imagerootdir):
            try:
                result = self.load_image(d)
                if result['meta']['imageId'] not in ret:
                    ret.append(result['meta']['imageId'])
            except Exception as err:
                pass
            
        return(ret)

    def load_image(self, imageId):
        # populate all anchore data into image
        imagedir = self.imagerootdir + "/" + imageId
        analyzer_meta = {}
        allfiles = {}
        allpkgs = {}
        familytree = []
        layers = []

        if not os.path.exists(imagedir):
            # image has not been analyzed
            return(False)

        report = self.load_analysis_report(imageId)

        if 'file_checksums' in report:
            filelist = report['file_checksums'].pop('files.md5sums', None)
            for line in filelist:
                line = line.strip()
                (k, v) = line.split()
                allfiles[k] = v

            
        if 'package_list' in report:
            pkglist = report['package_list'].pop('pkgs.all', None)
            for line in pkglist:
                line = line.strip()
                (k, v) = line.split()
                allpkgs[k] = v

        if 'analyzer_meta' in report:
            ameta = report['analyzer_meta'].pop('analyzer_meta', None)
            analyzer_meta = {}
            for line in ameta:
                line = line.strip()
                (key, val) = line.split()
                analyzer_meta[key] = val

        report = self.load_image_report(imageId)

        familytree = report.pop('familytree', list())        
        layers = report.pop('layers', list())
        meta = report.pop('meta', {})
        all_tags = report.pop('anchore_all_tags', list())
        current_tags = report.pop('anchore_current_tags', list())
        tag_history = report.pop('tag_history', list())

        ret = {}
        ret['meta'] = meta
        ret['allfiles'] = allfiles
        ret['allpkgs'] = allpkgs
        ret['familytree'] = familytree
        ret['layers'] = layers
        ret['analyzer_meta'] = analyzer_meta
        ret['all_tags'] = all_tags
        ret['current_tags'] = current_tags
        ret['tag_history'] = tag_history
        
        return(ret)

    def load_analysis_report(self, imageId):
        thefile = self.imagerootdir + "/" + imageId + "/reports/analysis_report.json"
        if not os.path.exists(thefile):
            return({})

        FH = open(thefile, 'r')
        ret = json.loads(FH.read())
        FH.close()
        return(ret)

    def save_analysis_report(self, imageId, report):
        thedir = self.imagerootdir + "/" + imageId + "/reports/"
        if not os.path.exists(thedir):
            os.makedirs(thedir)
        thefile = thedir + "/analysis_report.json"
        anchore_utils.update_file_jsonstr(json.dumps(report), thefile, False)

    def load_compare_report(self, imageId):
        thefile = self.imagerootdir + "/" + imageId + "/reports/compare_report.json"
        if not os.path.exists(thefile):
            return({})

        FH = open(thefile, 'r')
        ret = json.loads(FH.read())
        FH.close()
        
        return(ret)

    def save_compare_report(self, imageId, report):
        thedir = self.imagerootdir + "/" + imageId + "/reports/"
        if not os.path.exists(thedir):
            os.makedirs(thedir)
        thefile = thedir + "/compare_report.json"
        anchore_utils.update_file_jsonstr(json.dumps(report), thefile, False)

    def load_gates_report(self, imageId):
        thefile = self.imagerootdir + "/" + imageId + "/reports/gates_report.json"
        if not os.path.exists(thefile):
            return({})

        FH = open(thefile, 'r')
        ret = json.loads(FH.read())
        FH.close()
        return(ret)

    def save_gates_report(self, imageId, report):
        thedir = self.imagerootdir + "/" + imageId + "/reports/"
        if not os.path.exists(thedir):
            os.makedirs(thedir)
        thefile = thedir + "/gates_report.json"
        anchore_utils.update_file_jsonstr(json.dumps(report), thefile, False)

    def load_gates_eval_report(self, imageId):
        thefile = self.imagerootdir + "/" + imageId + "/reports/gates_eval_report.json"
        if not os.path.exists(thefile):
            return({})

        FH = open(thefile, 'r')
        ret = json.loads(FH.read())
        FH.close()
        return(ret)

    def save_gates_eval_report(self, imageId, report):
        thedir = self.imagerootdir + "/" + imageId + "/reports/"
        if not os.path.exists(thedir):
            os.makedirs(thedir)
        thefile = thedir + "/gates_eval_report.json"
        anchore_utils.update_file_jsonstr(json.dumps(report), thefile, False)

    def load_image_report(self, imageId):
        thefile = self.imagerootdir + "/" + imageId + "/reports/image_report.json"
        if not os.path.exists(thefile):
            return({})

        FH = open(thefile, 'r')
        ret = json.loads(FH.read())
        FH.close()
        return(ret)

    def save_image_report(self, imageId, report):
        date = str(int(time.time()))
        thedir = self.imagerootdir + "/" + imageId + "/reports/"
        if not os.path.exists(thedir):
            os.makedirs(thedir)
        thefile = thedir + "/image_report.json"

        if os.path.exists(thefile):
            oldreport = self.load_image_report(imageId)
            if 'tag_history' in oldreport:
                report['tag_history'] = list(oldreport['tag_history'])
            else:
                report['tag_history'] = list()

            if 'anchore_current_tags' not in oldreport:
                oldreport['anchore_current_tags'] = list([date, report['anchore_current_tags']])

            diff = list(set(oldreport['anchore_current_tags']).symmetric_difference(set(report['anchore_current_tags'])))
            if len(diff) > 0:
                # there is a difference between stored tags and new tags
                report['tag_history'].append([date, oldreport['anchore_current_tags']])
        
        if 'tag_history' not in report:
            report['tag_history'] = list()

        if len(report['tag_history']) <= 0:
            report['tag_history'].append([date, report['anchore_current_tags']])

        anchore_utils.update_file_jsonstr(json.dumps(report), thefile, False)
