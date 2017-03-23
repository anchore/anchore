import json
import re
import os
import shutil
import time
import logging
import tarfile

from anchore import anchore_utils

DEVNULL = open(os.devnull, 'wb')

class AnchoreImageDB(object):
    _logger = logging.getLogger(__name__)

    def __init__(self, config={}):
        self.config = config
        self.initialized = False
        self.version = None
        self.anchore_version_string = None
        self.anchore_db_version_string = None
        try:
            from anchore import version as anchore_version_string
            self.anchore_version_string = anchore_version_string
            self.anchore_db_version_string = self.anchore_version_string
            try:
                patt = re.match("([0-9]+)\.([0-9]+)\.(.*)", self.anchore_version_string)
                if patt:
                    (major, minor, subminor) = patt.group(1,2,3)
                    self.anchore_db_version_string = '.'.join([major, minor])
            except Exception as err:
                pass
                
            self.version = {'anchore_version': self.anchore_version_string, 'db_version': self.anchore_db_version_string}
        except ValueError as err:
            raise err
        except Exception as err:
            raise err

        #self.initialized = True        

    def __del__(self):
        if self.initialized:
            pass

    def get_version(self):
        return(self.version)

    def check(self):
        return(self.initialized)

    def is_image_present(self, imageId, imagelist=None):
        self._logger.debug("AnchoreDB: parent unimplemented")
        return(False)

    def is_image_analyzed(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def get_image_list(self):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_all_images(self):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_all_images_iter(self):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def delete_image(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_image(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_image_new(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def create_image(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def make_image_structure(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_image_new(self, imageId, report=None):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_query_manifest(self):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_query_manifest(self, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_analysis_report(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_analysis_report(self, imageId, report):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def list_analysis_outputs(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_analyzer_manifest(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_analyzer_manifest(self, imageId, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_analysis_output(self, imageId, module_name, module_value, module_type=None):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_analysis_output(self, imageId, module_name, module_value, data, module_type=None, directory_data=False):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_gates_manifest(self):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gates_manifest(self, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_gates_report(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gates_report(self, imageId, report):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_gate_output(self, imageId, gate_name):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def list_gate_outputs(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gate_output(self, imageId, gate_name, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gate_help_output(self, gate_help):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gate_eval_output(self, imageId, gate_name, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def del_gate_eval_output(self, imageId, gate_name):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_gates_eval_report(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gates_eval_report(self, imageId, report):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_gate_policy(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gate_policy(self, imageId, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def del_gate_policy(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_gate_whitelist(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_gate_whitelist(self, imageId, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_image_report(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_image_report(self, imageId, report):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_files(self, imageId, namespace, rootfsdir, files):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_files_tarfile(self, imageId, namespace):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_files_tarfile(self, imageId, namespace, tarfile):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_files_namespaces(self, imageId):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_files_metadata(self, imageId, namespace):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def del_files_cache(self, imageId, namespace):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_feedmeta(self):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_feedmeta(self, feedmeta):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def create_feed(self, feed):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def create_feedgroup(self, feed, group):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def delete_feed(self, feed):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def save_feed_group_data(self, feed, group, datafilename, data):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def load_feed_group_data(self, feed, group, datafilename):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)

    def delete_feed_group_data(self, feed, group, datafilename):
        self._logger.debug("AnchoreDB: parent unimplemented: driver has not implemented this anchoreDB operation")
        return(False)
