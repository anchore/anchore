import yaml
import os
import shutil
from util.tools import load_and_merge
from pkg_resources import Requirement, resource_filename


class AnchoreConfiguration (object):
    """
    Backed by a yaml file
    """

    DEFAULT_ANCHORE_DATA_DIR = os.path.join(os.getenv('HOME'), '.anchore')
    DEFAULT_CONFIG_DIR = os.path.join(DEFAULT_ANCHORE_DATA_DIR, 'conf')
    DEFAULT_CONFIG_FILE = os.path.join(DEFAULT_CONFIG_DIR, 'config.yaml')
    EXAMPLE_CONFIG_DIR = resource_filename("anchore", "conf/")
    EXAMPLE_CONFIG_FILE = resource_filename("anchore", "conf/config.yaml")
    DEFAULT_PKG_DIR = resource_filename("anchore", "")
    DEFAULT_SCRIPTS_DIR = resource_filename("anchore", "anchore-modules")

    DEFAULTS = {
        'anchore_data_dir': DEFAULT_ANCHORE_DATA_DIR,
        'image_data_store': 'data',
        'tmpdir': '/tmp',
        'pkg_dir': DEFAULT_PKG_DIR,
        'scripts_dir': DEFAULT_SCRIPTS_DIR,
        'docker_conn': 'unix://var/run/docker.sock',
        'vulnerabilities': {
            'url': 'https://service-data.anchore.com/vulnerabilities.tar.gz',
        },
        'analysis': {
            'url': 'https://service-data.anchore.com/analysis_db.tar.gz',
        },
        'images': {
            'docker_conn': 'unix://var/run/docker.sock'
        }
    }

    def __init__(self, cliargs=None):
        # config file handling
        self.config_dir, self.config_file = self.find_config_file()
        try:
            self.data = load_and_merge(file_path=self.config_file, defaults=self.DEFAULTS)

            # set up names of CLI common contexts
            #self.contexts = {}
            #self.contexts['docker_cli'] = None
            #self.contexts['anchore_allimages'] = None

            self.cliargs = {}
            if cliargs:
                # store CLI arguments
                self.cliargs = cliargs

            #update relative to data dir if not an absolute path
            if not os.path.isabs(self.data['image_data_store']):
                self.data['image_data_store'] = os.path.join(self.data['anchore_data_dir'], self.data['image_data_store'])

            if not os.path.exists(self.data['image_data_store']):
                os.makedirs(self.data['image_data_store'])

        except Exception as err:
            self.data = None
            import traceback
            traceback.print_exc()
            raise err

    def __getitem__(self, item):
        """
        Allow dict-style access on the object itself.
        :param item:
        :return:
        """
        return self.data[item]

    def __setitem__(self, key, value):
        """
        Allow dict-style setting of values into the backing structure
        :param key:
        :param value:
        :return:
        """
        self.data[key] = value

    def __str__(self):
        return yaml.safe_dump(self.data)

    def find_config_file(self):
        thefile = ""
        thedir = ""
        if os.path.exists(self.DEFAULT_CONFIG_FILE):
            thefile = self.DEFAULT_CONFIG_FILE
            thedir = self.DEFAULT_CONFIG_DIR
        elif os.path.exists("/etc/anchore/config.yaml"):
            thefile = "/etc/anchore/config.yaml"
            thedir = "/etc/anchore"
        else:
            # config file doesn't exist, copy the example default to ~
            if not os.path.exists(self.DEFAULT_CONFIG_DIR):
                os.makedirs(self.DEFAULT_CONFIG_DIR)
            for d in os.listdir(self.EXAMPLE_CONFIG_DIR):
                if not os.path.exists('/'.join([self.DEFAULT_CONFIG_DIR, d])):
                    shutil.copy('/'.join([self.EXAMPLE_CONFIG_DIR, d]), '/'.join([self.DEFAULT_CONFIG_DIR, d]))

            thefile = self.DEFAULT_CONFIG_FILE
            thedir = self.DEFAULT_CONFIG_DIR

        return thedir, thefile

