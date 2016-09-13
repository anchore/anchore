import yaml
import os
import shutil
import filecmp
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
    DEFAULT_ANON_ANCHORE_USERNAME = 'anon@ancho.re'
    DEFAULT_ANON_ANCHORE_PASSWORD = 'pbiU2RYZ2XrmYQ'
    DEFAULT_ANCHORE_CLIENT_URL = 'https://ancho.re/v1/account/users'
    DEFAULT_ANCHORE_TOKEN_URL = 'https://ancho.re/oauth/token'
    DEFAULT_ANCHORE_AUTH_CONN_TIMEOUT = 5
    DEFAULT_ANCHORE_AUTH_MAX_RETRIES = 5
    
    try:
        DEFAULT_EXTRASCRIPTS_DIR = resource_filename("anchore-modules", "/")
    except:
        DEFAULT_EXTRASCRIPTS_DIR = None

    DEFAULTS = {
        'anchore_data_dir': DEFAULT_ANCHORE_DATA_DIR,
        'image_data_store': 'data',
        'tmpdir': '/tmp',
        'pkg_dir': DEFAULT_PKG_DIR,
        'scripts_dir': DEFAULT_SCRIPTS_DIR,
        'user_scripts_dir': 'user-scripts',
        'extra_scripts_dir': DEFAULT_EXTRASCRIPTS_DIR,
        'docker_conn': 'unix://var/run/docker.sock',
        'docker_conn_timeout':'60',
        'anchore_client_url':DEFAULT_ANCHORE_CLIENT_URL,
        'anchore_token_url':DEFAULT_ANCHORE_TOKEN_URL,
        'anchore_auth_conn_timeout':DEFAULT_ANCHORE_AUTH_CONN_TIMEOUT,
        'anchore_auth_max_retries':DEFAULT_ANCHORE_AUTH_MAX_RETRIES,
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

        # handle override of the default .anchore location
        if os.getenv('ANCHOREDATADIR'):
            self.DEFAULT_ANCHORE_DATA_DIR = os.getenv('ANCHOREDATADIR')
            self.DEFAULT_CONFIG_DIR = os.path.join(self.DEFAULT_ANCHORE_DATA_DIR, 'conf')
            self.DEFAULT_CONFIG_FILE = os.path.join(self.DEFAULT_CONFIG_DIR, 'config.yaml')
            self.DEFAULTS['anchore_data_dir'] = self.DEFAULT_ANCHORE_DATA_DIR

        self.config_dir, self.config_file = self.find_config_file()
        try:
            self.data = load_and_merge(file_path=self.config_file, defaults=self.DEFAULTS)

            self.cliargs = {}
            if cliargs:
                # store CLI arguments
                self.cliargs = cliargs

            #update relative to data dir if not an absolute path
            if not os.path.isabs(self.data['image_data_store']):
                self.data['image_data_store'] = os.path.join(self.data['anchore_data_dir'], self.data['image_data_store'])

            if not os.path.exists(self.data['image_data_store']):
                os.makedirs(self.data['image_data_store'])

            if not os.path.isabs(self.data['user_scripts_dir']):
                self.data['user_scripts_dir'] = os.path.join(self.data['anchore_data_dir'], self.data['user_scripts_dir'])
            
            if not os.path.exists(self.data['user_scripts_dir']):
                os.makedirs(self.data['user_scripts_dir'])
                for d in ['analyzers', 'gates', 'queries', 'multi-queries', 'shell-utils']:
                    os.makedirs(os.path.join(self.data['user_scripts_dir'], d))

            dc = filecmp.dircmp(os.path.join(self.data['scripts_dir'], 'shell-utils'), os.path.join(self.data['user_scripts_dir'], 'shell-utils'))
            for f in dc.left_only + dc.diff_files:
                try:
                    shutil.copy(os.path.join(self.data['scripts_dir'], 'shell-utils', f), os.path.join(self.data['user_scripts_dir'], 'shell-utils', f))
                except Exception as err:
                    raise err
            
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

