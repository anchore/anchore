#!/usr/bin/python
from setuptools import setup, find_packages
from anchore import version

import os, shutil, errno

installroot = '/'
linux_default_config_location = os.path.join(installroot, 'etc/anchore')


def install_configs(overwrite=False):
    if overwrite:
        shutil.copytree('/usr/etc/anchore', linux_default_config_location)
    else:
        prefix = '/usr/etc/anchore'
        if not os.path.isdir(linux_default_config_location):
            try:
                os.makedirs(linux_default_config_location)
            except OSError:
                if errno != 17:
                    raise

        for f in os.listdir(prefix):
            oldfile = os.path.join(prefix, f)
            newfile = os.path.join(linux_default_config_location, f)

            if os.path.exists(newfile):
                shutil.copyfile(newfile, newfile + '.old')
                shutil.copyfile(oldfile, newfile)


with open('requirements.txt') as f:
    requirements = f.read().splitlines()

package_name = "anchore"

package_data = {
    package_name: ['conf/*',
                   'anchore-modules/analyzers/*',
                   'anchore-modules/gates/*',
                   'anchore-modules/queries/*',
                   'anchore-modules/multi-queries/*',
                   'anchore-modules/inputs/*',
                   'anchore-modules/outputs/*',
                   'anchore-modules/shell-utils/*',
                   'anchore-modules/examples/queries/*',
                   'anchore-modules/examples/multi-queries/*',
                   'anchore-modules/examples/analyzers/*',
                   'anchore-modules/examples/gates/*',
                   'doc/man/*'
                   ]
}

scripts = ['scripts/anchore_bash_completer']

anchore_description = 'A toolset for inspecting, querying, and curating containers'
anchore_long_description = open('README.rst').read()

url = 'https://github.com/anchore/anchore.git'

data_files = []

setup(
    name='anchore',
    author='Anchore Inc.',
    author_email='dev@anchore.com',
    license='Apache License 2.0',
    description=anchore_description,
    long_description=anchore_long_description,
    url=url,
    packages=find_packages(exclude=('conf*', 'tests*')),
    version=version,
    data_files=data_files,
    include_package_data=True,
    package_data=package_data,
    entry_points='''
    [console_scripts]
    anchore=anchore.cli:main_entry
    ''',
    install_requires=requirements,
    scripts=scripts
)
