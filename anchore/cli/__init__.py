import os
import click
import subprocess
import docker
import sys
from anchore.configuration import AnchoreConfiguration
from anchore.version import version as anchore_version

import analyzer
import explorer
import subscriptions
import system
import synchronizer
import logs
import toolbox
import anchore.anchore_image_db

from anchore.util import contexts
from .common import init_output_format, anchore_print_err, extended_help_option


main_extended_help="""
Anchore is a tool for analyzing, querying, and curating container images to deliver the transparency, predictability,
and control necessary to use containers in production. Anchore is composed of a toolset that runs locally on a host as
well as a web service that monitors the container ecosystem and provides inputs to the local toolset.

The tool has capabilities to populate a registry, run analysis, explore/query the analysis results (including custom
queries and checks), and run policy-based gate-functions against container images to help an ops team decide if a container
should go into the CI/CD pipeline and on to production based on attributes of the Dockerfile, built image, or both.

After installation, the first command run must be: 'anchore sync catalog' to initialize the system and load subscription data.

Subscriptions are lists of container images (e.g. ubuntu:latest, centos:7, nginx:latest), that anchore will automatically
fetch from docker hub during a catalog sync to keep up-to-date and will also download the latest analysis data on those images
from the anchore web service. Except during a sync, no network connectivity is required by anchore to run analysis and query
images.

Configuration Files:

Anchore configuration files are automatically installed if not found when looking in-order at:
\b
$HOME/.anchore/conf
/etc/anchore

A default install will copy the files to $HOME/.anchore/conf/, but they may be manually put in /etc/anchore for a system global config.

* config.yaml - main configuration file. Used to override default values. Anchore will search for it in
$HOME/.anchore/conf, then in /etc/anchore. If not found in either place, a new one is initilized and copied to $HOME/.anchore

* anchore_gate.policy - The global gate policy file (see anchore-gate(1) for more help on gates).


High-level example flows:

Initialize the system and subscribe to 'ubuntu' image:

\b
anchore sync catalog
anchore subscriptions add ubuntu
anchore sync catalog

Generate a summary report on all analyzed images

anchore explore report

Check gate output for nginx:latest:

anchore gate --image nginx:latest
"""


@click.group()
@click.option('--verbose', is_flag=True, help='Enable verbose output to stderr.')
@click.option('--debug', is_flag=True, help='Developer debug output to stderr.')
@click.option('--quiet', is_flag=True, help='Only errors to stderr, no status messages.')
@click.option('--json', is_flag=True, help='Output formatted json to stdout.')
@click.option('--plain', is_flag=True, help='Output formatted scriptable text to stdout.')
@click.version_option(version=anchore_version)
@click.pass_context
@extended_help_option(extended_help=main_extended_help)
def main_entry(ctx, verbose, debug, quiet, json, plain):
    """
    Anchore is a tool to analyze, query, and curate container images. The options at this top level
    control stdout and stderr verbosity and format.

    The first command that must be run after installation is: 'anchore sync catalog'. That will initialize
    the system and prepare the local install for use.

    High-level example flows:

    Initialize the system and subscribe to 'ubuntu' image:

    \b
    anchore sync catalog
    anchore subscriptions add ubuntu
    anchore sync catalog

    Generate a summary report on all analyzed images

    anchore explore report

    Check gate output for nginx:latest:

    anchore gate --image nginx:latest


    """
    # Load the config into the context object
    logfile = None
    debug_logfile = None
    try:
        try:
            args = {'verbose': verbose, 'debug': debug, 'json': json, 'plain': plain, 'quiet': quiet}
            anchore_conf = AnchoreConfiguration(cliargs=args)
        except Exception as err:
            click.echo("Error setting up/reading Anchore configuration", err=True)
            click.echo("Info: "+str(err), err=True)
            import traceback
            traceback.print_exc()
            sys.exit(1)
        try:
            logfile = anchore_conf.data['log_file'] if 'log_file' in anchore_conf.data else None
            debug_logfile = anchore_conf.data['debug_log_file'] if 'debug_log_file' in anchore_conf.data else None
        except Exception, e:
            click.echo(str(e))

        ctx.obj = anchore_conf

    except:
        if ctx.invoked_subcommand != 'system':
            click.echo('Expected, but did not find configuration file at %s' % os.path.join(AnchoreConfiguration.DEFAULT_CONFIG_FILE), err=True)
            exit(1)

    try:
        init_output_format(json, plain, debug, verbose, quiet, log_filepath=logfile, debug_log_filepath=debug_logfile)
    except Exception, e:
        click.echo('Error initializing logging: %s' % str(e))
        exit(2)

    if not anchore_pre_flight_check(ctx):
        anchore_print_err("Error running pre-flight checks")
        exit(1)

    if not anchore_common_context_setup(ctx):
        anchore_print_err("Error setting up common data based on configuration")
        exit(1)

main_entry.add_command(subscriptions.subscriptions)
main_entry.add_command(system.system)
main_entry.add_command(synchronizer.sync)
main_entry.add_command(explorer.explore)
main_entry.add_command(analyzer.analyze)
main_entry.add_command(analyzer.gate)
main_entry.add_command(toolbox.toolbox)

def anchore_pre_flight_check(ctx):
    # helper checks
    try:
        subcommand = ctx.invoked_subcommand
        config = ctx.obj.data
    except:
        return(False)
        
    if subcommand in ['explore', 'gate', 'analyze']:

        # check for some shellouts for analyzers
        try:
            from deb_pkg_tools.version import Version
            cmd = ['dpkg-query', '--version']
            sout = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except Exception as err:
            anchore_print_err("Anchore requires dpkg libs and commands")
            return(False)

        try:
            from rpmUtils.miscutils import splitFilename
            cmd = ['rpm', '--version']
            sout = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except Exception as err:
            anchore_print_err("Anchore requires yum/rpm libs and commands")
            return(False)

        try:
            import graphviz  
            cmd = ['dot', '-V']
            sout = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except Exception as err:
            anchore_print_err("Anchore requires graphviz libs and commands")
            return(False)
            
    if subcommand in ['explore', 'gate', 'analyze', 'toolbox']:
        # check DB readiness
        try:
            db = anchore.anchore_image_db.AnchoreImageDB(imagerootdir=config['image_data_store'])
        except Exception as err:
            anchore_print_err("Could not set up connection to Anchore DB")
            return(False)

    return(True)


def anchore_common_context_setup(ctx):
    config = ctx.obj

    if 'docker_cli' not in contexts or not contexts['docker_cli']:
        try:
            contexts['docker_cli'] = docker.Client(base_url=config['docker_conn'])
            testconn = contexts['docker_cli'].images()
        except Exception as err:
            contexts['docker_cli']=None

    if 'anchore_allimages' not in contexts or not contexts['anchore_allimages']:
        contexts['anchore_allimages'] = {}

    if 'anchore_db' not in contexts or not contexts['anchore_db']:
        contexts['anchore_db'] = anchore.anchore_image_db.AnchoreImageDB(imagerootdir=config['image_data_store'])

    return(True)
