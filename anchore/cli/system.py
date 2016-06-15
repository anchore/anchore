# Main entry point for the registry manager cli
import click
import yaml

import anchore.catalog
from anchore.catalog import AnchoreCatalog
from anchore.cli.common import anchore_print, anchore_print_err


@click.group()
def system():
    """
    Anchore system-level operations, which do not operate on resources, but the overall system itself.

    System includes subcommands to backup, restore, and view status info on the local system.
    """
    pass


@system.command()
@click.option('--config', is_flag=True, help='Output the currently used configuration yaml content')
@click.pass_obj
def status(anchore_config, config):
    """
    Print state of local anchore images and artifacts. Includes paths, cache states, and configuration values.

    Use the --config option to dump the current configuration that the system is using. The configuration option
    returns structured output (yaml) or json if using the --json option. All configuration values are populated,
    with defaults if not explicitly overridden in the config file. The output of this is suitable to create a new config
    file.


    """
    assert anchore_config is not None

    try:

        working_catalog = AnchoreCatalog(config=anchore_config)
        if config:
            if anchore_config.cliargs['json']:
                anchore_print(working_catalog.configuration().data, do_formatting=True)
            else:
                anchore_print(yaml.safe_dump(working_catalog.configuration().data, indent=True, default_flow_style=False))
        else:
            result = working_catalog.check_status()
            for k, v in result.items():
                if 'local' in v:
                    result[k] = v['local']

            anchore_print(result, do_formatting=True)

    except:
        anchore_print_err('Failed checking local system status. Please check config file: %s' % anchore_config.config_file)
        exit(1)


@system.command()
@click.argument('outputdir', type=click.Path())
@click.pass_obj
def backup(anchore_config, outputdir):
    """
    Backup the Anchore data locally to a tarball. Will result in a backup file with the name:
    anchore-backup-<date>.tar.gz

    If the anchore configuration file specifies a different image_data_store outside of the anchore_data_dir tree it will
    be backed up, but may require manual intervention on restore. Backup includes the configuration files as well as data
    files. Backup does *not* include docker images themselves.

    """

    try:
        output_file = anchore.catalog.AnchoreCatalog.backup(anchore_config, outputdir)
        anchore_print({'output': output_file}, do_formatting=True)
    except:
        anchore_print_err('Backup of catalog to %s failed' % outputdir)
        exit(1)


@system.command(short_help='Restore Anchore data from a tarball')
@click.argument('inputfile', type=click.File('rb'))
@click.argument('destination_root', type=click.Path(), default='/')
@click.pass_obj
def restore(anchore_config, inputfile, destination_root):
    """
    Restore anchore from a backup to directory root. E.g. "anchore system restore /tmp/anchore_backup.tar.gz /"

    If the image_data_store value has been changed from default ('data') to a path outside of the anchore_data_dir subtree
    then manual intervention may be required to modify the restored config file or move the image_data_store if relative paths
    were used that are no longer accessible. The restore process is an untar process so data is placed in the same place
    relative to the root directory when the tar was created. If the system being restored on is structured differently than
    the original backup source then manual movement of data or config file values may be necessary to get all artifacts in the
    correct locations for the system to find.

    """

    anchore_print('Restoring anchore registry from backup file %s to %s'
               % (inputfile, destination_root))
    try:
        anchore.catalog.AnchoreCatalog.restore(destination_root, inputfile)
    except:
        anchore_print_err('Restore of catalog from %s failed' % inputfile)
        exit(1)

