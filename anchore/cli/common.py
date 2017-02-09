import os
import click
import json
import yaml
import logging
import sys
from anchore import anchore_utils
from anchore.cli import logs
from anchore.util import contexts

plain_output = False


def extended_help_option(extended_help=None, *param_decls, **attrs):
    """
    Based on the click.help_option code.

    Adds a ``--extended-help`` option which immediately ends the program
    printing out the extended extended-help page. Defaults to using the
    callback's doc string, but can be given an explicit value as well.

    This is intended for use as a decorator on a command to provide a 3rd level
    of help verbosity suitable for use as a manpage (though not formatted as such explicitly).

    Like :func:`version_option`, this is implemented as eager option that
    prints in the callback and exits.

    All arguments are forwarded to :func:`option`.
    """

    def decorator(f):
        def callback(ctx, param, value):
            if value and not ctx.resilient_parsing:
                if not extended_help:
                    ctx.command.help = ctx.command.callback.__doc__
                    click.echo(ctx.get_help(), color=ctx.color)
                else:
                    ctx.command.help = extended_help
                    click.echo(ctx.get_help(), color=ctx.color)
                ctx.exit()

        attrs.setdefault('is_flag', True)
        attrs.setdefault('expose_value', False)
        attrs.setdefault('help', 'Show extended help content, similar to manpage, and exit.')
        attrs.setdefault('is_eager', True)
        attrs['callback'] = callback
        return click.option(*(param_decls or ('--extended-help',)), **attrs)(f)

    return decorator


def std_formatter(msg):
    """
    Default simple string format. Dumps block-style indented yaml for dicts if found. Otherwise no formatting
    :param msg:
    :return:
    """

    if isinstance(msg, dict):
        return yaml.safe_dump(msg, indent=True, default_flow_style=False)
    return str(msg)


def json_formatter(obj):
    """
    Format the output in JSON
    :param obj:
    :return:
    """
    if isinstance(obj, str):
        # Make a list of size 1
        return json.dumps([obj], indent=True)
    else:
        return json.dumps(obj, indent=True, sort_keys=True)

# Which formatting function to use
formatter = std_formatter


def init_output_format(use_json=False, use_plain=False, use_debug=False, use_verbose=False, use_quiet=False, log_filepath=None, debug_log_filepath = None):
    global formatter

    if use_json:
        formatter = json_formatter

    if use_debug:
        level = 'debug'
    elif use_verbose:
        level = 'verbose'
    elif use_quiet:
        level = 'quiet'
    else:
        level = 'normal'

    logs.init_output_formatters(output_verbosity=level, logfile=log_filepath, debug_logfile=debug_log_filepath)


def anchore_print_err(msg):
    exc = sys.exc_info()
    if exc is not None and exc != (None, None, None):
        logging.getLogger(__name__).exception(msg)
    else:
        logging.getLogger(__name__).error(msg)


def anchore_print(msg, do_formatting=False):
    """
    Print to stdout using the proper formatting for the command.

    :param msg: output to be printed, either an object or a string. Objects will be serialized according to config
    :return:
    """
    if do_formatting:
        click.echo(formatter(msg))
    else:
        click.echo(msg)


def build_image_list(config, image, imagefile, all_local, include_allanchore, dockerfile=None, exclude_file=None):
    """Given option inputs from the cli, construct a list of image ids. Includes all found with no exclusion logic"""

    if not image and not (imagefile or all_local):
        raise click.BadOptionUsage('No input found for image source. One of <image>, <imagefile>, or <all> must be specified')

    if image and imagefile:
        raise click.BadOptionUsage('Only one of <image> and <imagefile> can be specified')

    filter_images = []
    if exclude_file:
        with open(exclude_file) as f:
            for line in f.readlines():
                filter_images.append(line.strip())

    imagelist = {}
    if image:
        imagelist[image] = {'dockerfile':dockerfile}

    if imagefile:
        filelist = anchore_utils.read_kvfile_tolist(imagefile)
        for i in range(len(filelist)):
            l = filelist[i]
            imageId = l[0]
            try:
                dfile = l[1]
            except:
                dfile = None
            imagelist[imageId] = {'dockerfile':dfile}

    if all_local:
        docker_cli = contexts['docker_cli']
        if docker_cli:
            for f in docker_cli.images(all=True, quiet=True, filters={'dangling': False}):
                if f not in imagelist and f not in filter_images:
                    imagelist[f] = {'dockerfile':None}
        else:
            raise Exception("Could not load any images from local docker host - is docker running?")

    if include_allanchore:
        ret = contexts['anchore_db'].load_all_images().keys()
        if ret and len(ret) > 0:
            for l in list(set(imagelist.keys()) | set(ret)):
                imagelist[l] = {'dockerfile':None}

    # Remove excluded items
    for excluded in filter_images:
        docker_cli = contexts['docker_cli']
        if not docker_cli:
            raise Exception("Could not query docker - is docker running?")
        for img in docker_cli.images(name=excluded, quiet=True):
            imagelist.pop(img, None)

    return imagelist
