import gv
import os
import logging

from anchore import anchore_utils
from anchore.util import contexts
import anchore_image_db


DEVNULL=open(os.devnull, 'wb')


class Visualizer(object):
    """
    Component that handles generating visualizations of images and trees"
    """

    _logger = logging.getLogger(__name__)

    def __init__(self, config, imagelist, allimages, docker_cli=None):
        self.config = config

        self.allimages = allimages

        self.anchore_datadir = config['image_data_store']
        self.tmproot=self.config['tmpdir']

        self.images = anchore_utils.image_context_add(imagelist,
                                                      allimages,
                                                      docker_cli=docker_cli,
                                                      anchore_datadir=self.anchore_datadir,
                                                      tmproot=self.tmproot,
                                                      anchore_db=contexts['anchore_db'],
                                                      must_be_analyzed=True,
                                                      must_load_all=True)

    def get_images(self):
        return(self.images)

    def get_node_attrs(self, i, mode="family", params={}):
        text = ""
        color = "black"
        style = ""
        fillcolor = ""
        drepo = None
        arepo = None

        arepo = drepo = "n/a"
        if len(i.get_alltags_current()) > 0:
            drepo = ' '.join(i.get_alltags_current())
        if len(i.get_alltags_past()) > 0:
            arepo = ' '.join(i.get_alltags_past())
        
        text = i.meta['shortId'] + "\n(curr="+drepo+")\n(allknown="+arepo+")"
            
        if mode == "family":
            fillcolor = '#FFFFFF'
            if i.is_user():
                fillcolor = '#00AA00'
            elif i.is_anchore_base():
                fillcolor = '#f3d51b'
                #fillcolor = '#AA0000'
            elif i.is_base():
                fillcolor = '#FF0000'
            elif i.is_intermediate():
                fillcolor = '#FFFFFF'

            style = 'filled'

        return([text, color, style, fillcolor, drepo, arepo])

    def vis_graph(self, mode="family", params={}):
        dot = graphviz.Digraph(comment='Container Images: ' + mode)
        nodes = {}
        edges = {}
        show_all = False

        for id in self.images:
            i = self.allimages[id]
            if i.meta['shortId'] not in nodes:

                if show_all or (len(i.get_alltags_ever()) > 0):
                    nodes[i.meta['shortId']] = self.get_node_attrs(i, mode=mode, params=params)

                for fid in i.anchore_familytree:
                    f = self.allimages[fid]

                    if f.meta['shortId'] not in nodes:
                        if show_all or (len(f.get_alltags_ever()) > 0):
                            nodes[f.meta['shortId']] = self.get_node_attrs(f, mode=mode, params=params)

        for id in self.images:
            i = self.allimages[id]
            last = i
            revtree = list(i.get_familytree())
            revtree.reverse()
            for fid in revtree:
                f = self.allimages[fid]

                if show_all or ( len(last.get_alltags_ever()) > 0 and len(f.get_alltags_ever()) > 0 ) :
                    if last.meta['shortId'] != f.meta['shortId']:
                        edges[last.meta['shortId']] = f.meta['shortId']
                        last = f

        for n in nodes.keys():
            dot.node(n, nodes[n][0], color=nodes[n][1], style=nodes[n][2], fillcolor=nodes[n][3])

        for k in edges.keys():
            dot.edge(k, edges[k])

        fname = "/anchore-"+mode+"-graph"
        dot.render('/'.join([self.tmproot,fname]), view=False)
        
    def run(self, params={}):
            self.vis_graph(mode="family")
            self._logger.info("Done: output graph(s) are in: " + '/'.join([self.tmproot,"/anchore-*-graph.pdf"]))

