import os
import re
import subprocess
import random
import shutil
import logging
import time

from anchore import anchore_utils
from anchore.util import scripting, contexts

class Navigator(object):
    _logger = logging.getLogger(__name__)

    def __init__(self, anchore_config, imagelist, allimages):
        self.config = anchore_config
        self.allimages = allimages
        #self.anchore_datadir = self.config['image_data_store']
        self.images = list()

        self.images = anchore_utils.image_context_add(imagelist, allimages, docker_cli=contexts['docker_cli'], tmproot=self.config['tmpdir'], anchore_db=contexts['anchore_db'], docker_images=contexts['docker_images'], must_be_analyzed=True, must_load_all=True)

        self.anchoreDB = contexts['anchore_db']

    def add_images(self, imagelist):
        newimages = anchore_utils.image_context_add(imagelist, self.allimages, docker_cli=contexts['docker_cli'], tmproot=self.config['tmpdir'], anchore_db=contexts['anchore_db'], docker_images=contexts['docker_images'], must_be_analyzed=True, must_load_all=True)

        self.images = list(set(self.images) | set(newimages))

    def generate_reports(self):
        ret = {}
        for imageId in self.images:
            image = self.allimages[imageId]
            baseId = image.get_earliest_base()
            bimage = self.allimages[baseId]
            sizebytes = image.meta['sizebytes']

            image_report = image.get_image_report()
            analysis_report = image.get_analysis_report()
            gates_report = image.get_gates_report()
            gates_eval_report = image.get_gates_eval_report()

            record = {
                'image_report': image_report,
                'analysis_report': analysis_report,
                'gates_report': gates_report,
                'gates_eval_report': gates_eval_report,
                'result': {
                    'header':['Image_Id', 'Type', 'Current_Tags', 'All_Tags', 'Gate_Status', 'Size(bytes)', 'Counts', 'Base_Diffs'],
                    'rows': list()
                }
            }

            shortId = image.meta['shortId']
            usertype = str(image.get_usertype())
            currtags = ','.join(image.get_alltags_current())
            alltags = ','.join(image.get_alltags_ever())

            gateaction = 'UNKNOWN'
            for g in gates_eval_report:
                if g['trigger'] == 'FINAL':
                    gateaction = g['action']
                    break

            try:
                pnum = str(len(anchore_utils.load_analysis_output(image.meta['imageId'], 'package_list', 'pkgs.all').keys()))
            except:
                pnum = "N/A"
            try:
                fnum = str(len(anchore_utils.load_analysis_output(image.meta['imageId'], 'file_list', 'files.all').keys()))
            except:
                fnum = "N/A"
            try:
                snum = str(len(anchore_utils.load_analysis_output(image.meta['imageId'], 'file_suids', 'files.suids').keys()))
            except:
                fnum = "N/A"

            analysis_str = ' '.join(["PKGS="+pnum, "FILES="+fnum, "SUIDFILES="+snum])

            compare_str = "N/A"

            if image.meta['imageId'] != baseId:
                diffdata = anchore_utils.diff_images(image.meta['imageId'], baseId)            
                record['base_compare_data'] = diffdata
                pnum = "N/A"
                if 'package_list' in diffdata and 'pkgs.all' in diffdata['package_list']:
                    for module_type in diffdata['package_list']['pkgs.all']:
                        pnum = str(len(diffdata['package_list']['pkgs.all'][module_type]))
                        break

                fnum = "N/A"
                if 'file_list' in diffdata and 'files.all' in diffdata['file_list']:
                    for module_type in diffdata['file_list']['files.all']:
                        fnum = str(len(diffdata['file_list']['files.all'][module_type]))

                snum = "N/A"
                if 'file_suids' in diffdata and 'files.suids' in diffdata['file_suids']:
                    for module_type in diffdata['file_suids']['files.suids']:
                        snum = str(len(diffdata['file_suids']['files.suids'][module_type]))

                compare_str = ' '.join(["PKGS="+pnum, "FILES="+fnum, "SUIDFILES="+snum])

            row = [ shortId, usertype, currtags, alltags, gateaction, sizebytes, analysis_str, compare_str ]

            record['result']['rows'].append(row)

            ret[imageId] = record
        return ret

    def get_images(self):
        return(self.images)

    def get_dockerfile_contents(self):
        result = {}
        for imageId in self.images:
            image = self.allimages[imageId]
            #result[imageId] = image.get_dockerfile_contents()
            record = {'result':{}}
            record['result']['header'] = ['Image_Id', 'Mode', 'Dockerfile_Contents']
            record['result']['rows'] = list()
            (dbuf, mode) = image.get_dockerfile_contents()
            record['result']['rows'].append([image.meta['shortId'], mode, dbuf])
            result[imageId] = record
        return(result)

    def get_familytree(self):
        result = {}
        for imageId in self.images:
            image = self.allimages[imageId]
            record = {'result':{}}
            record['result']['header'] = ['Image_Id', 'Current_Repo_Tags', 'Past_Repo_Tags', 'Image_Type']
            record['result']['rows'] = list()
            for fid in image.get_familytree():
                fimage = self.allimages[fid]
                fidstr = fimage.meta['shortId']
                curr_tags = ','.join(fimage.get_alltags_current())
                past_tags = ','.join(fimage.get_alltags_past())
                
                usertype = fimage.get_usertype()
                if usertype == "anchorebase":
                    userstr = "Anchore Base Image"
                elif usertype == "base":
                    userstr = "Base"
                elif usertype == "oldanchorebase":
                    userstr = "Previous Anchore Base Image"
                elif usertype == "user":
                    userstr = "User Image"
                else:
                    userstr = "Intermediate"

                record['result']['rows'].append([fidstr, curr_tags, past_tags, userstr])

            result[imageId] = record
            
        return(result)

    def get_layers(self):
        result = {}
        for imageId in self.images:
            image = self.allimages[imageId]
            record = {'result':{}}
            record['result']['header'] = ['Layer_Id']
            record['result']['rows'] = list()
            for fid in image.get_layers() + [imageId]:
                record['result']['rows'].append([fid])

            result[imageId] = record
            
        return(result)

    def get_taghistory(self):
        result = {}
        for imageId in self.images:
            image = self.allimages[imageId]
            record = {'result':{}}
            record['result']['header'] = ['Image_Id', 'Date', 'Known_Tags']
            record['result']['rows'] = list()
            for tagtup in image.get_tag_history():
                tstr = time.ctime(int(tagtup[0]))
                tagstr = ','.join(tagtup[1])
                record['result']['rows'].append([image.meta['shortId'], tstr, tagstr])

            try:
                currtags = ','.join(image.get_alltags_current())
                record['result']['rows'].append([image.meta['shortId'], time.ctime(), currtags])
            except:
                pass

            result[imageId] = record
        return(result)

    def unpack(self, destdir='/tmp'):
        ret = {}
        for imageId in self.images:
            image = self.allimages[imageId]
            outdir = image.unpack(docleanup=False, destdir=destdir)
            if not outdir:
                self._logger.warn("failed to unpack image ("+str(imageId)+")")
            else:
                self._logger.debug("Unpacked image " + image.meta['shortId'] + " in " + outdir)
                ret[imageId] = outdir
        return(ret)

    def run(self):
        return(True)

    def find_query_command(self, action):
        cmdobj = None
        mode = None
        cmd = None
        rc = False
        try:
            path_overrides = ['/'.join([self.config['user_scripts_dir'], 'queries'])]
            if self.config['extra_scripts_dir']:
                path_overrides = path_overrides + ['/'.join([self.config['extra_scripts_dir'], 'queries'])]

            cmdobj = scripting.ScriptExecutor(path='/'.join([self.config['scripts_dir'], 'queries']), script_name=action, path_overrides=path_overrides)
            cmd = cmdobj.thecmd
            mode = 'query'
            rc = True
        except ValueError as err:
            raise err
        except Exception as err:
            errstr = str(err)
            try:
                path_overrides = ['/'.join([self.config['user_scripts_dir'], 'multi-queries'])]
                if self.config['extra_scripts_dir']:
                    path_overrides = path_overrides + ['/'.join([self.config['extra_scripts_dir'], 'multi-queries'])]
                cmdobj = scripting.ScriptExecutor(path='/'.join([self.config['scripts_dir'], 'multi-queries']), script_name=action, path_overrides=path_overrides)
                cmd = cmdobj.thecmd
                mode = 'multi-query'
                rc = True
            except ValueError as err:
                raise err
            except Exception as err:
                raise err

        ret = (rc, mode, cmdobj)
        return(ret)

    def execute_query(self, imglist, se, params):
        success = True
        datadir = self.config['image_data_store']
        outputdir = '/'.join([self.config['anchore_data_dir'], "querytmp", "query." + str(random.randint(0, 99999999))])
        if not os.path.exists(outputdir):
            os.makedirs(outputdir)

        imgfile = '/'.join([self.config['anchore_data_dir'], "querytmp", "queryimages." + str(random.randint(0, 99999999))])
        anchore_utils.write_plainfile_fromlist(imgfile, imglist)

        cmdline = ' '.join([imgfile, datadir, outputdir])
        if params:
            cmdline = cmdline + ' ' + ' '.join(params)

        meta = {}

        try:
            (cmd, rc, sout) = se.execute(capture_output=True, cmdline=cmdline)
            if rc:
                self._logger.error("Query command ran but execution failed" )
                self._logger.error("Query command: (" + ' '.join([se.thecmd, cmdline])+")")
                self._logger.error("Query output: (" + str(sout) + ")")
                self._logger.error("Exit code: (" + str(rc)+")")
                raise Exception("Query ran but exited non-zero.")
        except Exception as err:
            raise Exception("Query execution failed: " + str(err))
        else:
            try:
                #outputs = os.listdir(outputdir)
                warnfile = False
                found = False
                for f in os.listdir(outputdir):
                    if re.match(".*\.WARNS", f):
                        warnfile = '/'.join([outputdir, f])
                    else:
                        ofile = '/'.join([outputdir, f])
                        found=True

                if not found:
                    raise Exception("No output files found after executing query command\n\tCommand Output:\n"+sout+"\n\tInfo: Query command should have produced an output file in: " + outputdir)

                orows = list()

                try:
                    frows = anchore_utils.read_kvfile_tolist(ofile)
                    header = frows[0]
                    rowlen = len(header)
                    for row in frows[1:]:
                        if len(row) != rowlen:
                            raise Exception("Number of columns in data row ("+str(len(row))+") is not equal to number of columns in header ("+str(rowlen)+")\n\tHeader: "+str(header)+"\n\tOffending Row: "+str(row))
                        orows.append(row)
                except Exception as err:
                    raise err 

                if warnfile:
                    try:
                        meta['warns'] = anchore_utils.read_plainfile_tolist(warnfile)
                    except:
                        pass

                meta['queryparams'] = ','.join(params)
                meta['querycommand'] = cmd
                try:
                    i = header.index('URL')
                    meta['url_column_index'] = i
                except:
                    pass
                meta['result'] = {}
                meta['result']['header'] = header
                meta['result']['rowcount'] = len(orows)
                try:
                    #meta['result']['colcount'] = len(orows[0])
                    meta['result']['colcount'] = len(header)
                except:
                    meta['result']['colcount'] = 0
                meta['result']['rows'] = orows

            except Exception as err:
                self._logger.error("Query output handling failed: ")
                self._logger.error("\tCommand: " + str(cmd))
                self._logger.error("\tException: " + str(err))
                success = False
        finally:
            os.remove(imgfile)
            if outputdir:
                shutil.rmtree(outputdir)

        ret = [success, cmd, meta]
        return(ret)

    def format_query_manifest_record(self, command, status, returncode, timestamp, qtype, output, csum):
        ret = {
            "status": status,
            "returncode": returncode,
            "timestamp": timestamp,
            "type": qtype,
            "command": command,
            "output": output,
            "csum": csum
        }
        return(ret)

    def list_query_commands(self, command=None):
        result = {}

        record = {'result':{}}
        record['result']['header'] = ["Query", "Help_String"]
        record['result']['rows'] = list()

        query_manifest = self.anchoreDB.load_query_manifest()

        if command:
            try:
                (rc, command_type, se) = self.find_query_command(command)
                if rc:
                    commandpath = se.get_script()
                    csum = se.csum()
                    if commandpath in query_manifest and csum != "N/A" and csum == query_manifest[commandpath]['csum']:
                        self._logger.debug("skipping query help refresh run ("+str(command)+"): no change in query")
                        cmd = query_manifest[commandpath]['command']
                        rc = query_manifest[commandpath]['returncode']
                        sout = query_manifest[commandpath]['output']
                    else:
                        (cmd, rc, sout) = se.execute(capture_output=True, cmdline='help')
                    
                    if rc == 0:
                        query_manifest[commandpath] = self.format_query_manifest_record(cmd, "SUCCESS", rc, time.time(), "N/A", sout, csum)
                        record['result']['rows'].append([command, sout])
                    else:
                        query_manifest[commandpath] = self.format_query_manifest_record(cmd, "FAIL", rc, time.time(), "N/A", "N/A", csum)

            except Exception as err:
                self._logger.debug("cannot execute ("+str(command)+"): skipping in list")

                
        else:
            paths = list()
            paths.append('/'.join([self.config['scripts_dir'], "queries"]))
            paths.append('/'.join([self.config['scripts_dir'], "multi-queries"]))

            if self.config['user_scripts_dir']:
                paths.append('/'.join([self.config['user_scripts_dir'], 'queries']))
                paths.append('/'.join([self.config['user_scripts_dir'], 'multi-queries']))

            if self.config['extra_scripts_dir']:
                paths.append('/'.join([self.config['extra_scripts_dir'], 'queries']))
                paths.append('/'.join([self.config['extra_scripts_dir'], 'multi-queries']))

            for dd in paths:
                if not os.path.exists(dd):
                    continue
                for d in os.listdir(dd):
                    command = re.sub("(\.py|\.sh)$", "", d)
                    commandpath = os.path.join(dd, d)
                    if re.match(".*\.pyc$", d):
                        continue

                    try:
                        (rc, command_type, se) = self.find_query_command(command)
                        if rc:
                            commandpath = se.get_script()
                            csum = se.csum()
                            if commandpath in query_manifest and csum != "N/A" and csum == query_manifest[commandpath]['csum']:
                                self._logger.debug("skipping query help refresh run ("+str(command)+"): no change in query")
                                cmd = query_manifest[commandpath]['command']
                                rc = query_manifest[commandpath]['returncode']
                                sout = query_manifest[commandpath]['output']
                            else:
                                (cmd, rc, sout) = se.execute(capture_output=True, cmdline='help')

                            if rc == 0:
                                query_manifest[commandpath] = self.format_query_manifest_record(cmd, "SUCCESS", rc, time.time(), command_type, sout, csum)
                                record['result']['rows'].append([command, sout])
                            else:
                                query_manifest[commandpath] = self.format_query_manifest_record(cmd, "FAIL", rc, time.time(), command_type, "N/A", csum)
                                
                    except Exception as err:
                        self._logger.debug("cannot execute ("+str(command)+"): skipping in list")

        self.anchoreDB.save_query_manifest(query_manifest)
        
        result['list_query_commands'] = record
        return(result)

    def check_for_warnings(self, result):
        for k in result.keys():
            if 'warns' in result[k]:
                return(True)
        return(False)

    def run_query(self, query):
        result = {}

        if len(query) == 0:
            return(self.list_query_commands())
        elif len(query) == 1:
            action = query[0]
            params = ['help']
        else:
            action = query[0]
            params = query[1:]

        if re.match(r".*(\.\.|~|/).*", action) or re.match(r"^\..*", action):
            self._logger.error("invalid query string (bad characters in string)")
            return(False)
                    
        try:
            (rc, command_type, se) = self.find_query_command(action)
        except Exception as err:
             raise err

        if not rc:
            self._logger.error("cannot find query command in Anchore query directory: " + action + "(.py|.sh)")
            return(False)

        if params and params[0] == 'help':
            return(self.list_query_commands(action))

        outputdir = None

        if command_type == 'query':
            for imageId in self.images:
                (rc, cmd, output) = self.execute_query([imageId], se, params)
                if rc:
                    result[imageId] = output

        elif command_type == 'multi-query':
            (rc, cmd, output) = self.execute_query(self.images, se, params)
            if rc:
                result['multi'] = output

        return(result)

