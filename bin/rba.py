## Minimal set of standard modules to import
import csv      ## Result set is in CSV format
import gzip     ## Result set is gzipped
import json     ## Payload comes in JSON format
import logging  ## For specifying log levels
import sys      ## For appending the library path
import re       ## For regex matches for user categories

## Standard modules specific to this action

import splunk.search as search
import splunk.util
## Importing the cim_actions.py library
from splunk.clilib.bundle_paths import make_splunkhome_path
# import our cim_actions.py library
# from Splunk_SA_CIM
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
from cim_actions import ModularAction, ModularActionTimer

## Retrieve a logging instance from ModularAction
## It is required that this endswith _modalert
logger = ModularAction.setup_logger('rba_modalert')

## Subclass ModularAction for purposes of implementing
## a script specific dowork() method
class RbaModularAction(ModularAction):

    ## This method will initialize PwnedModularAction
    def __init__(self, settings, logger, action_name=None):
        ## Call ModularAction.__init__
        super(RbaModularAction, self).__init__(settings, logger, action_name)
        ## add status info
        self.addinfo()
        ## search_name
        self.search_name = self.search_name or 'AdHoc Risk Score'

    
    def dowork(self):
        #logger.info(str(self.settings))
        #logger.info(str(self.configuration)) 
        ## for adhoc risk modifiers from incident review, change search_name to event's search_name if available.
        ## check if user mod was checked
        if splunk.util.normalizeBoolean(self.configuration.get( 'modify_user', False )) is True:
            ## try to run a search, here's the macro we need to append
            search_string = "| loadjob {sid} {macro}" 
            user_macro = "`risk_score_user({impact},{confidence},{obj},{category})`"
            user_macro = user_macro.format(impact=self.configuration.get('impact'),confidence=self.configuration.get('confidence'),\
                    obj=self.configuration.get('user_field'),category=self.configuration.get('category'))
            logger.info(user_macro)
            #i self.session_key = self.settings.get('session_key')
            # serach example 
            # job = search.dispatch( \
            #    spl, sessionKey=session_key, earliestTime=earliest, latestTime=latest) 
            # job_finished = search.waitForJob(job, timeout)
            job = search.dispatch(search_string.format(sid=self.settings.get('sid'),macro=user_macro),sessionKey=self.settings.get('session_key'))
            job_finished = search.waitForJob(job,maxtime=-1)
            if job_finished:
                logger.info("JOB INFO: {}".format(str(job.messages)))
            else:
                logger.info("JOB FAILED: {}".format(str(job.messages)))

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)
    
    try:
        modaction = RbaModularAction(sys.stdin.read(), logger, 'rba')
        if modaction.configuration.get('verbose') == "true":
            logger.debug(modaction.settings)
        
        with ModularActionTimer(modaction, 'main', modaction.start_timer):
            ## process results
            #modaction.update(result)
            modaction.invoke()
            modaction.dowork()
            """
            if modaction.writeevents(index=modaction.configuration.get('index', 'risk'),
                                     source=modaction.search_name):
                modaction.message('Successfully created risk entry event',
                                  status='success',
                                  rids=modaction.rids)
            else:
                modaction.message('Failed to create splunk event',
                                  status='failure',
                                  rids=modaction.rids,
                                  level=logging.ERROR)
            """ 
    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except Exception:
            logger.info(e)
        print >> sys.stderr, "ERROR: %s" % e
        sys.exit(3)
