# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import Queue
import datetime
import json
import os
import signal
import socket
import subprocess
import threading
import time
import traceback
import uuid

from celery import Celery
from celery.app.control import Control
from celery.exceptions import TaskRevokedError
from celery.execute import send_task
from celery.signals import celeryd_after_setup
from celery.task.control import revoke
from celery.utils.log import get_task_logger
from pymongo import MongoClient
import requests
from twisted.internet import reactor
from twisted.internet.error import ProcessDone, ProcessTerminated, ProcessExitedAlready
from twisted.internet.protocol import ProcessProtocol

from minion.backend import ownership
from minion.backend.utils import backend_config, scan_config, scannable


cfg = backend_config()
celery = Celery('tasks', broker=cfg['celery']['broker'], backend=cfg['celery']['backend'])

# If the config does not mention mongo then we do not set it up. That is ok because
# that will only happen in plugin-workers that do not need direct mongodb access.
if cfg.get('mongodb') is not None:
    mongodb = MongoClient(host=cfg['mongodb']['host'], port=cfg['mongodb']['port'])
    db = mongodb.minion
    plans = db.plans
    scans = db.scans
    issues = db.issues

logger = get_task_logger(__name__)


def find_session(scan, session_id):
    for session in scan['sessions']:
        if session['id'] == session_id:
            return session


@celery.task
def scan_start(scan_id, t):
    scans.update({"id": scan_id},
                 {"$set": {"state": "STARTED",
                           "started": datetime.datetime.utcfromtimestamp(t)}})

@celery.task
def scan_finish(scan_id, state, t, failure=None):

    try:

        #
        # Find the scan we are asked to finish
        #

        scan = scans.find_one({'id': scan_id})
        if not scan:
            logger.error("Cannot find scan %s" % scan_id)
            return

        #
        # Mark the scan as finished with the provided state
        #

        if failure:
            scans.update({"id": scan_id},
                         {"$set": {"state": state,
                                   "finished": datetime.datetime.utcfromtimestamp(t),
                                   "failure": failure}})
        else:
            scans.update({"id": scan_id},
                         {"$set": {"state": state,
                                   "finished": datetime.datetime.utcfromtimestamp(t)}})

        #
        # Fire the callback
        #

        try:
            callback = scan['configuration'].get('callback')
            if callback:
                r = requests.post(callback['url'], headers={"Content-Type": "application/json"},
                                  data=json.dumps({'event': 'scan-state', 'id': scan['id'], 'state': state}))
                r.raise_for_status()
        except Exception as e:
            logger.exception("(Ignored) failure while calling scan state callback for scan %s" % scan['id'])

        #
        # If there are remaining plugin sessions that are still in the CREATED state
        # then change those to CANCELLED because we wont be executing them anymore.
        #

        for s in scan['sessions']:
            if s['state'] == 'CREATED':
                s['state'] = 'CANCELLED'
                scans.update({"id": scan_id, "sessions.id": s['id']},
                             {"$set": {"sessions.$.state": "CANCELLED"}})

    except Exception as e:

        logger.exception("Error while finishing scan. Trying to mark scan as FAILED.")

        try:
            scans.update({"id": scan_id},
                         {"$set": {"state": "FAILED",
                                   "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

@celery.task
def scan_stop(scan_id):

    logger.debug("This is scan_stop " + str(scan_id))

    try:

        #
        # Find the scan we are asked to stop
        #

        scan = scans.find_one({'id': scan_id})
        if not scan:
            logger.error("Cannot find scan %s" % scan_id)
            return

        #
        # Set the scan to cancelled. Even though some plugins may still run.
        #

        scans.update({"id": scan_id}, {"$set": {"state": "STOPPED", "started": datetime.datetime.utcnow()}})

        #
        # Set all QUEUED and STARTED sessions to STOPPED and revoke the sessions that have been queued
        #

        for session in scan['sessions']:
            if session['state'] in ('QUEUED', 'STARTED'):
                scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$.state": "STOPPED", "sessions.$.finished": datetime.datetime.utcnow()}})
            if '_task' in session:
                revoke(session['_task'], terminate=True, signal='SIGUSR1')

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

@celery.task
def session_queue(scan_id, session_id, t):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$set": {"sessions.$.state": "QUEUED",
                           "sessions.$.queued": datetime.datetime.utcfromtimestamp(t)}})

@celery.task
def session_start(scan_id, session_id, t):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$set": {"sessions.$.state": "STARTED",
                           "sessions.$.started": datetime.datetime.utcfromtimestamp(t)}})

@celery.task
def session_set_task_id(scan_id, session_id, task_id):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$set": {"sessions.$._task": task_id}})

@celery.task
def session_report_issue(scan_id, session_id, issue):
    # Check if the issue already exists.
    # If not, insert it in the collection then put the reference in the scan,
    # else put the reference in the scan and update the severity
    found_issue = issues.find_one({"Id": issue["Id"]})
    if found_issue is None:
        issues.insert(issue)
    else:
        issues.update({"Id": issue["Id"]}, {"$set": {"Severity": issue["Severity"]}})
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$push": {"sessions.$.issues": issue["Id"]}})

@celery.task
def session_report_artifact(scan_id, session_id, artifact):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$push": {"sessions.$.artifacts": artifact}})

@celery.task
def session_finish(scan_id, session_id, state, t, failure=None):
    if failure:
        scans.update({"id": scan_id, "sessions.id": session_id},
                     {"$set": {"sessions.$.state": state,
                               "sessions.$.finished": datetime.datetime.utcfromtimestamp(t),
                               "sessions.$.failure": failure}})
    else:
        scans.update({"id": scan_id, "sessions.id": session_id},
                     {"$set": {"sessions.$.state": state,
                               "sessions.$.finished": datetime.datetime.utcfromtimestamp(t)}})

@celery.task
def set_status_issues(scan_id):
    scan = scans.find_one({"id": scan_id})
    list_scan = list(scans.find({'configuration.target': scan['configuration']['target'], 'plan.name': scan['plan']['name']}).sort("created", -1))
    last_scan = list_scan[0]

    if len(list_scan) > 1:

        second_to_last_scan = list_scan[1]

        # For each session in last scan
        for session in last_scan['sessions']:
            # For each issue in last scan (in each session)
            for issue in session['issues']:
                # Check if issue is in second_to_last_scan :
                in_second_to_last = False
                for second_session in second_to_last_scan['sessions']:
                    if issue in second_session['issues']:
                        old_issue = issues.find_one({"Id": issue})
                        issues.update({"Id": issue},
                                      {"$set": {"Status": "Current", "OldStatus": old_issue['Status']}})
                        in_second_to_last = True
                        break

                # Else it's a new issue
                if not in_second_to_last:
                    issues.update({"Id": issue},
                                  {"$set": {"Status": "Current", "OldStatus": "-"}})

        for second_session in second_to_last_scan['sessions']:
            # For each issue in last scan (in each session)
            for issue in second_session['issues']:
                # Check if issue is in second_to_last_scan :
                issue_found = False
                last_session_id = None
                for session in last_scan['sessions']:
                    if session['plugin']['name'] == second_session['plugin']['name']:
                        last_session_id = session["id"]
                        if issue in session['issues']:
                            issue_found = True
                            break

                # Else the issue is fixed if the scan ended well
                if not issue_found and last_session_id is not None: #
                    # if not issue_found and last_session_id is not None:
                    scans.update({"id": scan_id, "sessions.id": last_session_id},
                                 {"$push": {"sessions.$.issues": issue}})

                    old_issue = issues.find_one({"Id": issue})

                    state = "Fixed"

                    # Fix only if scan finished well
                    if session["state"] is not "FINISHED":
                        state = old_issue['Status']
                        
                    issues.update({"Id": issue}, {"$set": {"Status": state, "OldStatus": old_issue['Status']}})

    else:
        # It's the first scan, all issues are new
        for session in last_scan['sessions']:
            for issue in session['issues']:
                issues.update({"Id": issue},
                              {"$set": {"Status": "Current", "OldStatus": "-"}})


# plugin_worker







plugin_runner_process = None


#
#
#

class Runner(ProcessProtocol):

    def __init__(self, plugin_class, configuration, session_id, callback):
        self._plugin_class = plugin_class
        self._configuration = configuration
        self._session_id = session_id
        self._callback = callback
        self._exit_status = None
        self._process = None
        self._buffer = ""

    # ProcessProtocol Methods

    def _parseLines(self, buffer):
        lines = buffer.split("\n")
        if len(lines) == 1:
            return ([], buffer)
        elif buffer.endswith("\n"):
            return (lines[0:-1],"")
        else:
            return (lines[0:-1],lines[-1])

    def outReceived(self, data):
        # Parse incoming data, taking incomplete lines into account
        buffer = self._buffer + data
        lines, self._buffer = self._parseLines(buffer)
        # Process all the complete lines that we received
        for line in lines:
            self._process_message(line)

    def errReceived(self, data):
        pass # TODO What to do with stderr?

    def processEnded(self, reason):
        if isinstance(reason.value, ProcessTerminated):
            self._exit_status = reason.value.status
        if isinstance(reason.value, ProcessDone):
            self._exit_status = reason.value.status
        self._process = None
        reactor.stop()

    # Runner

    def _process_message(self, message):
        # TODO Harden this by catching JSON parse errors and invalid messages
        m = json.loads(message)
        self._callback(m)

    def _locate_program(self, program_name):
        for path in os.getenv('PATH').split(os.pathsep):
            program_path = os.path.join(path, program_name)
            if os.path.isfile(program_path) and os.access(program_path, os.X_OK):
                return program_path

    def run(self):

        #
        # Setup the arguments
        #

        self._arguments = [ "minion-plugin-runner",
                           "-c", json.dumps(self._configuration),
                           "-p", self._plugin_class,
                           "-s", self._session_id ]

        #
        # Spawn a plugin-runner process
        #

        plugin_runner_path = self._locate_program("minion-plugin-runner")
        if plugin_runner_path is None:
            # TODO EMIT FAILURE
            return False

        self._process = reactor.spawnProcess(self, plugin_runner_path, self._arguments, env=None)

        #
        # Run the twisted reactor. It will be stopped either when the plugin-runner has
        # finished or when it has timed out.
        #

        reactor.run()

        return self._exit_status

    def terminate(self):
        if self._process is not None:
            try:
                self._process.signalProcess('KILL')
            except ProcessExitedAlready as e:
                pass
        if self._terminate_id is not None:
            if self._terminate_id.active():
                self._terminate_id.cancel()
            self._terminate_id = None

    def schedule_stop(self):

        #
        # Send the plugin runner a USR1 signal to tell it to stop. Also
        # start a timer to force kill the runner if it does not stop
        # on time.
        #

        self._process.signalProcess(signal.SIGUSR1)
        self._terminate_id = reactor.callLater(10, self.terminate)


def get_scan(api_url, scan_id):
    r = requests.get(api_url + "/scans/" + scan_id)
    r.raise_for_status()
    j = r.json()
    return j['scan']

def get_site_info(api_url, url):
    r = requests.get(api_url + '/sites', params={'url': url})
    r.raise_for_status()
    j = r.json()
    return j['sites'][0]

def set_finished(scan_id, state, failure=None):
    send_task("minion.backend.tasks.scan_finish",
              [scan_id, state, time.time(), failure],
              queue='state').get()

#
# run_plugin
#

def find_session(scan, session_id):
    for session in scan['sessions']:
        if session['id'] == session_id:
            return session

@celery.task
def run_plugin(scan_id, session_id):

    logger.debug("This is run_plugin " + str(scan_id) + " " + str(session_id))

    try:

        #
        # Find the scan for this plugin session. Bail out if the scan has been marked as STOPPED or if
        # the state is not STARTED.
        #

        scan = get_scan(cfg['api']['url'], scan_id)
        if not scan:
            logger.error("Cannot load scan %s" % scan_id)
            return

        if scan['state'] in ('STOPPING', 'STOPPED'):
            return

        if scan['state'] != 'STARTED':
            logger.error("Scan %s has invalid state. Expected STARTED but got %s" % (scan_id, scan['state']))
            return

        #
        # Find the plugin session in the scan. Bail out if the session has been marked as STOPPED or if
        # the state is not QUEUED.
        #

        session = find_session(scan, session_id)
        if not session:
            logger.error("Cannot find session %s/%s" % (scan_id, session_id))
            return

        if session['state'] != 'QUEUED':
            logger.error("Session %s/%s has invalid state. Expected QUEUED but got %s" % (scan_id, session_id, session['state']))
            return

        #
        # Move the session in the STARTED state
        #

        send_task("minion.backend.tasks.session_start",
                  [scan_id, session_id, time.time()],
                  queue='state').get()

        finished = None

        #
        # This is an experiment to see if removing Twisted makes the celery workers more stable.
        #

        def enqueue_output(fd, queue):
            try:
                for line in iter(fd.readline, b''):
                    queue.put(line)
            except Exception as e:
                logger.exception("Error while reading a line from the plugin-runner")
            finally:
                fd.close()
                queue.put(None)

        def make_signal_handler(p):
            def signal_handler(signum, frame):
                p.send_signal(signal.SIGUSR1)
            return signal_handler

        arguments = [ "minion-plugin-runner",
                      "-c", json.dumps(session['configuration']),
                      "-p", session['plugin']['class'],
                      "-s", session_id ]

        p = subprocess.Popen(arguments, bufsize=1, stdout=subprocess.PIPE, close_fds=True)

        signal.signal(signal.SIGUSR1, make_signal_handler(p))

        q = Queue.Queue()
        t = threading.Thread(target=enqueue_output, args=(p.stdout, q))
        t.daemon = True
        t.start()

        while True:
            try:
                line = q.get(timeout=0.25)
                if line is None:
                    break

                line = line.strip()

                if finished is not None:
                    logger.error("Plugin emitted (ignored) message after finishing: " + line)
                    return

                msg = json.loads(line)

                # Issue: persist it
                if msg['msg'] == 'issue':
                    send_task("minion.backend.tasks.session_report_issue",
                              args=[scan_id, session_id, msg['data']],
                              queue='state').get()

                # Progress: update the progress
                if msg['msg'] == 'progress':
                    pass # TODO

                # Artifact: save the report
                if msg['msg'] == 'artifact':
                    send_task("minion.backend.tasks.session_report_artifact",
                              args=[scan_id, session_id, msg['data']],
                              queue='state').get()

                # Finish: update the session state, wait for the plugin runner to finish, return the state
                if msg['msg'] == 'finish':
                    finished = msg['data']['state']
                    if msg['data']['state'] in ('FINISHED', 'FAILED', 'STOPPED', 'TERMINATED', 'TIMEOUT', 'ABORTED'):
                        send_task("minion.backend.tasks.session_finish",
                                  [scan['id'], session['id'], msg['data']['state'], time.time(), msg['data']['failure']],
                                  queue='state').get()

            except Queue.Empty:
                pass

        return_code = p.wait()

        signal.signal(signal.SIGUSR1, signal.SIG_DFL)

        if not finished:
            failure = { "hostname": socket.gethostname(),
                        "message": "The plugin did not finish correctly",
                        "exception": None }
            send_task("minion.backend.tasks.session_finish",
                      [scan['id'], session['id'], 'FAILED', time.time(), failure],
                      queue='state').get()

        send_task("minion.backend.tasks.set_status_issues",
                  args=[scan_id],
                  queue='state').get()

        return finished

    except Exception as e:

        #
        # Our exception strategy is simple: if anything was thrown above that we did not explicitly catch then
        # we assume there was a non recoverable error that made the plugin session fail. We mark it as such and
        # record the exception.
        #

        logger.exception("Error while running plugin session. Marking session FAILED.")

        try:
            failure = { "hostname": socket.gethostname(),
                        "message": str(e),
                        "exception": traceback.format_exc() }
            send_task("minion.backend.tasks.session_finish",
                      [scan_id, session_id, "FAILED", time.time(), failure],
                      queue='state').get()
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

        return "FAILED"





# scan worker






def get_scan(api_url, scan_id):
    r = requests.get(api_url + "/scans/" + scan_id)
    r.raise_for_status()
    j = r.json()
    return j['scan']

def queue_for_session(session, cfg):
    queue = 'plugin'
    if 'plugin_worker_queues' in cfg:
        weight = session['plugin']['weight']
        if weight in ('heavy', 'light'):
            queue = cfg['plugin_worker_queues'][weight]
    return queue

@celery.task(ignore_result=True)
def scan(scan_id):

    try:

        #
        # See if the scan exists.
        #

        scan = get_scan(cfg['api']['url'], scan_id)
        if not scan:
            logger.error("Cannot load scan %s" % scan_id)
            return

        #
        # Is the scan in the right state to be started?
        #

        if scan['state'] != 'QUEUED':
            logger.error("Scan %s has invalid state. Expected QUEUED but got %s" % (scan_id, scan['state']))
            return

        #
        # Move the scan to the STARTED state
        #

        scan['state'] = 'STARTED'
        send_task("minion.backend.tasks.scan_start",
                  [scan_id, time.time()],
                  queue='state').get()

        #
        # Check this site against the access control lists
        #

        if not scannable(scan['configuration']['target'],
                         scan_config().get('whitelist', []),
                         scan_config().get('blacklist', [])):
            failure = {"hostname": socket.gethostname(),
                       "reason": "target-blacklisted",
                       "message": "The target cannot be scanned by Minion because its (IPv4) address has been blacklisted."}
            return set_finished(scan_id, 'ABORTED', failure=failure)

        #
        # Verify ownership prior to running scan
        #

        target = scan['configuration']['target']
        site = get_site_info(cfg['api']['url'], target)
        if not site:
            return set_finished(scan_id, 'ABORTED')

        if site.get('verification') and site['verification']['enabled']:
            verified = ownership.verify(target, site['verification']['value'])
            if not verified:
                failure = {"hostname": socket.gethostname(),
                           "reason": "target-ownership-verification-failed",
                           "message": "The target cannot be scanned because the ownership verification failed."}
                return set_finished(scan_id, 'ABORTED', failure=failure)

        #
        # Run each plugin session
        #

        for session in scan['sessions']:

            #
            # Mark the session as QUEUED
            #

            session['state'] = 'QUEUED'
            #scans.update({"id": scan['id'], "sessions.id": session['id']}, {"$set": {"sessions.$.state": "QUEUED", "sessions.$.queued": datetime.datetime.utcnow()}})
            send_task("minion.backend.tasks.session_queue",
                      [scan['id'], session['id'], time.time()],
                      queue='state').get()

            #
            # Execute the plugin. The plugin worker will set the session state and issues.
            #

            logger.info("Scan %s running plugin %s" % (scan['id'], session['plugin']['class']))

            queue = queue_for_session(session, cfg)
            result = send_task("minion.backend.tasks.run_plugin",
                               [scan_id, session['id']],
                               queue=queue)

            #scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$._task": result.id}})
            send_task("minion.backend.tasks.session_set_task_id",
                      [scan_id, session['id'], result.id],
                      queue='state').get()

            try:
                plugin_result = result.get()
            except TaskRevokedError as e:
                plugin_result = "STOPPED"

            session['state'] = plugin_result

            #
            # If the user stopped the workflow or if the plugin aborted then stop the whole scan
            #

            if plugin_result in ('ABORTED', 'STOPPED'):
                # Mark the scan as failed
                #scans.update({"id": scan_id}, {"$set": {"state": plugin_result, "finished": datetime.datetime.utcnow()}})
                send_task("minion.backend.tasks.scan_finish",
                          [scan_id, plugin_result, time.time()],
                          queue='state').get()
                # Mark all remaining sessions as cancelled
                for s in scan['sessions']:
                    if s['state'] == 'CREATED':
                        s['state'] = 'CANCELLED'
                        #scans.update({"id": scan['id'], "sessions.id": s['id']}, {"$set": {"sessions.$.state": "CANCELLED", "sessions.$.finished": datetime.datetime.utcnow()}})
                        send_task("minion.backend.tasks.session_finish",
                                  [scan['id'], s['id'], "CANCELLED", time.time()],
                                  queue='state').get()
                # We are done with this scan
                return

        #
        # Move the scan to the FINISHED state
        #

        scan['state'] = 'FINISHED'

        #
        # If one of the plugin has failed then marked the scan as failed
        #
        for session in scan['sessions']:
            if session['state'] == 'FAILED':
                scan['state'] = 'FAILED'

        #scans.update({"id": scan_id}, {"$set": {"state": "FINISHED", "finished": datetime.datetime.utcnow()}})
        send_task("minion.backend.tasks.scan_finish",
                  [scan_id, scan['state'], time.time()],
                  queue='state').get()

    except Exception as e:

        #
        # Our exception strategy is simple: if anything was thrown above that we did not explicitly catch then
        # we assume there was a non recoverable error that made the scan fail. We mark it as such and
        # record the exception.
        #

        logger.exception("Error while running scan. Marking scan FAILED.")

        try:
            failure = { "hostname": socket.gethostname(),
                        "reason": "backend-exception",
                        "message": str(e),
                        "exception": traceback.format_exc() }
            send_task("minion.backend.tasks.scan_finish",
                      [scan_id, "FAILED", time.time(), failure],
                      queue='state').get()
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")
