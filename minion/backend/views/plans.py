#!/usr/bin/env python

import calendar
import datetime
import functools
import importlib
import uuid

from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import api_guard, plans, plugins, users, sites, groups, scans


def _plan_description(plan):
    return {
        'description': plan['description'],
        'name': plan['name'],
        'workflow': plan['workflow'],
        'created' : plan['created'] }

def get_plan_by_plan_name(plan_name):
    return plans.find_one({'name': plan_name})

def get_sanitized_plans():
    return [sanitize_plan(_plan_description(plan)) for plan in plans.find()]

def _check_plan_by_email(email, plan_name):
    plan = plans.find_one({'name': plan_name})
    if not plan:
        return False
    sitez = sites.find({'plans': plan_name})
    if sitez.count():
        matches = 0
        for site in sitez:
            groupz = groups.find({'users': email, 'sites': site['url']})
            if groupz.count():
                matches += 1
        return matches

def get_plans_by_email(email):
    plans = get_sanitized_plans()
    matched_plans = [plan for plan in plans if _check_plan_by_email(email, plan["name"])]
    return matched_plans

def permission(view):
    @functools.wraps(view)
    def has_permission(*args, **kwargs):
        email = request.args.get('email')
        if email:
            user = users.find_one({'email': email})
            if not user:
                return jsonify(success=False, reason='User does not exist.')
            if user['role'] == 'user':
                plan_name = request.view_args['plan_name']
                if not _check_plan_by_email(email, plan_name):
                    return jsonify(success=False, reason="Plan does not exist.")
        return view(*args, **kwargs) # if groupz.count is not zero, or user is admin
    return has_permission

def sanitize_plan(plan):
    if plan.get('_id'):
        del plan['_id']
    for field in ('created',):
        if plan.get(field) is not None:
            plan[field] = calendar.timegm(plan[field].utctimetuple())
    return plan

def _split_plugin_class_name(plugin_class_name):
    e = plugin_class_name.split(".")
    return '.'.join(e[:-1]), e[-1]

def _import_plugin(plugin_class_name):
    package_name, class_name = _split_plugin_class_name(plugin_class_name)
    plugin_module = importlib.import_module(package_name, class_name)
    return getattr(plugin_module, class_name)

def _check_plan_workflow(workflow):
    """ Ensure plan workflow contain valid structure. """
    if not all(isinstance(plugin, dict) for plugin in workflow):
        return False
    required_fields = set(('plugin_name', 'configuration', 'description'))
    #
    if len(workflow) == 0:
        return False
    for plugin in workflow:
        # test whether every field in required_fields is in plugin keys
        if not required_fields.issubset(set(plugin.keys())):
            return False
        if not isinstance(plugin['configuration'], dict):
            return False
        try:
            _import_plugin(plugin['plugin_name'])
        except (AttributeError, ImportError):
            return False
    return True

def _check_plan_exists(plan_name):
    return plans.find_one({'name': plan_name}) is not None

# API Methods to manage plans

#
# Return a list of available plans. Plans are global and not
# limited to a specific user.
#
#  GET /plans
#
# Returns an array of plan:
#
#  { "success": true,
#    "plans": [ { "description": "Run an nmap scan",
#                 "name": "nmap" },
#               ... ] }
#

@app.route("/plans", methods=['GET'])
@api_guard
def get_plans():
    name = request.args.get('name')
    if name:
        plan = get_plan_by_plan_name(name)
        if not plan:
            return jsonify(success=True, plans=[])
        else:
            # Fill in the details of the plugin
            for step in plan['workflow']:
                plugin = plugins.get(step['plugin_name'])
            return jsonify(success=True, plans=[sanitize_plan(plan)])
    else:
        email = request.args.get('email')
        if email:
            plans = get_plans_by_email(email)
        else:
            plans = get_sanitized_plans()
        return jsonify(success=True, plans=plans)

#
# Delete an existing plan
#
#  DELETE /plans/<plan_name>
#

@app.route('/plans/<plan_name>', methods=['DELETE'])
@api_guard
def delete_plan(plan_name):
    if not get_plan_by_plan_name(plan_name):
        return jsonify(success=False, reason="Plan does not exist.")
    # Remove the plan
    plans.remove({'name': plan_name})

    # Delete cascade mentions of plan
    remove_plan(plan_name)

    return jsonify(success=True)


# Delete every issues and scan with the same target and plan
# param scan_id : id of the scan to delete
def remove_similar_scan(scan_id):
    # Obtain information about the scan and its target
    scan = scans.find_one({"id": scan_id})

    # Check the scan exists
    if scan is None:
        print "No entry found"
        return

    # Get every scan with the same configuration and target
    list_scan = list(
        scans.find({'configuration.target': scan['configuration']['target'], 'plan.name': scan['plan']['name']}).sort(
            "created", -1))

    # Get the ID of every scan with the same configuration
    for prev_scan in list_scan:
        print "to delete : " + prev_scan["id"] + "\n"

        # Delete the scan
        delete_scan(prev_scan["id"])


# Find issues of scan
# param scan_id : string id of the scan
# returns : array containing id of issues from the scan
def find_issues(scan_id):
    return scans.find({"id": scan_id}).distinct("sessions.issues")


# Delete issues only existing in scan (no other dependencies)
# param scan_id : string id of the scan
#
def delete_issues(scan_id):
    # Get issues from the scan
    scan_issues = find_issues(scan_id)

    # Browse each issue
    to_delete = []
    for issue in scan_issues:
        # Find others scan for this issue
        res = scans.find({"sessions.issues": issue, "id": {"$ne": scan_id}}, {"id": 1, "_id": 0})

        # Add issue to delete list if no other scan is linked
        if res.count() == 0:
            to_delete.append(issue)

    # Delete issues
    for delete in to_delete:
        issues.remove({"Id": delete})

    return to_delete


# Get every existing scan for a given plan
# param plan : string containing name of the plan
# return : array of scan id
def get_scans(plan):
    # Get every scan with this plan
    res = list(scans.find({'plan.name': plan}, {"id": 1, "_id": 0}))

    # Format result
    ids = []
    for myid in res:
        ids.append(myid["id"])

    return ids


# Delete every issue only linked to the scan, then delete the scan
# param : scan_id to delete
def delete_scan(scan_id):
    # Remove the issues
    removed = delete_issues(scan_id)

    # Remove the scan
    scans.remove({"id": scan_id})

    return "removed " + str(len(removed)) + " issues and scan " + scan_id


# Delete every trace of existing plan
# Warning no coming back, this removes permanently the plan and results from the data-base
# param : name of the plan
def remove_plan(plan):
    # Get id of scan containing this plan
    to_delete = get_scans(plan)

    # Delete every instance of each scan
    for line in to_delete:
        remove_similar_scan(line)

    # Get id of every site containing the plan
    res = list(sites.find({'plans': plan}, {"id": 1, "_id": 0, "plans": 1}))

    for site in res:
        # Remove old plan from their list
        site_plans = site["plans"]
        site_plans.remove(plan)

        # Update the record of the site
        sites.update({"id": site["id"]}, {"$set": {"plans": site_plans}})


#
# Create a new plan
#

@app.route("/plans", methods=['POST'])
@api_guard('application/json')
def create_plan():
    plan = request.json

    # Verify incoming plan
    if plans.find_one({'name': plan['name']}) is not None:
        return jsonify(success=False, reason='plan-already-exists')

    if not _check_plan_workflow(plan['workflow']):
        return jsonify(success=False, reason='invalid-plan-exists')

    # Create the plan
    new_plan = { 'name': plan['name'],
                 'description': plan['description'],
                 'workflow': plan['workflow'],
                 'created': datetime.datetime.utcnow() }
    plans.insert(new_plan)

    # Return the new plan
    plan = plans.find_one({"name": plan['name']})
    if not plan:
        return jsonify(success=False)
    return jsonify(success=True, plan=sanitize_plan(plan))

#
# Update a plan
#

@app.route('/plans/<plan_name>', methods=['POST'])
@api_guard
@permission
def update_plan(plan_name):
    if not get_plan_by_plan_name(plan_name):
        return jsonify(success=True)
    new_plan = request.json
    if not _check_plan_workflow(new_plan['workflow']):
        return jsonify(success=False, reason='invalid-plan')

    # Update the plan
    changes = {}
    if 'description' in new_plan:
        changes['description'] = new_plan['description']
    if 'workflow' in new_plan:
        changes['workflow'] = new_plan['workflow']
    plans.update({'name': plan_name}, {'$set': changes})
    # Return the plan
    plan = plans.find_one({"name": plan_name})
    return jsonify(success=True, plan=sanitize_plan(plan))


#
# Return a single plan description. Takes the plan name.
#
#  GET /plans/:plan_name
#
# Returns a JSON structure that contains the complete plan
#
#  { "success": true,
#    "plan": { "description": "Run an nmap scan",
#               "name": "nmap",
#               "workflow": [ { "configuration": {},
#                               "description": "Run the NMAP scanner.",
#                               "plugin": { "version": "0.2",
#                                           "class": "minion.plugins.nmap.NMAPPlugin",
#                                           "weight": "light",
#                                           "name": "NMAP" } } ] }
#

@app.route("/plans/<plan_name>", methods=['GET'])
@api_guard
@permission
def get_plan(plan_name):
    plan = get_plan_by_plan_name(plan_name)
    if plan:
        # Fill in the details of the plugin
        for step in plan['workflow']:
            plugin = plugins.get(step['plugin_name'])
        return jsonify(success=True, plan=sanitize_plan(plan))
    else:
        return jsonify(success=False, reason="Plan does not exist")
