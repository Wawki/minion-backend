#!/usr/bin/env python

from flask import jsonify, request
from minion.backend.views.base import api_guard, groups, scans, issues, sanitize_time
from minion.backend.app import app
from minion.backend.views.scans import permission

#
# Search for issues:
#
#  /GET /issues
#
# Parameters:
#
#  group_name
#  plan_name
#  issue_code
#
# Returns:
#
#  { success: true,
#    issues: [
#      { site: "", scan_id: "", issue_id: "" }
#    ] }
#
# Examples:
#
#
#  Find all Server Identifying issues:
#
#   GET /issues?group_name=miniminion&plan_name=miniminion&issue_code=SD-0
#

#
# TODO This is all really bad. We get away with it because mongo is so fast but we
# obviously need to make some big changes in the data model.
#

@app.route('/issues', methods=['GET'])
@api_guard
def get_issues():
    issue_codes = request.args.getlist('issue_code')

    issues = []

    group = groups.find_one({'name': request.args.get('group_name')})
    if group is not None:
        for target in group['sites']:
            scan = scans.find_one({"plan.name": request.args.get('plan_name'),
                                   "configuration.target": target,
                                   "state": "FINISHED",
                                   "sessions.issues.Code": {"$in": issue_codes}},
                                  {"id": 1, "created": 1, "started": 1, "finished": 1,
                                   "configuration.target": 1, "sessions.issues.$": 1})
            if scan:
                hit = {"site": {"url": scan["configuration"]["target"]},
                       "scan": {"id": scan["id"],
                                "created": sanitize_time(scan["created"]),
                                "started": sanitize_time(scan["started"]),
                                "finished": sanitize_time(scan["finished"]),
                                "sessions": []}}
                for session in scan["sessions"]:
                    s = {"plugin": {"class": session["plugin"]["class"]}, "issues": []}
                    for issue_id in session['issues']:
                        issue = issues.find_one({"Id": issue_id})
                        if issue['Code'] in issue_codes:
                            s["issues"].append({"summary": issue["Summary"], "id": issue["Id"], "code": issue["Code"]})
                    hit["scan"]["sessions"].append(s)
                issues.append(hit)

    return jsonify(success=True, issues=issues)

@app.route('/issue/tagIssue', methods=['POST'])
@api_guard('application/json')
@permission
def tag_issue():

    # Retrieve issued ID and boolean
    issue_id = request.json["issueId"]
    boolean = request.json["boolean"]
    status = request.json["status"]
    old_issue = issues.find_one({"Id": issue_id})

    # Try to tag or untag the issue
    if boolean:
        issue = issues.find_and_modify({"Id": issue_id}, {"$set": {"Status": status, "OldStatus": old_issue['Status']}})
    else:
        issue = issues.find_and_modify({"Id": issue_id}, {"$set": {"Status": old_issue['OldStatus'], "OldStatus": old_issue['Status']}})

    if issue is None:
        return jsonify(success=False, reason="no-such-issue")

    return jsonify(success=True)


# Find issues of scan
# param scan_id : string id of the scan
# returns : array containing id of issues from the scan
def find_issues(scan_id):
    return scans.find({"id": scan_id}).distinct("sessions.issues")


# Delete issues only existing in scan (no other dependencies)
# param scan_id : string id of the scan
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
