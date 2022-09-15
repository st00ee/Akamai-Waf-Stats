"""
Usage:
- Runs on Python3
- requests library needs to be installed
- edgegrid-python library needs to be installed
- tabulate library needs to be installed
--- use pip for libraries installation
- Akamai api credentials need to be stored at ~/.edgerc
- appsec view access needed for this script
"""


import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from urllib.parse import urljoin
import os
import json
from tabulate import tabulate
import time


def akamai_conn(account, path):
    """
    function to connect with Akamai APIs
    https://techdocs.akamai.com/application-security/reference/api
    """
    global query
    edgerc = EdgeRc('~/.edgerc')
    section = 'default'
    baseurl = 'https://%s' % edgerc.get(section, 'host')
    s = requests.Session()
    s.auth = EdgeGridAuth.from_edgerc(edgerc, section)
    account = "?accountSwitchKey={}".format(account)
    path = path + account
    headers = {"Accept": "application/json"}
    query = s.get(urljoin(baseurl, path), headers=headers)
    return query


def export_files(account):
    """
    Export a list of security files and the lastest version in prod
    """
    global sec_files
    path = "/appsec/v1/configs/"
    akamai_conn(account, path)
    sec_files = json.loads(query.text)


def export_policies(account, file, prod_version):
    """
    Export a list of policies from a file
    """
    global sec_policies
    path = "/appsec/v1/configs/{}/versions/{}/security-policies".format(file,
            prod_version)
    akamai_conn(account, path)
    sec_policies = json.loads(query.text)


def f_ruleset_mode(account, file, prod_version, sec_policies):
    """
    extracts which app controls ruleset is the policy using
    """
    global rule_modes
    num_policies = len(sec_policies['policies'])
    i = 0
    base = "/appsec/v1/configs"
    while i < num_policies:
        policy_id = sec_policies['policies'][i]['policyId']
        path = base + "/{}/versions/{}/security-policies/{}/mode".format(
            file, prod_version, policy_id)
        akamai_conn(account, path)
        rule_mode = json.loads(query.text)
        rule_modes.append(rule_mode['mode'])
        i = i + 1


def f_attack_group(account, file, prod_version, sec_policies):
    """
    extracts percentage of attack groups in deny mode
    """
    global attack_groups
    num_policies = len(sec_policies['policies'])
    i = 0
    ba = "/appsec/v1/configs"
    while i < num_policies:
        policy_id = sec_policies['policies'][i]['policyId']
        path = ba + "/{}/versions/{}/security-policies/{}/attack-groups".format(
            file, prod_version, policy_id)
        akamai_conn(account, path)
        group_state = json.loads(query.text)
        j = 0
        num_groups = len(group_state['attackGroupActions'])
        list_actions = []
        while j < num_groups:
            action = group_state['attackGroupActions'][j]['action']
            list_actions.append(action)
            j = j + 1
        alerts = list_actions.count('alert')
        denies = list_actions.count('deny')
        #attacks groups not used or skipped, it will default to 0%
        try:
            perc_deny = "{:.0%}".format(denies / (alerts + denies))
            attack_groups.append(perc_deny)
        except ZeroDivisionError:
            perc_deny = "0%"
            attack_groups.append(perc_deny)
        i = i + 1


def f_rate_control(account, file, prod_version, sec_policies):
    """
    extracts number of rate controls in alert and deny per policyId
    both ipv4 and ipv6 need to be in deny to be counted as deny mode
    """
    global rate_controls
    num_policies = len(sec_policies['policies'])
    i = 0
    ba = "/appsec/v1/configs"
    while i < num_policies:
        policy_id = sec_policies['policies'][i]['policyId']
        path = ba + "/{}/versions/{}/security-policies/{}/rate-policies".format(
            file, prod_version, policy_id)
        akamai_conn(account, path)
        rate_list = json.loads(query.text)
        alerts = 0
        denies = 0
        try:
            num_rates = len(rate_list['ratePolicyActions'])
            j = 0
            # ipv4 and ipv6 must be both in deny, to be counted in deny Mode
            # the rest but none and none will be counted as alerts
            ratePolicyA = 'ratePolicyActions'
            while j < num_rates:
                if rate_list[ratePolicyA][j]['ipv4Action'] == 'alert':
                    alerts = alerts + 1
                elif rate_list[ratePolicyA][j]['ipv6Action'] == 'alert':
                    alerts = alerts + 1
                elif rate_list[ratePolicyA][j]['ipv4Action'] == 'deny':
                    if rate_list[ratePolicyA][j]['ipv6Action'] == 'deny':
                        denies = denies + 1
                    else:
                        alerts = alerts + 1
                else:
                    pass
                j = j + 1
        # this will check if the rate controls are configured at all
        except KeyError:
            pass
        rate_info = [denies, alerts]
        rate_controls.append(rate_info)
        i = i + 1


def f_slow_post(account, file, prod_version, sec_policies):
    """
    check if slow post is in abort mode
    """
    global slow_post
    num_policies = len(sec_policies['policies'])
    i = 0
    ba = "/appsec/v1/configs"
    while i < num_policies:
        policy_id = sec_policies['policies'][i]['policyId']
        path = ba + "/{}/versions/{}/security-policies/{}/slow-post".format(
            file, prod_version, policy_id)
        akamai_conn(account, path)
        slow_post_list = json.loads(query.text)
        try:
            slow_post.append(slow_post_list['action'])
        except KeyError:
            slow_post.append('None')
        i = i + 1


def f_client_rep(account, file, prod_version, sec_policies):
    """
    counts denies in client rep
    """
    global client_rep
    num_policies = len(sec_policies['policies'])
    i = 0
    ba = "/appsec/v1/configs"
    end = "/reputation-profiles"
    while i < num_policies:
        denies = 0
        policy_id = sec_policies['policies'][i]['policyId']
        path = ba + "/{}/versions/{}/security-policies/{}".format(file,
            prod_version, policy_id) + end
        akamai_conn(account, path)
        rep_list = json.loads(query.text)
        j = 0
        try:
            num_reps = len(rep_list['reputationProfiles'])
            while j < num_reps:
                if rep_list['reputationProfiles'][j]['action'] == 'deny':
                    denies = denies + 1
                j = j + 1
        except KeyError:
            pass
        client_rep.append(denies)
        i = i + 1


def main():
    """
    calculates the time of the query
    assign processes to different functions
    returns table with:
        1. File Name
        2. Policy Name
        3. Ruleset Used
        4. Attack Groups in Deny Mode (%)
        5. Rate Controls in Deny Mode
        6. Rate Controls in Alert Mode
        7. Slow Post
        8. Client Rep Profiles in Deny Mode
    """
    account = input("Enter account ID... ")
    start_time = time.time()
    export_files(account)
    num_files = len(sec_files['configurations'])
    global rule_modes
    global attack_groups
    global rate_controls
    global slow_post
    global client_rep
    global policy_list
    policy_list = []
    i = 0
    k = 0
    while i < num_files:
        try:
            rule_modes = []
            attack_groups = []
            rate_controls = []
            slow_post = []
            client_rep = []
            file_id = sec_files['configurations'][i]['id']
            file_name = sec_files['configurations'][i]['name']
            prod_version = sec_files['configurations'][i]['productionVersion']
            export_policies(account, file_id, prod_version)
            num_policies = len(sec_policies['policies'])
            f_ruleset_mode(account, file_id, prod_version, sec_policies)
            f_attack_group(account, file_id, prod_version, sec_policies)
            f_rate_control(account, file_id, prod_version, sec_policies)
            f_slow_post(account, file_id, prod_version, sec_policies)
            f_client_rep(account, file_id, prod_version, sec_policies)
            j = 0
            while j < num_policies:
                table_insert = [k+1, file_name,
                sec_policies['policies'][j]['policyName'],rule_modes[j],
                attack_groups[j], rate_controls[j][0], rate_controls[j][1],
                slow_post[j], client_rep[j]]
                policy_list.append(table_insert)
                j = j + 1
                k = k + 1
            i = i + 1
        except KeyError:
            i = i + 1
    #tabulating final table
    col_names = ["Number", "File Name", "Policy Name", "Mode", "AGs Deny(%)",
        "RCs Deny", "RCs Alert", "Slow Post", "CR Deny"]
    print (tabulate(policy_list, headers=col_names))
    print ()
    print ("AG = Attack Group, RC = Rate Control", "CR = Client Reputation")
    end_time = time.time()
    total_time = round(end_time - start_time, 5)
    print('Query processed in {} seconds.'.format(total_time))


if __name__ == "__main__":
    main()
