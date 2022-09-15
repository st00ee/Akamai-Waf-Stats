#Akamai WAF Configuration Report

##A python script that returns status of the configuration in your policies

This python script uses Akamai appsec api and returns back the critical
controls and their status (mitigation mode or not). At the moment it only works
with KSD and AAP. The table returned will provide the following:

* Type of Ruleset Used
* Attack Groups in Deny Mode Percentage
* Rate Controls in Deny and Alert Mode
* Client Rep Profiles in Deny Mode
* Slow Post Status

API used: https://techdocs.akamai.com/application-security/reference/api

#Installation Instructions

## Get API Access!

Please follow the guide provided by Akamai

https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials

## Install the required python3 libraries

This script runs on Python3, and the libraries needed to be installed are:

* requests
* edgegrid-python
* tabulate

hint: use the 'pip install' command for this
