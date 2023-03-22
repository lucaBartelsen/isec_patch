# SVA System Vertrieb Alexander GmbH
# Version 1.1
# Autor: Luca Bartelsen

import requests
import configparser
from requests_ntlm import HttpNtlmAuth
import json

# global variables
server = None
first_ring_id = None
second_ring_id = None
auth = None
family_name = None
microsoft_family_name = None
product_versions_server = None
patch_type = None


def load_config():
    # define variables as global
    global server, first_ring_id, second_ring_id, auth, family_name, microsoft_family_name, product_versions_server, patch_type
    # Create a ConfigParser object
    config = configparser.ConfigParser()
    # Read the config file
    config.read('config.ini')

    # Get the server variable from the [Server] section
    server = config.get('Server', 'server')
    # Get the first_ring_id variable from the [Server] section
    first_ring_id = config.getint('Server', 'first_ring_id')
    # Get the second_ring_id variable from the [Server] section
    second_ring_id = config.getint('Server', 'second_ring_id')

    # Get the NTLM authentication parameters from the [NTLM Auth] section
    username = config.get('NTLM Auth', 'username')
    password = config.get('NTLM Auth', 'password')
    auth = HttpNtlmAuth(username, password)

    # Get the filter variables from the [Filter] section
    family_name = eval(config.get('Filter', 'family_name'))
    microsoft_family_name = eval(config.get('Filter', 'microsoft_family_name'))
    product_versions_server = eval(
        config.get('Filter', 'product_versions_server'))
    patch_type = eval(config.get('Filter', 'patch_type'))

# moving the patches from the first ring on to the second ring


def next_ring(patch_list):
    # API Post Request Second Ring
    url = f"https://{server}/st/console/api/v1.0/patch/groups/{second_ring_id}/patches"

    payload = json.dumps(patch_list)
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request(
        "POST", url, auth=auth, headers=headers, data=payload, verify=False)

# removes the patches given in the patch_list parameter, the patch_list ist a simple list with IDs


def clear_first_ring(patch_list):
    # API request to delete all patches
    url = f"https://{server}/st/console/api/v1.0/patch/groups/{first_ring_id}/patches"

    payload = json.dumps(patch_list)
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request(
        "DELETE", url, auth=auth, headers=headers, data=payload, verify=False)

# removes all patches from the second ring


def clear_second_ring():

    url = f"https://{server}/st/console/api/v1.0/patch/groups/{second_ring_id}/patches?count=1000"

    payload = {}
    headers = {}

    response = requests.get(url, auth=auth, verify=False)

    # Create List with ID's that are currently in the patch group
    py_obj = json.loads(response.text)
    ID_Pilot = []
    for start in py_obj["value"]:
        ID_Pilot.append(start["id"])

    # API request to delete all patches
    url = f"https://{server}/st/console/api/v1.0/patch/groups/{second_ring_id}/patches"

    payload = json.dumps(ID_Pilot)
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request(
        "DELETE", url, auth=auth, headers=headers, data=payload, verify=False)

# Returns a list with objects where the configured microsoft filter applies


def filter_productversions(text, productversions, product=['Windows']):
    ret = set()
    filtered = [item for item in text['families'] if item['name'] in product]
    for item in filtered:
        for itempv in item['productVersions']:
            if itempv['name'] in productversions:
                ret = ret.union({product['uid']
                                for product in itempv['products']})
    return ret

# Finds the correct patches using the filters defined


def find_patch(max_id):
    # API Get Request Patches
    # If the argument max_id is empty search the last 1000 patches with the filters, otherwise start with the latest patch used in the first ring
    if max_id == '':
        url = f"https://{server}/st/console/api/v1.0/patch/patchmetadata?count=1000&orderBy=bulletinReleaseDate&sortOrder=Desc"
    if max_id != '':
        url = f"https://{server}/st/console/api/v1.0/patch/patchmetadata?count=1000&orderBy=bulletinReleaseDate&sortOrder=Asc&start={max_id}"

    response = requests.get(url, auth=auth, verify=False)

    # get the uids from the microsoft filter list, the uids are used to match with the patchmetadata later on
    uids = set()
    for product_set in get_version_uuids_microsoft(product_versions_server):
        uids = uids.union(product_set)

    basedict = json.loads(response.text)

    ret = []

    # Using the product filters, patch type filter and the patch uids onto the patch metadata and creating a list with bulletin ids, matching the filter
    for item in basedict['value']:
        if item['patchType'] not in patch_type:
            continue
        if item['familyName'] in family_name:
            ret.append(item['bulletinId'])
        if len(set(item['affectedProducts']).intersection(uids)) > 0:
            ret.append(item['bulletinId'])

    return ret

# Matching the Bulletin Ids with the Patch IDs


def get_ids_of_patches(max_id=''):

    bulletin_ids = find_patch(max_id)

    # Creating API Url with all Bulleting Ids to get the Patch ID
    base_url = f"https://{server}/st/console/api/v1.0/patches?bulletinIds="
    base_url += ",".join([f"{bulletinId}" for bulletinId in bulletin_ids])

    response = requests.get(base_url, auth=auth, verify=False)
    text = json.loads(response.text)
    ret = set()
    for l in [vuln['vulnerabilities'] for vuln in text['value']]:
        for x in l:
            ret.add(x['id'])
    return ret

# Looks up for the uids of the microsoft products


def get_version_uuids_microsoft(product_versions):
    # API Get Product Level Versions
    url = f"https://{server}/st/console/api/v1.0/metadata/vendors?start=1&count=1"

    response = requests.get(url, auth=auth, verify=False)

    values = json.loads(response.text)['value']
    # iterating over the list in value, normaly its just one value inside the list
    uids = [filter_productversions(value, product_versions, microsoft_family_name)
            for value in values]
    return uids

# Writes Patches to the First Ring


def start_ring(id_pilot):
    url = f"https://{server}/st/console/api/v1.0/patch/groups/{first_ring_id}/patches"

    payload = json.dumps(id_pilot)
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request(
        "POST", url, auth=auth, headers=headers, data=payload, verify=False)

# creates a set of patch ids from the first ring


def first_ring_set():
    # API Get Request First Ring
    url = f"https://{server}/st/console/api/v1.0/patch/groups/{first_ring_id}/patches?count=1000"

    response = requests.get(url, auth=auth, verify=False)

    # Create List with ID's
    py_obj = json.loads(response.text)
    ID_Pilot = set()
    for start in py_obj["value"]:
        ID_Pilot.add(start["id"])

    return ID_Pilot

# matching patch id with patch uid


def get_patchuid(patch_id):
    url = f"https://{server}/st/console/api/v1.0/patches?start={patch_id}&count=1"

    response = requests.get(url, auth=auth, verify=False)

    # looking for the patch uid
    py_obj = json.loads(response.text)
    for start in py_obj["value"]:
        ID_Pilot = start["vulnerabilities"][0]["patchIds"]
    return ID_Pilot[0]


if __name__ == '__main__':
    # loads the config from config.ini
    load_config()
    # gets the patches of the first ring
    first_id = first_ring_set()
    # removes the patches of the second ring
    clear_second_ring()
    # moves the patches from the first ring to the second ring
    next_ring(list(first_id))
    # remove the patches of the first ring
    clear_first_ring(list(first_id))
    # adds new patches to the first ring according to the filter, if the first ring is empty catch the error and ad some patches
    try:
        # get the last patch id of the previous patches of the first ring, and match this id with an patch uid
        patch_uid = get_patchuid(max(list(first_id)))
        # get the new patches with ids and substract it with the previous ids of the first ring
        pilot_id = list(get_ids_of_patches(patch_uid) - first_id)
        # adds the patches to the first ring
        start_ring(pilot_id)
    except ValueError:
        # get the new patches with ids and substract it with the previous ids of the first ring
        pilot_id = list(get_ids_of_patches() - first_id)
        # adds the patches to the first ring
        start_ring(pilot_id)