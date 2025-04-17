import argparse, getpass, logging, requests, sys, warnings
from tabulate import tabulate

warnings.filterwarnings("ignore")
parser = argparse.ArgumentParser(description="Python script using Redfish API to get the Health Information of the Server")
parser.add_argument('-ips', help='Pass in iDRAC IP addresses (comma-separated)', required=True)
parser.add_argument('-u', help='Pass in iDRAC username', required=True)
parser.add_argument('-p', help='Pass in iDRAC password. If not passed in, script will prompt to enter password which will not be echoed to the screen', required=False)
parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in "true". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--license', help='Get all health information of the server', action="store_true", required=False)
parser.add_argument('--all', help='Get all information of the server', action="store_true", required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- python3 license.py -ips 10.2.57.101,10.2.57.102 -u root -p calvin --license, this will get the license information of the Servers.""")
    sys.exit(0)

def make_request(url, ip):
    headers = {'X-Auth-Token': args["x"]} if args["x"] else None
    auth = None if args["x"] else (idrac_username, idrac_password)

    response = requests.get(url, verify=verify_cert, headers=headers, auth=auth)
    return response

def check_supported_idrac_version(ip):
    response = make_request(f'https://{ip}/redfish/v1', ip)
    data = response.json()
    if response.status_code == 401:
        logging.warning(f"\n- WARNING, status code 401 detected for {ip}, check iDRAC username/password credentials")
        sys.exit(0)
    elif response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to validate iDRAC creds for {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

def get_license(idrac_ip, verify_cert, idrac_username=None, idrac_password=None, x_auth_token=None):
    try:
        headers = {'X-Auth-Token': x_auth_token} if x_auth_token else None
        auth = (idrac_username, idrac_password) if idrac_username and idrac_password else None

        # Fetch the list of licenses
        response = requests.get(f'https://{idrac_ip}/redfish/v1/LicenseService/Licenses/FD00000034924531', verify=verify_cert, headers=headers, auth=auth)
        response.raise_for_status()  # Check if the request was successful

        licenses = response.json().get('Members', [])

        license_data = []

        for license_member in licenses:
            license_url = f'https://{idrac_ip}{license_member["@odata.id"]}'
            license_response = requests.get(license_url, verify=verify_cert, headers=headers, auth=auth)
            license_response.raise_for_status()
            license_info = license_response.json()

            # Extract required fields
            description = license_info.get('Description', 'N/A')
            status = license_info.get('Status', {})
            health = status.get('Health', 'N/A')
            state = status.get('State', 'N/A')

            # Filter for specific license description
            if description == "iDRAC9 15g Enterprise License":
                license_data.append([description, health, state])

        return license_data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching licenses: {e}")
        return []


def information(idrac_ip):
    response = make_request(f'https://{idrac_ip}/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces/NIC.1', idrac_ip)
    data = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {idrac_ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)       

    info = data['IPv4Addresses'][0]['Address']
    return info

if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()

    if args["ips"] and (args["u"] or args["x"]):
        idrac_ips = args["ips"].split(',')
        idrac_username = args["u"]

        if args["p"]:
            idrac_password = args["p"]
        elif not args["p"] and not args["x"] and args["u"]:
            idrac_password = getpass.getpass(f"\n- Argument -p not detected, pass in iDRAC user {args['u']} password: ")

        verify_cert = args["ssl"].lower() == "true" if args["ssl"] else False

        table = [["IP", "Description", "Health", "State"]]
        for ip in idrac_ips:
            check_supported_idrac_version(ip)
            if args["license"] or args["all"]:
                ip_address = information(ip)
                licenses = get_license(ip, verify_cert, idrac_username, idrac_password, args["x"])
                for license_info in licenses:
                    table.append([ip_address] + license_info)
            
        print()
        print("=================== LICENSE INFORMATION OF THE SERVERS ===================")
        print(tabulate(table, headers="firstrow", tablefmt="pretty"))
        print()

    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)