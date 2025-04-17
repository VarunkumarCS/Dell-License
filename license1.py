import argparse,getpass,logging,requests,sys,warnings
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
    print("""\n- python3 license1.py -ips 10.2.57.101 -u root -p calvin --all, 
          this will get the information of the Servers.""")
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

def information_of_server(ip):
    response = make_request(f'https://{ip}/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces/NIC.1', ip)
    data = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/LicenseService/Licenses/FD00000034924245', ip)
    data1 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/LicenseService/Licenses/FD00000034924249 ', ip)
    data2 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    return [data['IPv4Addresses'][0]['Address'],data1['Id'],data1['Status']['Health'],data1['Status']['State'],data2['Id'],data2['Status']['Health'],data2['Status']['State']]

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

        table = [["IP Address","License ID1","Health","State","License ID2","Health","State"]]

        for ip in idrac_ips:
            check_supported_idrac_version(ip)
            if args["license"]:
                table.append(information_of_server(ip))
            if args["all"]:
                table.append(information_of_server(ip))

        print()
        print("=================== LICENSE INFORMATION OF THE SERVERS ===================")
        print(tabulate(table, headers="firstrow", tablefmt="pretty"))
        print()

    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)