import requests
import oci
import sys
import argparse
import os

configfile = "~/.oci/config"  # Linux
configProfile = "DEFAULT"

def create_signer(config_profile, is_instance_principals, is_delegation_token):

    # if instance principals authentications
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer

        except Exception:
            print("Error obtaining instance principals certificate, aborting")
            sys.exit(-1)

    # -----------------------------
    # Delegation Token
    # -----------------------------
    elif is_delegation_token:

        try:
            # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
            env_config_file = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            # check if file exist
            if env_config_file is None or env_config_section is None:
                print("*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                print("")
                sys.exit(-1)

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)

                return config, signer

        except KeyError:
            print("* Key Error obtaining delegation_token_file")
            sys.exit(-1)

        except Exception:
            raise

    # -----------------------------
    # config file authentication
    # -----------------------------
    else:
        try:
            config = oci.config.from_file(
                oci.config.DEFAULT_LOCATION,
                (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
            )
            signer = oci.signer.Signer(
                tenancy=config["tenancy"],
                user=config["user"],
                fingerprint=config["fingerprint"],
                private_key_file_location=config.get("key_file"),
                pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
                private_key_content=config.get("key_content")
            )
        except:
            print("Error obtaining authentication, did you configure config file? aborting")
            sys.exit(-1)

        return config, signer


def input_command_line(help=False):
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80, width=130))
    parser.add_argument('-cp', default="", dest='config_profile', help='Config Profile inside the config file')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')
    parser.add_argument('-log', default="log.txt", dest='log_file', help='output log file')
    parser.add_argument('-force', action='store_true', default=False, dest='force', help='force delete without confirmation')
    parser.add_argument('-debug', action='store_true', default=False, dest='debug', help='Enable debug')
    parser.add_argument("-rg", default="", dest='region', help="Region")
    parser.add_argument("-c", default="", dest='compartment', help="top level compartment id to delete")
    cmd = parser.parse_args()
    if help:
        parser.print_help()

    return cmd

def ListDesktopPools(region, compartmentID, signer):
    url = "https://api.desktops.{}.oci.oraclecloud.com/20220618/desktopPools?compartmentId={}".format(region, compartmentID)
    response = requests.get(url, auth=signer)
    data = response.json()
    return data["items"]

def ListDesktops(region, compartmentID, DesktopPoolID, signer):
    url = "https://api.desktops.{}.oci.oraclecloud.com/20220618/desktopPools/{}/desktops?compartmentId={}".format(region, DesktopPoolID, compartmentID)
    response = requests.get(url, auth=signer)
    data = response.json()
    return data["items"]


cmd = input_command_line()
configProfile = cmd.config_profile if cmd.config_profile else configProfile
config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)
if cmd.region:
    config["region"] = cmd.region

if cmd.compartment:
    desktoppools = ListDesktopPools(config["region"], cmd.compartment, signer)
    for p in desktoppools:
        print ("Desktop pool: {}".format(p["displayName"]))
        desktops = ListDesktops(config["region"], cmd.compartment, p["id"], signer)
        for d in desktops:
            desktopID = d["instanceId"]
            compute = oci.core.ComputeClient(config, signer=signer)
            network = oci.core.VirtualNetworkClient(config, signer=signer)
            vnic_attachments = compute.list_vnic_attachments(compartment_id=cmd.compartment, instance_id=desktopID).data
            ipinfo = ""
            for a in vnic_attachments:
                vnic = network.get_vnic(vnic_id=a.vnic_id).data
                ipinfo = ipinfo + vnic.private_ip + " "
            print (" - {} - {} - {} ".format(d["lifecycleState"], ipinfo, d["owner"]))

else:
    print ("Please specify compartment ID")
