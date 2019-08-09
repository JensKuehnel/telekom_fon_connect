#!/usr/bin/python
# Imports

# To parse arguments
import argparse
# Import logging module
import logging

# Import ConfigParser Module
try:
    # Python 2
    import ConfigParser
except ImportError:
    # Python 3
    import configparser

# Import os to read config file path from env var
import os
# For exit (codes) and for correct http debug Log in debug logging
import sys

# For sleep in while loop
import time

# To convert the imported whitelist dict out of config to an python dict
# (is a string when read via config)
import ast

# To communicate with telekom rest api
import json

# Import BeautifulSoup for parsing html
from bs4 import BeautifulSoup

# For http(s) reguests in python
import requests

# Import of urllib needed for url decode
try:
    # Python 3
    from urllib.parse import unquote
except ImportError:
    # Python 2
    from urllib import unquote


def initialize_logger(level, log_file, args):
    # Start logger
    logger = logging.getLogger()
    # Get int of defined level
    loglvl = getattr(logging, level)
    # Set Log to int level
    logger.setLevel(loglvl)
    # Define log format
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    # If Debug level include httplib/http.client
    # to debug requests in detail and log to File
    if level == 'DEBUG':
        # Used by request module, needed to set debug
        try:
            # Python 3
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client

        # If log level debug, set lib for requests also to debug (see headers)
        http_client.HTTPConnection.debuglevel = 1

        # Enable Logs form request (which uses urllib3)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(level)
        requests_log.propagate = True

        # create file handler
        handler_file = logging.FileHandler(log_file, "w")
        handler_file.setFormatter(formatter)
        logger.addHandler(handler_file)

    # create console handler
    handler_console = logging.StreamHandler()
    handler_console.setFormatter(formatter)
    logger.addHandler(handler_console)
    # If log level debug and verbose mode not wanted
    if level == "DEBUG" and args.verbose is False:
        # Set level to info for console handler - file takes debug
        handler_console.setLevel(logging.INFO)


def reset_http_debug_out(http_log):
    # Remember to reset sys.stdout!
    sys.stdout = sys.__stdout__
    debug_info = ''.join(http_log.content).replace('\\r', '').decode('string_escape').replace('\'', '')

    # Remove empty lines and print in Debug Channel
    logging.debug("\n".join([ll.rstrip() for ll in debug_info.splitlines() if ll.strip()]))


# Return Stuff save response code also to check if success !
def do_request(url,
               level,
               do_head_only=False,
               get_session=False,
               want_header=False,
               post=False,
               note_timeout=True):
    # Define some things #
    # Create empty return_stuff dict
    return_stuff = {}
    # Default timeout for each request is 10 seconds
    timeout = 30

    # If Level is debug we get some info we want in debug channel
    if level == 'DEBUG':
        # HTTP stream handler
        class WritableObject:
            def __init__(self):
                self.content = []

            def write(self, string):
                self.content.append(string)

        # A writable object
        http_log = WritableObject()
        # Redirection
        sys.stdout = http_log

    # Do all requests in a try to catch every error
    try:
        # if we want the location header only
        if do_head_only is True:
            # Do head request
            r = requests.head(url=url, timeout=timeout)
            # Save response code of request
            return_stuff['rsp_code'] = r.status_code
            # If we want a specific header
            if want_header is not False:
                # Return this header
                return_stuff['rsp_content'] = r.headers.get(want_header)
            else:
                # If no wanted header @ head request defined,
                # return status code again
                return_stuff['rsp_content'] = r.status_code
        else:
            # Post data defined ...
            if post is not False:
                # ... do post request
                r = requests.post(url=url, data=post, timeout=timeout)
                # Save response code of request
                return_stuff['rsp_code'] = r.status_code
                # Want session header
                if get_session is True:
                    # Return Session header
                    return_stuff['rsp_content'] = r.cookies['JSESSIONID']
                else:
                    # Save response of request (encode utf-8 for shure ;)
                    return_stuff['rsp_content'] = r.text
            else:
                # Do normal get request
                r = requests.get(url=url, timeout=timeout)
                # Save response code of request
                return_stuff['rsp_code'] = r.status_code
                # Save response of request (encode utf-8 for shure ;)
                return_stuff['rsp_content'] = r.text

        # If Level is debug we get some info we want in debug Channel
        if level == 'DEBUG':
            # Call final part of HTTP Debug output
            reset_http_debug_out(http_log)

        # Return filled dict with needed stuff
        return return_stuff
    # I got sometimes timeoutes @ final login
    except requests.exceptions.Timeout as e:
        # If we got it @ Login ignore, i was always nevertheless online
        if note_timeout is False:
            # Print debug message about the timeout
            logging.debug(str(e) + " occured when requesting page, ignoring")
            # Return 200 - because online and ignore error
            return_stuff['rsp_code'] = 200
            # Return 200 - because online and ignore error
            return_stuff['rsp_content'] = 200
            # Return defined stuff
            return return_stuff
        else:
            logging.error('Timeout after ' +
                          str(timeout) +
                          ' seconds, request aborted, will exit from here now',
                          '.  Please try again later')
            return 'error'
    # Catch all network errors
    except requests.exceptions.RequestException as e:
        logging.error('An error occurred when doing the request, ' +
                      'will exit now. Please try again later')
        logging.debug(e)
        return 'error'


def do_login(username,
             password,
             test_url,
             rlp_request_whitelist,
             telekom_api_endpoint,
             session_api_url,
             login_api_url,
             loglvl,
             login_url=None):
    # START Do a request to get the Login URL and save session
    if login_url is None:
        logging.info('Doing request to ' +
                     test_url +
                     ' to get hotspot status page')
        login_page = do_request(url=test_url,
                                do_head_only=True,
                                want_header='location',
                                level=loglvl)

        # If request failed and return is only offline
        if login_page == 'error':
            # return direct offline, errors are already thrown
            return 'offline'

        # Save url of login page
        login_url = login_page['rsp_content']

        # Redirect is done (correctly) via 302, if not something went wrong
        if login_page['rsp_content'] is None or login_page['rsp_code'] != 302:
            logging.error('Error when getting hotspot status page, ' +
                          'something went wrong. Will exit from here now')
            logging.debug('Location-Header of request to ' +
                          test_url +
                          ' was ' +
                          login_url +
                          'HTTP-Status was ' +
                          str(login_page['rsp_code']))
            return 'offline'
    else:
        logging.debug('Login Url is already defined, use it')

    logging.debug('Hotspot login and status page is ' + login_url)
    # END Do a request to get the Login URL

    # START Do reguest to login page to get source code
    # and get post informations to post
    logging.info('Doing request to hotspot login page to fetch source code')
    logging.debug('Doing request to ' +
                  login_url +
                  ' to fetch source code to create post data')
    # Get source of login page to extract some infos to create a session
    fon_source = do_request(url=login_url, level=loglvl)

    # If request failed and return is only offline
    if fon_source == 'error':
        # Return direct offline, errors are already thrown
        return 'offline'

    logging.debug('Start parsing html to get post data')
    # Try parsing ...
    try:
        # Parse HTML of login page request
        parsed_fon_html = BeautifulSoup(fon_source['rsp_content'], 'lxml')
        # Save logoff url
        #  logoff_page = 'logoffpage'
        # Find div with post infos
        form = parsed_fon_html.body.find('div', attrs={'id': 'page-container'})
        # Get Logout url: in div page-container -> angular div with
        # name/class/id (whatever called in angular) data-ng-init ->
        # split at ' and save url in the 's
        logout_url = form.find('div').get('data-ng-init').split("'")[1]
        # Parse out all inputs
        # Get inputs of div
        inputs = form.find_all('input')
        # Fill formdata dict
        divdata = dict((field.get('name'),
                        field.get('value')) for field in inputs)
        logging.debug('Post data found')
    # ... catch exception if html code could not be parsed as wanted
    except Exception as e:
        logging.error('Error when parsing html code to get post data. ' +
                      'Either a (temporary) error or script is not working ' +
                      'anymore. Will try again')
        logging.debug('Got error ' +
                      str(e) +
                      ' when parsing html to get form data')
        return 'offline'

    # Filter dict, keep only elements in post_data_whitelist
    # Define new dict with post data
    rlp_request = {}
    # For each whitelist key
    for key in rlp_request_whitelist:
        # Fill new dict key with key value of old
        rlp_request[key] = divdata[key]

    # We got the urls dirct of of source code, there it is encoded
    # but for json post later we need it plain/decoded
    # Decode Url for correct json post
    divdata['WISPURL'] = unquote(divdata['WISPURL'])
    # Decode Url for correct json post
    divdata['WISPURLHOME'] = unquote(divdata['WISPURLHOME'])

    # Create json to post to api
    postdata = json.dumps({'location': {},
                           'partnerRegRequest': {},
                           'rlpRequest': divdata,
                           'session': {},
                           'user': {}})

    logging.debug('Postdata created')
    # END Do reguest to Login page to get source code and
    # get post informations to post

    # START Starting login session at Telekom rest api
    # Build url to get session
    url = telekom_api_endpoint + session_api_url
    # Do post request to get session
    login_check = do_request(url,
                             get_session=True,
                             post=postdata,
                             level=loglvl)

    # If request failed and return is only offline
    if login_check == 'error':
        # return direct offline, errors are already thrown
        return 'offline'

    # Check if session generated. 200 all okay.
    # HTTP-400 when wrong informations posted. 302 if post empty
    if login_check['rsp_code'] != 200:
        logging.error('Failed to begin login session @ telekom api. ' +
                      'Please try again later')
        # Creation of session failed, we must try in next run - offline
        return 'offline'

    # Save session
    session = login_check['rsp_content']

    logging.info('Session @ Telekom api successfull created')
    # END Starting login session at Telekom rest api

    # START Try to login with credentials @ Telekom fon hotspot
    # Build url with session for login check
    url = telekom_api_endpoint + login_api_url + ';jsessionid=' + session
    # Create json with login credentials
    logindata = json.dumps({"username": username, "password": password})
    # Do login
    login_status = do_request(url, post=logindata, level=loglvl)

    # If request failed and return is only offline
    if login_status == 'error':
        # return direct offline, errors are already thrown
        return 'offline'

    # Decode json return of api
    dec_json = json.loads(login_status['rsp_content'])

    # Catch errors
    if 'errors' in dec_json and 'redirect' not in dec_json:
        # Print received error message
        logging.error('Error when login with ' +
                      username +
                      ' @ Telekom fon hotspot, got message ' +
                      dec_json['errors'][0]['description'])
        logging.error('Maybe your given credentials are not valid, ' +
                      'please check')
        return 'offline'

    logging.info('Authentification @ Telekom api was successfull, ' +
                 'got login url')
    # Login url @ local router is given from telekom api after auth.
    # Save to do login
    login_url = dec_json['redirect']['url']
    # END Try to login with credentials @ Telekom fon hotspot

    # START Login
    # Do the final request to be online, ignore timeouts here
    online_status = do_request(url=login_url, note_timeout=False, level=loglvl)

    # If request failed and return is only offline
    if online_status == 'error':
        # return direct offline, errors are already thrown
        return 'offline'

    # 200 if timeout or login okay
    if online_status['rsp_code'] == 200:
        logging.info('Login successfull, you are online :)')
        logging.info('To logout, please open ' + logout_url)
        return 'online'
    else:
        # Something went wrong ...
        logging.info('Login failed, you are (maybe) not online')
        return 'offline'
    # END LOGIN


def do_statusfile(statusfile, action='remove', test_url=None, loglvl=None):
    if action == 'create' and test_url is not None and loglvl is not None:
        # Do head to https test_url to fetch ip header
        your_ip = do_request(url=test_url.replace("http", "https"),
                             do_head_only=True,
                             want_header='X-your-ip',
                             level=loglvl)
        # If request for ip was success, return is not only offline
        if your_ip != 'error':
            # Open status file to write
            f = open(statusfile, "w")
            # Write current ip saved in content to file
            f.write(your_ip['rsp_content'])
            logging.debug('Written your current ip ' +
                          your_ip['rsp_content'] +
                          ' successfull to file ' +
                          statusfile)
        else:
            logging.debug('Error when terminating your ip for statusfile ' +
                          statusfile +
                          ', will not write statusfile')
    else:
        # If statusfile exists
        if os.path.isfile(statusfile):
            # Remove, we are offline
            os.remove(statusfile)
            logging.debug('Statusfile successfull deleted')


def main():
    # START argument parser
    parser = argparse.ArgumentParser(
        # Define help description
        description='This script check take care of your online status on a ' +
        'Telekom_FON Hotspot and will login you if necessary')
    parser.add_argument('-c', '--config',
                        help='Pass path of config file to script. ' +
                        'If nothing given script will try to read env ' +
                        'var telekom_fon_connect_cfg')
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run this script as a daemon checking any n ' +
                        'time for online status and connect if needed. If ' +
                        'not option not given the script will only connect ' +
                        'and afterwards die')
    parser.add_argument('-s', '--statusfile', action='store_true',
                        help='Safe your external ip in a statusfile defined ' +
                        'in configfile')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='If log_level is debug, script will print this ' +
                        'also to stdout instead of save in file only')
    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s 1.0')
    args = parser.parse_args()
    # END argument parser

    # START lookup for arg or env var to load config
    # Check if config argument is defined
    if args.config is not None:
        cfg_file = args.config
    else:
        # If the env var with config path is not defined
        if 'telekom_fon_connect_cfg' not in os.environ:
            logging.error('Env var telekom_fon_connect_cfg not found - ' +
                          'please set or pass path as argument')
            sys.exit(1)
        # Safe config path out of env var
        cfg_file = os.environ['telekom_fon_connect_cfg']
    # Try to include configparser
    try:
        # Python2
        Config = ConfigParser.ConfigParser()
    except NameError:
        # Python3
        Config = configparser.ConfigParser()

    # Try to read config
    try:
        # Open configfile and read
        Config.read(cfg_file)
    # Catch exception if wrong file given
    except Exception as e:
        logging.error('Error when loading config file, ' +
                      'please check path and syntax')
        logging.debug('Got error ' + str(e) + ' when loading config file')
        sys.exit(1)
    # END lookup for arg or env var to load config

    # START Save infos out of config file in vars
    loglvl = Config.get('telekom_fon_connect', 'log_level')
    log_file = Config.get('telekom_fon_connect', 'log_file')
    username = Config.get('telekom_fon_connect', 'fon_username')
    password = Config.get('telekom_fon_connect', 'fon_password')
    test_url = Config.get('telekom_fon_connect', 'test_url')
    # Convert list string to list via a safe eval python way
    rlp_request_whitelist = ast.literal_eval(Config.get('telekom_fon_connect',
                                                        'rlp_request_whitelist'
                                                        ))
    telekom_api_endpoint = Config.get('telekom_fon_connect',
                                      'telekom_api_endpoint')
    session_api_url = Config.get('telekom_fon_connect', 'session_api_url')
    login_api_url = Config.get('telekom_fon_connect', 'login_api_url')
    sleeptime = Config.get('telekom_fon_connect', 'sleeptime')
    # If status file wanted
    if args.statusfile is True:
        # Save status file var for config
        statusfile = Config.get('telekom_fon_connect', 'status_file')
    # END Save infos out of config file in vars

    # Start logging
    # Pass log level and log file path as arguments to logger setup
    initialize_logger(loglvl, log_file, args)

    # Print some infos @ startup
    logging.debug('Working with configfile: ' + cfg_file)
    logging.info('log_level is : ' + loglvl)

    # START While Loop for online check
    # while forever
    run = True

    # While run = True, run forever
    while run is True:
        # Do head reguest to check online status
        online_request = do_request(url=test_url,
                                    do_head_only=True,
                                    want_header='location',
                                    level=loglvl)

        # If request failed and return is only offline
        if online_request == 'error':
            # Return direct offline, errors are already thrown
            status = 'offline'
            # If status file wanted
            if args.statusfile is True:
                # Remove statusfile, we are offline
                do_statusfile(statusfile=statusfile,
                              action='remove')
        # We are online because we got 301 redirect to https
        # (with correct location)
        elif online_request['rsp_code'] == 301 and online_request['rsp_content'] == test_url.replace("http", "https") + '/':
            logging.debug('You are online')
            # Set success to online
            status = 'online'
            # If statusfile wanted
            if args.statusfile is True:
                # Create statusfile
                do_statusfile(statusfile=statusfile,
                              action='create',
                              test_url=test_url,
                              loglvl=loglvl)
        # We are not online, try login
        else:
            # Save location from head online test to do login
            login_url = online_request['rsp_content']
            logging.info('You are not online, try to login now')
            # If status file wanted
            if args.statusfile is True:
                # Remove statusfile, we are offline
                do_statusfile(statusfile=statusfile, action='remove')
            status = do_login(username,
                              password,
                              test_url,
                              rlp_request_whitelist,
                              telekom_api_endpoint,
                              session_api_url,
                              login_api_url,
                              loglvl,
                              login_url)
            # If request was success, return is not only offline
            # and statusfile wanted
            if status == 'online' and args.statusfile is True:
                # Create statusfile
                do_statusfile(statusfile=statusfile,
                              action='create',
                              test_url=test_url,
                              loglvl=loglvl)

        # No deamon mode wanted, exit the while loop after first run
        if args.daemon is False and status == 'online':
            logging.info('Your are now ' +
                         status +
                         ' and because no deamon mode selected i will ' +
                         'exit now bye')
            run = False
        # If daemon mode, sleep
        if args.daemon is True:
            logging.debug('You are ' +
                          status +
                          ' sleeping now for ' +
                          str(sleeptime) +
                          ' before checking status again')
            # Sleep for n seconds before check status again
            time.sleep(float(sleeptime))
    # END While Loop for online check


if __name__ == '__main__':
    # If no arg, pass none
    sys.exit(main())
