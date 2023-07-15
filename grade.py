from __future__ import print_function
from operator import itemgetter
from os import environ
from sys import exit

BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠶⠚⠋⠉⠉⠙⠛⠲⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣶⣾⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠳⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⢿⠙⣿⣻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠹⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⡟⠁⢹⠿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠘⢷⣼⢷⣄⡀⠀⠀⢤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣇⠀⠀⠀⠈⢻⡉⢣⠙⡶⣶⢾⣿⣿⡷⠀⠀⠀⠀⠀⠀⢀⠀⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡀⣸⠆⠀⠀⠙⢆⠳⣆⠹⣿⣿⣿⣥⣄⠀⠀⠀⠀⠀⢾⡀⣸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠋⠉⠀⠀⠀⠀⠘⡄⣀⡉⠻⣟⣿⡏⠙⠃⠀⠀⠀⠀⠀⠉⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⡇⢸⣶⣤⣀⠀⠀⠀⠹⠁⢳⡀⢈⣻⡇⠀⠀⠀⠀⢀⣠⣴⣾⠀⡷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡌⣿⡟⠻⢷⣶⢄⡀⠀⠨⢿⢻⣿⠙⠀⣀⣤⣾⠿⠛⣿⡽⣸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⢫⡇⢻⣿⣄⠀⠈⠙⠿⣷⣤⣼⣆⣠⣴⡿⠛⠉⠀⠀⣴⡿⠁⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢷⡀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠁⣠⣷⣄⠙⢝⠳⠶⠶⠞⢋⡠⠛⠚⠣⣉⠛⠲⠶⠖⣛⠟⢁⣴⠇⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴
⢸⣷⡄⠀⠀⠀⠀⠀⠀⢸⡇⡔⢡⡏⠹⢿⣄⣉⠁⠒⠈⠁⠀⠀⠀⠀⠀⠉⠐⠒⢉⣡⣼⣯⡶⠛⠋⢉⣩⠿⠛⠒⠂⠀⠀⠀⠀⢀⣼⡏
⠀⢿⠙⢦⡀⠀⠀⠀⠀⠘⣿⡁⡿⠀⢠⠞⢷⠈⠱⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠉⢠⠟⠁⠀⡄⣄⣸⣆⠀⠀⠀⠀⠀⠀⠀⣠⠞⣸⠁
⠀⠘⣧⠀⠙⢦⡀⠀⠀⠀⠈⠻⣿⣶⣞⠛⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⡿⠀⢰⣋⣉⠉⣠⡜⠀⠀⠀⠀⢀⣠⠞⠁⢠⠏⠀
⠀⠀⠘⣧⡀⠀⠙⠷⣄⡀⠀⠀⠹⣯⡏⠙⠛⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣷⡶⢾⣇⣨⠽⠋⠀⠀⠀⣀⡴⠋⠁⠀⣰⠏⠀⠀
⠀⠀⠀⠈⠳⣄⠓⢄⠈⠛⢦⣄⠀⠘⢿⣄⡀⢹⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠁⣀⣀⣸⡦⠄⠀⣀⡤⠞⠉⣀⠔⢁⡼⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠳⣦⡁⠢⢄⠈⠙⠶⣤⣈⠙⠻⠶⣿⣦⡀⠀⠀⠀⠀⠀⣠⣾⣥⠶⠛⠉⠁⢀⣠⡴⠚⠉⢀⠔⢊⣠⠞⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⢤⣙⠢⢄⠀⠉⠓⠦⣄⣀⠀⠙⠓⠒⠒⠒⠛⠁⠀⠀⢀⣠⡤⠞⠋⠁⡀⠄⣊⣥⠶⠋⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠲⢬⣁⠂⠤⣀⠉⠛⠶⢤⣀⡀⠀⣀⣤⠶⠚⠉⢁⡠⠔⣂⣥⠶⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣈⡙⠲⢦⣍⣒⣤⣤⠼⠟⠋⢉⣀⠤⢒⣊⡥⠶⠛⣉⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣠⠤⣤⣀⣀⣀⣀⣀⣀⣀⣀⣀⣠⡏⠉⠉⡷⠖⠚⠋⣉⡠⠤⠐⢂⣩⡴⠶⢟⣉⡉⠛⠒⢶⠇⠉⢹⣧⣀⣀⣀⣀⣀⣀⣀⣀⣀⡠⠤⢄
⡇⠀⠀⠀⠀⡏⢠⡇⡇⢰⡀⡄⢀⢷⠀⡆⢹⣂⣈⣩⡤⠶⠞⠋⠉⠉⠙⠓⠶⠤⣬⣉⣐⡺⠀⠂⣸⢱⠀⠀⡃⠈⠀⠃⠈⠀⠀⠀⠀⢸
⠙⠢⠶⠴⠦⠷⠤⠷⠛⠒⠓⠛⠛⢻⣦⣵⡼⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠧⢼⣤⡟⠛⠛⠛⠳⠿⠭⠽⠤⠴⠦⠄⠀⠚
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

    
import argparse
import datetime
import pytz
import json
import requests
import sys
import time
import colorama
from colorama import Fore, Style

# import urlparse in a Python2 / Python3 compatible way
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

import readline  # Required for ANSI sequence handling

API_URL = environ.get('HTTPOBS_API_URL', 'https://http-observatory.security.mozilla.org/api/v1')
SSLLABS_URL = "https://api.ssllabs.com/api/v2/analyze?publish=off&fromCache=on&maxAge=24&host={domain}"

# Color codes
COLOR_GREEN = Fore.GREEN
COLOR_RED = Fore.RED
COLOR_YELLOW = Fore.YELLOW
COLOR_CYAN = Fore.CYAN
COLOR_BLUE = Fore.BLUE


def analyze(host):
    global args

    data = {}

    if args.rescan:
        data['rescan'] = 'true'
    if args.hidden:
        data['hidden'] = 'true'

    try:
        print(Fore.RED + BANNER + Style.RESET_ALL)
        # First, make a POST to the Observatory to start the scan
        scan = requests.post(API_URL + '/analyze?host={host}'.format(host=host), data=data).json()
        # print(json.dumps(scan, indent=4))  # Output the scan JSON

        # Notify the user if they attempted a rescan too soon
        if args.rescan and scan.get('error') == 'rescan-attempt-too-soon':
            print('Rescan attempt is sooner than the allowed cooldown period. Returning cached results instead.\n',
                  file=sys.stderr)

        grade = scan['grade']
        score = scan['score']
        scan_id = scan['scan_id']
        start_time = scan['start_time']
        state = scan['state']

        print(COLOR_CYAN + "Scan ID:", scan_id)
        print("Start Time:", start_time)
        print("State:", state)
        print("Score:", score)
        print()
    except SystemExit:
        raise
    except Exception as e:
        print(COLOR_RED + '\nCannot connect to HTTP Observatory at: {url} for Host: {host}.'.format(url=API_URL, host=host))
        exit(1)


    # Get the test results
    try:
        response = requests.get(API_URL + '/getScanResults?scan={scan}'.format(scan=scan_id))
        tests = response.json()
        # print(json.dumps(tests, indent=4))  # Output the test results JSON
    except Exception as e:
        print(COLOR_RED + 'Error occurred while retrieving test results:', str(e))
        exit(1)

    # Sort the tests by name
    sorted_tests = sorted(tests.items(), key=lambda x: x[1]['name'])

    # Print the test results
    print(COLOR_BLUE + '\nTest Results:')
    for test_name, test_data in sorted_tests:
        name = test_data['name']
        result = test_data['result']
        score_modifier = test_data['score_modifier']
        score_description = test_data['score_description']

        # Colorize the output based on the result
        if result == 'PASSED':
            result_color = COLOR_GREEN
        elif result == 'FAILED':
            result_color = COLOR_RED
        else:
            result_color = COLOR_YELLOW

        formatted_output = '[{score_modifier: >3}] {score_description}'.format(
            score_modifier=score_modifier, score_description=score_description)

        print('{name:<40}{result_color}{formatted_output}{reset}'.format(
            name=name, result_color=result_color, formatted_output=formatted_output, reset=Style.RESET_ALL))

    print('\nGrade:', COLOR_CYAN + grade + Style.RESET_ALL, ', Score:', COLOR_CYAN + str(score) + Style.RESET_ALL)

    # Check SSL Labs API for SSL/TLS analysis
    try:
        ssllabs_url = SSLLABS_URL.format(domain=host)
        ssllabs_response = requests.get(ssllabs_url)
        ssllabs_data = ssllabs_response.json()
        # print(json.dumps(ssllabs_data, indent=4))  # Output the SSL Labs analysis JSON

        print(COLOR_BLUE + '\nSSL/TLS Analysis:')
        if 'status' in ssllabs_data and ssllabs_data['status'] == 'READY':
            ssllabs_grade = ssllabs_data.get('grade', 'N/A')
            print('Grade:', COLOR_CYAN + ssllabs_grade + Style.RESET_ALL)
            print("Host:", ssllabs_data["host"])
            print("Port:", ssllabs_data["port"])
            print("Protocol:", ssllabs_data["protocol"])
            print("Is Public:", ssllabs_data["isPublic"])
            print("Status:", ssllabs_data["status"])
            print("Start Time:", ssllabs_data["startTime"])
            print("Test Time:", ssllabs_data["testTime"])
            print("Engine Version:", ssllabs_data["engineVersion"])
            print("IP Address:", ssllabs_data["endpoints"][0]["ipAddress"])
            print("Server Name:", ssllabs_data["endpoints"][0]["serverName"])
        else:
            print('SSL/TLS analysis is not yet available.')
    except Exception as e:
        print(COLOR_RED + 'Error occurred while retrieving SSL/TLS analysis:', str(e))

    # Get scan results from HTTP Observatory
    try:
        scan_results_url = API_URL + '/getScanResults?scan={scan_id}'.format(scan_id=scan_id)
        scan_results = requests.get(scan_results_url).json()

        # Extract relevant information from scan results
        clean_results = {}

        # Get the grade and score
        clean_results['Grade'] = grade
        clean_results['Score'] = score

        # Extract test results
        test_results = []
        for test_name, test_data in sorted_tests:
            name = test_data['name']
            result = test_data['result']
            score_modifier = test_data['score_modifier']
            score_description = test_data['score_description']

            test_result = {
                'Name': name,
                'Result': result,
                'Score Modifier': score_modifier,
                'Score Description': score_description
            }
            test_results.append(test_result)

        clean_results['Test Results'] = test_results

        # Extract SSL/TLS analysis
        ssl_analysis = {}
        if 'status' in ssllabs_data and ssllabs_data['status'] == 'READY':
            ssl_analysis['Grade'] = ssllabs_data.get('grade', 'N/A')
            ssl_analysis['Host'] = ssllabs_data['host']
            ssl_analysis['Port'] = ssllabs_data['port']
            ssl_analysis['Protocol'] = ssllabs_data['protocol']
            ssl_analysis['Is Public'] = ssllabs_data['isPublic']
            ssl_analysis['Status'] = ssllabs_data['status']
            ssl_analysis['Start Time'] = ssllabs_data['startTime']
            ssl_analysis['Test Time'] = ssllabs_data['testTime']
            ssl_analysis['Engine Version'] = ssllabs_data['engineVersion']
            ssl_analysis['IP Address'] = ssllabs_data['endpoints'][0]['ipAddress']
            ssl_analysis['Server Name'] = ssllabs_data['endpoints'][0]['serverName']

        clean_results['SSL/TLS Analysis'] = ssl_analysis


        # Print the cleaned results
        print(COLOR_BLUE + '\nRaw Scan Results for Scan ID:', COLOR_CYAN + str(scan_id) + Style.RESET_ALL)
        print('Grade:', COLOR_CYAN + grade + Style.RESET_ALL, ', Score:', COLOR_CYAN + str(score) + Style.RESET_ALL)
        print('Test Results:')
        for test_result in test_results:
            print('Name:', test_result['Name'], ', Result:', test_result['Result'], ', Score Modifier:', test_result['Score Modifier'], ', Score Description:', test_result['Score Description'])
        print('SSL/TLS Analysis:')
        if ssl_analysis:
            for key, value in ssl_analysis.items():
                print(key + ':', value)
        else:
            print('SSL/TLS analysis is not yet available.')

    except Exception as e:
        print(COLOR_RED + 'Error occurred while retrieving scan results:', str(e))


# Entry point of the script
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP Observatory Scanner')
    parser.add_argument('host', help='The host to scan')
    parser.add_argument('--rescan', action='store_true', help='Force a rescan')
    parser.add_argument('--hidden', action='store_true', help='Scan hidden (onion) services')
    args = parser.parse_args()

    analyze(args.host)

