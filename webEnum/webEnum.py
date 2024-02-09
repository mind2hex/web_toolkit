#!/usr/bin/python3
#      author: mind2hex
# description: simple web directory enumeration tool

import requests
import threading
import socket
import re
import os
import argparse
import json
from alive_progress import alive_bar
from fake_useragent import UserAgent
from time import sleep
from requests.packages.urllib3.exceptions import (
    InsecureRequestWarning,
)  # to supress no verify cert warnings
from sys import argv
from django.core.validators import URLValidator
from inspect import currentframe


class AsciiColors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"


class UrlEncodedParameterParser(argparse.Action):
    """this class is used to convert an argument directly into a dict using the format key=value&key=value"""

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            setattr(
                namespace,
                self.dest,
                {
                    key: val
                    for key, val in (
                        query.split("=") for query in values.split("&")
                    )
                },
            )
        except ValueError:
            show_error(
                f"Invalid format for {self.dest}. Use key=value&key=value.",
                "class::UrlEncodedParameterParser",
            )
            exit(-1)


class ListParser(argparse.Action):
    """this class is used to convert an argument directly into a comma separated list"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, list())
        try:
            for val in values.split(","):
                getattr(namespace, self.dest).append(val)
        except:
            show_error(
                f"unable to parse {values} due to incorrect format",
                "class::ListParser",
            )
            exit(-1)


def show_banner():
    author = "mind2hex"
    version = "1.0"
    print(
        f"""
               _     ______                       
              | |   |  ____|                      
 __      _____| |__ | |__   _ __  _   _ _ __ ___     _
 \ \ /\ / / _ \ '_ \|  __| | '_ \| | | | '_ ` _ \   |-|  __
  \ V  V /  __/ |_) | |____| | | | |_| | | | | | |  |=| [wE]
   \_/\_/ \___|_.__/|______|_| |_|\__,_|_| |_| |_|  "^" ====`o   
                                                  
    author:  {AsciiColors.HEADER}{author}{AsciiColors.ENDC}
    version: {AsciiColors.HEADER}{version}{AsciiColors.ENDC}
    """
    )


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="./webEnum.py",
        usage="./webEnum.py [options] -u {url} -w {wordlist}",
        description="a simple python web directory enumerator",
        epilog="https://github.com/mind2hex/",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    if "--usage" in argv:
        show_usage()

    # saving help messages in dictionary to be able to modify help messages more easily
    general_arguments_help_messages = {
        "url": "%-40s - %s"
        % ("target url to enumerate", "example '-u http://localhost:6969/'"),
        "wordlist": "%-40s - %s"
        % (
            "wordlist path to use in enumeration",
            "example '-w /path/to/wordlist.txt'",
        ),
        "http-method": "%-40s - %s"
        % ("HTTP Method to use", "example '-M GET'"),
        "http-headers": "%-40s - %s"
        % (
            "http headers to use in every request",
            "example '-H Header1=foo&Header2=bar'",
        ),
        "user-agent": "%-40s - %s"
        % ("specify user agent. default[yoMamma]", "example '-ua yoMamma'"),
        "http-cookies": "%-40s - %s"
        % (
            "cookies to use in every request",
            "example '-C Cookie1=foo&Cookie2=bar'",
        ),
        "body-data": "%-40s - %s"
        % (
            "body data to send using POST method",
            "example '-b username=admin&password=admin'",
        ),
        "proxies": "%-40s - %s"
        % (
            "proxies to send every request",
            "example '-P http=http://localhost:6969'",
        ),
        "extensions": "%-40s - %s"
        % ("additional extensions to probe", "example '-x php,js,txt'"),
        "json": "%-40s - %s"
        % (
            "send post data in json format",
            "example '-j -b {'username':'admin'}'",
        ),
        "slash": "%-40s - %s" % ("add slash to every word in wordlist", ""),
        "follow": "%-40s - %s" % ("follow redirections.", "default[False]"),
        "randomize-ua": "%-40s - %s"
        % ("randomize user agent.", "default[False]"),
        "ignore-errors": "%-40s - %s" % ("ignore connection errors", ""),
        "verify": "%-40s - %s" % ("verify certificate", "default[False]"),
        "gen-wordlist": "%-40s - %s"
        % (
            "create wordlist using a dir structure",
            "example '-W /home/user/Downloads/wordpress/'",
        ),
        "usage": "%-40s - %s" % ("show usage", ""),
    }

    performance_arguments_help_messages = {
        "threads": "%-40s - %s" % ("threads. default[01]", "example '-t 10'"),
        "timeout": "%-40s - %s"
        % ("time to wait for a response default[10]", "example '-to 10'"),
        "timewait": "%-40s - %s"
        % ("time to wait between requests default[0]", "example '-tw 10'"),
        "retries": "%-40s - %s"
        % ("retry failed connections", "example '-rt 10'"),
    }

    debugging_arguments_help_messages = {
        "verbose": "%-40s - %s" % ("show verbose messages", ""),
        "debug": "%-40s - %s" % ("show debugging messages", ""),
        "output": "%-40s - %s"
        % ("save output to a file", "example '-o output.txt'"),
        "quiet": "%-40s - %s" % ("dont show config before execution", ""),
    }

    filter_arguments_help_messages = {
        "hide-status-code": "%-40s - %s"
        % ("hide responses using status code", "example '-hs 500,400'"),
        "hide-content-length": "%-40s - %s"
        % ("hide responses using content length", "example '-hc nnnn,nnn'"),
        "hide-web-server": "%-40s - %s"
        % ("hide responses using web server", "example '-hw nginx'"),
        "hide-regex": "%-40s - %s"
        % ("hide responses using regex", "example '-hr failed'"),
    }

    # dividing parsing in different functions to improve code readibility
    parser = parse_general_arguments(parser, general_arguments_help_messages)
    parser = parse_performance_arguments(
        parser, performance_arguments_help_messages
    )
    parser = parse_debugging_arguments(
        parser, debugging_arguments_help_messages
    )
    parser = parse_filter_arguments(parser, filter_arguments_help_messages)

    return parser.parse_args()


def parse_general_arguments(
    parser: argparse.ArgumentParser, help_messages: dict
):
    """
    this function parse general arguments.
    """

    parser.add_argument(
        "-u",
        "--url",
        metavar="",
        required=True,
        help=help_messages["url"],
    )
    wordlist_group = parser.add_mutually_exclusive_group(required=True)
    wordlist_group.add_argument(
        "-w",
        "--wordlist",
        metavar="",
        type=argparse.FileType("r", encoding="latin-1"),
        help=help_messages["wordlist"],
    )
    wordlist_group.add_argument(
        "-W",
        "--gen-wordlist",
        metavar="",
        type=str,
        help=help_messages["gen-wordlist"],
    )
    parser.add_argument(
        "-M",
        "--http-method",
        metavar="",
        choices=["GET", "HEAD", "POST"],
        default="GET",
        help=help_messages["http-method"],
    )
    parser.add_argument(
        "-H",
        "--headers",
        metavar="",
        default={},
        action=UrlEncodedParameterParser,
        help=help_messages["http-headers"],
    )
    parser.add_argument(
        "-A",
        "--user-agent",
        metavar="",
        default="yoMamma",
        help=help_messages["user-agent"],
    )
    parser.add_argument(
        "-C",
        "--cookies",
        metavar="",
        default={},
        action=UrlEncodedParameterParser,
        help=help_messages["http-cookies"],
    )
    parser.add_argument(
        "-b",
        "--body-data",
        metavar="",
        help=help_messages["body-data"],
    )
    parser.add_argument(
        "-P",
        "--proxy",
        metavar="",
        default={},
        action=UrlEncodedParameterParser,
        help=help_messages["proxies"],
    )
    parser.add_argument(
        "-x",
        "--extension",
        metavar="",
        default=None,
        action=ListParser,
        help=help_messages["extensions"],
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help=help_messages["json"],
    )
    parser.add_argument(
        "-s",
        "--add-slash",
        action="store_true",
        help=help_messages["slash"],
    )
    parser.add_argument(
        "-f",
        "--follow",
        action="store_true",
        default=False,
        help=help_messages["follow"],
    )
    parser.add_argument(
        "-R",
        "--randomize-ua",
        action="store_true",
        help=help_messages["randomize-ua"],
    )
    parser.add_argument(
        "-I",
        "--ignore-errors",
        action="store_true",
        help=help_messages["ignore-errors"],
    )
    parser.add_argument(
        "--usage", action="store_true", help=help_messages["usage"]
    )
    parser.add_argument(
        "-V", "--verify", action="store_true", help=help_messages["verify"]
    )

    return parser


def parse_performance_arguments(
    parser: argparse.ArgumentParser, help_messages: dict
):
    """
    this function parse perfomance arguments
    """

    performance = parser.add_argument_group("performance options")
    performance.add_argument(
        "-t",
        "--threads",
        metavar="",
        type=int,
        default=1,
        help=help_messages["threads"],
    )
    performance.add_argument(
        "-to",
        "--timeout",
        metavar="",
        type=int,
        default=10,
        help=help_messages["timeout"],
    )
    performance.add_argument(
        "-tw",
        "--timewait",
        metavar="",
        type=int,
        default=0,
        help=help_messages["timewait"],
    )
    performance.add_argument(
        "-rt",
        "--retries",
        metavar="",
        type=int,
        default=0,
        help=help_messages["retries"],
    )

    return parser


def parse_debugging_arguments(
    parser: argparse.ArgumentParser, help_messages: dict
):
    """
    this function parse debugging arguments
    """
    debug = parser.add_argument_group("debugging options")
    debug.add_argument(
        "-v", "--verbose", action="store_true", help=help_messages["verbose"]
    )
    debug.add_argument(
        "-d", "--debug", action="store_true", help=help_messages["debug"]
    )
    debug.add_argument(
        "-o",
        "--output",
        metavar="",
        type=str,
        help=help_messages["output"],
    )
    debug.add_argument(
        "-q", "--quiet", action="store_true", help=help_messages["quiet"]
    )

    return parser


def parse_filter_arguments(
    parser: argparse.ArgumentParser, help_messages: dict
):
    """
    this function parse filter arguments
    """
    filters = parser.add_argument_group("filter options")
    filters.add_argument(
        "-hs",
        "--hs-filter",
        metavar="",
        default=None,
        action=ListParser,
        help=help_messages["hide-status-code"],
    )
    filters.add_argument(
        "-hc",
        "--hc-filter",
        metavar="",
        default=None,
        action=ListParser,
        help=help_messages["hide-content-length"],
    )
    filters.add_argument(
        "-hw",
        "--hw-filter",
        metavar="",
        default=None,
        action=ListParser,
        help=help_messages["hide-web-server"],
    )
    filters.add_argument(
        "-hr",
        "--hr-filter",
        metavar="",
        default=None,
        help=help_messages["hide-regex"],
    )

    return parser


def additional_parsing(parsed_arguments):
    """This function configures additional properties required for the web
    directory enumeration process, such as:
    - request count
    - wordlist end-of-file position
    - extensions
    - the semaphores for thread synchronization and the execution event for thread signalling.

    Args:
        parsed_arguments (argparse.Namespace): this is a Namespace for the previously parsed arguments

    Returns:
        argparse.Namespace: This function returns the finished arguments already parsed.
    """

    parsed_arguments.wordlist_content = []
    if parsed_arguments.wordlist is not None:
        # loading wordlist
        with open(
            parsed_arguments.wordlist.name, "r", encoding="latin-1"
        ) as handler:
            for line in handler:
                word = line.rstrip("\n")
                parsed_arguments.wordlist_content.append(word)

                # adding slash to every word in the wordlist if specified
                if parsed_arguments.add_slash:
                    parsed_arguments.wordlist_content.append(word + "/")

                # adding extensions to every word in the wordlist if specified
                if parsed_arguments.extension is not None:
                    for extension in parsed_arguments.extension:
                        parsed_arguments.wordlist_content.append(
                            word + "." + extension
                        )

    elif parsed_arguments.gen_wordlist is not None:
        # loading wordlist using a directory structure
        for root, dirs, files in os.walk(parsed_arguments.gen_wordlist):
            for dir in dirs:
                for file in files:
                    parsed_arguments.wordlist_content.append(f"{dir}/{file}")

    # total requests
    parsed_arguments.total_requests = len(parsed_arguments.wordlist_content)

    # setting up screenlock to avoid threads printing at the same time and mess up the output
    parsed_arguments.screenlock = threading.Semaphore(value=1)
    parsed_arguments.lock = threading.Lock()

    # run_event is used to tell threads when to stop
    parsed_arguments.run_event = threading.Event()

    return parsed_arguments


def show_error(error, msg, origin, suggestion=""):
    print(f"\n {origin} --> {AsciiColors.FAIL}error{AsciiColors.ENDC}")
    print(f" [X] {AsciiColors.FAIL}{error}{AsciiColors.ENDC}")
    print(f" [X] {AsciiColors.FAIL}{msg}{AsciiColors.ENDC}")
    print(f" [X] {AsciiColors.WARNING}{suggestion}{AsciiColors.ENDC}")


def show_output(payload, req, screenlock, output_file=None):
    output_string = (
        f"{AsciiColors.OKGREEN}       PAYLOAD{AsciiColors.ENDC} --> %s"
        % (payload)
        + "\n"
    )
    output_string += (
        f"{AsciiColors.OKGREEN}   STATUS CODE{AsciiColors.ENDC} --> %s"
        % (req.status_code)
        + "\n"
    )
    output_string += (
        f"{AsciiColors.OKGREEN}CONTENT LENGTH{AsciiColors.ENDC} --> %s"
        % (req.headers["Content-Length"])
        + "\n"
    )
    output_string += (
        f"{AsciiColors.OKGREEN}        SERVER{AsciiColors.ENDC} --> %s"
        % (req.headers["Server"])
        + "\n"
    )
    output_string += "=" * 110 + "\n"
    screenlock.acquire()
    print(output_string)
    screenlock.release()

    # write output to a file (log) if specified
    if output_file is not None:
        with open(output_file, "a") as handler:
            handler.write(output_string)


def show_config(args):
    print(
        f"[!] %-20s %s"
        % (f"{AsciiColors.HEADER}GENERAL{AsciiColors.ENDC}", "=" * 40)
    )
    print("%-20s:%s" % ("URL", args.url))

    if args.wordlist is not None:
        print("%-20s:%s" % ("WORDLIST", args.wordlist.name))
    else:
        print("%-20s:%s" % ("GENERATE WL USING:", args.gen_wordlist))

    print("%-20s:%s" % ("HTTP METHOD", args.http_method))
    print("%-20s:%s" % ("JSON FORMAT", str(args.json)))

    if args.body_data is not None:
        print("%-20s:%s" % ("BODY", args.body_data))

    if len(args.cookies) > 0:
        print("%-20s:%s" % ("COOKIES", str(args.cookies)))

    if len(args.headers) > 0:
        print("%-20s:%s" % ("HEADERS", str(args.headers)))

    if len(args.proxy) > 0:
        print("%-20s:%s" % ("PROXIES", str(args.proxy)))

    if args.extension is not None:
        print("%-20s:%s" % ("EXTENSIONS", str(args.extension)))

    print("%-20s:%s" % ("RAND-USER-AGENT", str(args.randomize_ua)))
    print("%-20s:%s" % ("FOLLOW REDIRECT", str(args.follow)))
    print("%-20s:%s" % ("IGNORE ERRORS", str(args.ignore_errors)))
    print("%-20s:%s" % ("ADD SLASH", str(args.add_slash)))
    print("%-20s:%s" % ("VERIFY CERT", str(args.verify)))
    print()
    print(
        f"[!] %-20s %s"
        % (f"{AsciiColors.HEADER}PERFORMANCE{AsciiColors.ENDC}", "=" * 40)
    )
    print("%-20s:%s" % ("THREADS", args.threads))
    print("%-20s:%s" % ("TIMEOUT", args.timeout))
    print("%-20s:%s" % ("TIMEWAIT", args.timewait))
    print("%-20s:%s" % ("RETRIES", args.retries))
    print()
    print(
        f"[!] %-20s %s"
        % (f"{AsciiColors.HEADER}DEBUGGING{AsciiColors.ENDC}", "=" * 40)
    )
    print("%-20s:%s" % ("VERBOSE", args.verbose))
    print("%-20s:%s" % ("DEBUG", args.debug))
    print("%-20s:%s" % ("OUTPUT", args.output))
    print()
    print(
        f"[!] %-20s %s"
        % (f"{AsciiColors.HEADER}FILTERS{AsciiColors.ENDC}", "=" * 40)
    )
    print("%-20s:%s" % ("HIDE STATUS CODE", args.hs_filter))
    print("%-20s:%s" % ("HIDE CONTENT LENGTH", args.hc_filter))
    print("%-20s:%s" % ("HIDE WEB SERVER", args.hw_filter))
    print("%-20s:%s" % ("HIDE RE PATTERN", args.hr_filter))
    print()


def validate_arguments(args):
    """validate_arguments checks that every argument is valid or in the correct format"""

    validate_url(args.url)

    # no need since argparse checks wordlist already
    # validate_wordlist(args.wordlist)

    validate_threads(args.threads)

    if args.http_method == "POST":
        validate_body_data(args.headers, args.body_data)

    # validating hs-filter (hide status code filter)
    validate_filters(
        args.hs_filter, args.hc_filter, args.hw_filter, args.hr_filter
    )


def validate_url(url):
    """validate url using URLValidator from django"""

    val = URLValidator()
    try:
        val(url)
    except:
        # raise ValueError(f"URL invalida {url}")
        show_error(
            f"Invalid URL --> {url}",
            f"function::{currentframe().f_code.co_name}",
            "try using a correct url format like http://google.com/",
        )
        exit(-1)


def validate_threads(threads):
    if threads < 0:
        show_error(
            f"threads cannot be less than 0 --> {threads}",
            f"function::{currentframe().f_code.co_name}",
            "try using a thread number in range(1, 50)",
        )
        exit(-1)


def validate_body_data(post_data, js):
    if post_data is None:
        show_error(
            "No post data specified",
            f"function::{currentframe().f_code.co_name}",
            "see help message with --help to learn how to specify body data",
        )
        exit(-1)
    elif js:
        try:
            json.loads(post_data)
        except json.decoder.JSONDecodeError:
            show_error(
                f"Error while decoding json data {post_data}",
                f"function::{currentframe().f_code.co_name}",
                "see help message with --help to learn how to specify body data",
            )
            exit(-1)
    else:
        # normal body data validations goes here
        pass


def validate_filters(hs_filter, hc_filter, hw_filter, hr_filter):
    # (hide status code filter)
    if hs_filter is not None:
        for status_code in hs_filter:
            if not status_code.isdigit():
                show_error(
                    f" incorrect hs_filter value {status_code}",
                    f"function::{currentframe().f_code.co_name}",
                    "try using a digit like 6969",
                )
                exit(-1)

    # (hide content length filter)
    if hc_filter is not None:
        for content_length in hc_filter:
            if not content_length.isdigit():
                show_error(
                    f" incorrect hc_filter value {status_code}",
                    f"function::{currentframe().f_code.co_name}",
                )
                exit(-1)

    # (hide web server filter)
    # (hide regex filter)


def initial_checks(args):
    """Initial checks before proceeds with the program execution"""

    # Suprimir solo las advertencias de solicitudes inseguras
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # testing target connection
    try:
        requests.get(args.url, timeout=args.timeout, verify=args.verify)
    except requests.exceptions.ConnectionError as e:
        show_error(
            e,
            f"Failed to establish a new connection to {args.url}",
            "initial_checks()",
        )
        exit(-1)

    # testing proxy connection
    if len(args.proxy) > 0:
        try:
            requests.get(
                args.url + "/proxy_test",
                timeout=args.timeout,
                proxies=args.proxy,
            )
        except Exception as e:
            show_error(e, f"Proxy server is not responding", "initial_checks()")
            exit(-1)


def progress_bar(args):
    """Progress bar"""

    # setting global variable bar because it will be called from other threads
    # every time bar is called, progress var increments is bar in 1
    global bar
    # starting alive_bar
    with alive_bar(
        args.total_requests, title=f"Progress", enrich_print=False
    ) as bar:
        while True:
            # stop thread if run_event has been cleaned
            if not args.run_event.is_set() and threading.active_count() <= 3:
                break

            sleep(0.1)


def thread_handler(args):
    """this functions prepare and execute (start) every thread

    Args:
        args (argparse.Namespace): This namespace contains all parsed arguments

    Returns:
        int: exit code of the execution of the function
    """

    # setting run event to stop threads when required
    args.run_event.set()

    # creating thread lists
    thread_list = []

    # thread[0] is a specific thread for progress bar
    thread_list.append(threading.Thread(target=progress_bar, args=[args]))
    for thread in range(0, args.threads):
        thread_list.append(threading.Thread(target=thread_process, args=[args]))

    # starting threads
    for i, thread in enumerate(thread_list):
        thread.start()

        # giving thread[0] some time to set up progress bar global variables
        # in order to avoid calls to undefined variables from other threads
        if i == 0:
            sleep(0.3)

    exit_msg = ""

    try:
        # control loop to check if every thread is finished
        while args.run_event.is_set() and threading.active_count() > 3:
            thread_status = False
            for thread in threading.enumerate():
                # if thread in thread.name, that means that a thread still
                # running, so the program cant clear args.run_event yet
                if "thread" in thread.name:
                    thread_status = True
                    break

            if not thread_status:
                break

            sleep(0.1)

        # unmark to debug purpose
        # print("\n\n\n", args.run_event.is_set(), threading.active_count(), threading.enumerate())
        args.run_event.clear()
        exit_msg = "[!] program finished "
        exit_code = 0

    except KeyboardInterrupt:
        # to stop threads, run_event should be clear()
        args.run_event.clear()
        exit_msg = "[!] KeyboardInterrupt: Program finished by user...\n"
        exit_msg += "[!] threads successfully closed \n"
        exit_code = -1

    finally:
        # finishing threads
        for thread in thread_list[1:]:
            thread.join()
        sleep(1)
        thread_list[0].join()

    print("\n" + exit_msg)
    return exit_code


def thread_process(args):
    global bar  # used to increment progress bar

    # setting up headers and cookies
    headers = args.headers
    cookies = args.cookies

    filters = {
        "hs": args.hs_filter,
        "hc": args.hc_filter,
        "hw": args.hw_filter,
        "hr": args.hr_filter,
    }

    retry_counter = 0
    while args.run_event.is_set() and len(args.wordlist_content) > 0:
        # iterating to next word only when retry_counter == 0
        if retry_counter == 0:
            # pop word from wordlist specific for every thread
            if len(args.wordlist_content) == 0:
                break

            with args.lock:
                word = args.wordlist_content.pop(0)

        # adding word to url
        new_url = args.url if args.url.endswith("/") else args.url + "/"
        new_url += word
        payload = new_url

        # randomize user agent
        headers.setdefault(
            "User-Agent",
            UserAgent().random if args.randomize_ua else args.user_agent,
        )

        try:
            req = requests.request(
                args.http_method,
                url=new_url,
                data=args.body_data,
                timeout=int(args.timeout),
                allow_redirects=args.follow,
                proxies=args.proxy,
                cookies=cookies,
                headers=headers,
                verify=args.verify,
            )

        except (socket.error, requests.ConnectTimeout) as e:
            # Retrying connection if specified
            if retry_counter < args.retries:
                retry_counter += 1
                with args.lock:
                    args.screenlock.acquire()
                    print(
                        f" {AsciiColors.WARNING}// Retrying connection PAYLOAD[{payload}] retries[{retry_counter}] {AsciiColors.ENDC}"
                    )
                    args.screenlock.release()
                continue

            with args.lock:
                args.screenlock.acquire()
                show_error(
                    e,
                    f"Error stablishing connection  PAYLOAD[{payload}]",
                    "thread",
                    "Check ",
                )
                args.screenlock.release()

            if args.ignore_errors:
                with args.lock:
                    bar()
                continue
            else:
                args.run_event.clear()
                break

        # resetting retry counter to 0
        retry_counter = 0

        # if request made successfully, then increment bar
        with args.lock:
            bar()

        # in case server didnt send back content length and server info
        req.headers.setdefault("Content-Length", "UNK")
        req.headers.setdefault("Server", "UNK")

        if check_filters(filters, req):
            show_output(payload, req, args.screenlock, args.output)

        sleep(args.timewait)  # timewait between requests


def check_filters(filters, response):
    """
    if all filters are None, then show output
    else show output depending on which filter is set and is matching
    """
    filter_status = True

    if all(argument_filter is None for argument_filter in filters.values()):
        return filter_status

    elif filters.get("hs", None) is not None:
        if str(response.status_code) in filters.get("hs", None):
            filter_status = False

    elif filters.get("hc", None) is not None:
        if response.headers["Content-Length"] != "UNK":
            if str(response.headers["Content-Length"]) in filters.get(
                "hc", None
            ):
                filter_status = False

    elif filters.get("hw", None) is not None:
        if response.headers["Server"] in filters.get("hw", None):
            filter_status = False

    elif filters.get("hr", None) is not None:
        # searching matching patterns in response headers
        matching = False
        for header in response.headers.keys():
            if (
                re.search(filters.get("hr", None), response.headers[header])
                is not None
            ):
                matching = True
                break

        if matching:
            filter_status = False
        else:
            # searching matching patterns in response content
            aux = re.search(
                filters.get("hr", None), response.content.decode("latin-1")
            )
            if aux is not None:
                filter_status = False

    return filter_status


def main():
    show_banner()
    parsed_arguments = parse_arguments()
    parsed_arguments = additional_parsing(parsed_arguments)
    validate_arguments(parsed_arguments)

    initial_checks(parsed_arguments)

    if not parsed_arguments.quiet:
        show_config(parsed_arguments)
        sleep(2)

    return thread_handler(parsed_arguments)


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt as e:
        show_error(e, "User Keyboard Interrupt", "main")
        exit(-1)


# TODO:
#  - Resume functionality
#  - Basic Auth
#  - Codificadores para los payloads
#  - Aceptar rangos de valores en los content length y status code
#  - implementar multiproceso combinado con multihilo
#  - implementar verbose/debug output
