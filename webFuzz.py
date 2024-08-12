#!/usr/bin/python3
#      author: mind2hex
# description: simple web fuzzer

import argparse
import requests
import threading
import socket
import re
import json
from time import sleep
from sys import argv
from urllib.parse import quote
from random import choice as random_choice
from django.core.validators import URLValidator
from alive_progress import alive_bar
from chardet import detect as detect_encoding
from inspect import currentframe


def banner():
    author = "mind2hex"
    version = "1.0"
    print(
        f"""
               _     ______                      
              | |   |  ____|                     
 __      _____| |__ | |__ _   _ ___________ _ __ 
 \ \ /\ / / _ \ '_ \|  __| | | |_  /_  / _ \ '__|
  \ V  V /  __/ |_) | |  | |_| |/ / / /  __/ |   
   \_/\_/ \___|_.__/|_|   \__,_/___/___\___|_|   
                                                 
    author:  {AsciiColors.HEADER}{author}{AsciiColors.ENDC}
    version: {AsciiColors.HEADER}{version}{AsciiColors.ENDC}
    """
    )


class DictParser(argparse.Action):
    """this class is used to convert an argument directly into a dict using the format key=value&key=value"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        try:
            for query in values.split("&"):
                key, val = query.split("=")
                getattr(namespace, self.dest)[key] = val 
        except:
            show_error(f"uanble to parse {values} due to incorrect format ", "DictParser")


class ProxyParser(argparse.Action):
    """this class is used to convert an argument directly into a dict using the format key;value,key=value"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        try:
            for query in values.split(","):
                key, val = query.split(";")
                getattr(namespace, self.dest)[key] = val
        except:
            show_error(f"uanble to parse {values} due to incorrect format ", "ProxyParser")


class ListParser(argparse.Action):
    """this class is used to convert an argument directly into a comma separated list"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, list())
        try:
            for val in values.split(","):
                getattr(namespace, self.dest).append(val)
        except:
            show_error(f"unable to parse {values} due to incorrect format", "class::ListParser")


class AsciiColors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"


def parse_arguments():
    """return parsed arguments"""

    magic = "FUZZ"
    parser = argparse.ArgumentParser(
        prog="./webFuzzer.py",
        usage="./webFuzzer.py [options] -u {url} -w {wordlist}",
        description="a simple python multithreading web fuzzer",
        epilog="https://github.com/mind2hex/",
    )
    # general args
    parser.add_argument(
        "-u", 
        "--url", 
        metavar="", 
        required=True, 
        help=f"target url. ex --> http://localhost/{magic}"
    )
    parser.add_argument(
        "-w", 
        "--wordlist", 
        metavar="", 
        required=True, 
        type=argparse.FileType("r", encoding="latin-1"), 
        help="wordlist"
    )
    parser.add_argument(
        "-b",
        "--body-data",
        metavar="",
        help=f"body data to send using POST method. ex --> 'username=admin&password={magic}'",
    )
    parser.add_argument(
        "-C",
        "--cookies",
        metavar="",
        default={},
        action=DictParser,
        help="set cookies.      ex --> 'Cookie1=lol&Cookie2=lol'",
    )
    parser.add_argument(
        "-H",
        "--headers",
        metavar="",
        default={},
        action=DictParser,
        help="set HTTP headers. ex --> 'Header1=lol&Header2=lol'",
    )
    parser.add_argument(
        "-P",
        "--proxies",
        metavar="",
        default={},
        action=ProxyParser,
        help="set proxies.      ex --> 'http;http://proxy1:8080,https;http://proxy2:8000'",
    )
    parser.add_argument(
        "-U", 
        "--user-agent", 
        metavar="", 
        default="yoMama", 
        help="specify user agent"
    )
    parser.add_argument(
        "-M",
        "--http-method",
        metavar="",
        choices=["GET", "HEAD", "POST"],
        default="GET",
        help="HTTP  to use. [GET|POST|HEAD]",
    )
    parser.add_argument(
        "--magic", 
        metavar="", 
        default="FUZZ", 
        help=f"specify magic word [default:FUZZ]"
    )
    parser.add_argument(
        "-js",
        "--json",
        action="store_true",
        help="if specified, then body data should be json. ex --> -b {'username':'%s'}" % (magic),
    )
    parser.add_argument(
        "-f", 
        "--follow", 
        action="store_true", 
        help="follow redirections"
    )
    parser.add_argument(
        "--rand-user-agent", 
        action="store_true", 
        help="randomize user-agent"
    )
    parser.add_argument(
        "--usage", 
        action="store_true", 
        help="show usage examples"
    )
    parser.add_argument(
        "--ignore-errors", 
        action="store_true", 
        help="ignore connection errors, useful to enumerate fuzz subdomains"
    )

    # performance args
    performance = parser.add_argument_group("performance options")
    performance.add_argument(
        "-t", 
        "--threads", 
        metavar="", 
        type=int, 
        default=1, 
        help="threads [default 1]"
    )
    performance.add_argument(
        "-to", 
        "--timeout", 
        metavar="", 
        type=int, 
        default=10, 
        help="time to wait for response in seconds [default 10]"
    )
    performance.add_argument(
        "-tw",
        "--timewait",
        metavar="",
        type=int,
        default=0,
        help="time to wait between each requests in seconds [default 0]",
    )
    performance.add_argument(
        "-rt",
        "--retries",
        metavar="",
        type=int,
        default=0,
        help="retries per connections if connection fail [default 0]",
    )

    # debugging args
    debug = parser.add_argument_group("debugging options")
    debug.add_argument(
        "-v", 
        "--verbose", 
        action="store_true", 
        help="show verbose messages"
    )
    debug.add_argument(
        "-d", 
        "--debug", 
        action="store_true", 
        help="show debugging messages"
    )
    debug.add_argument(
        "-o", 
        "--output", 
        metavar="", 
        type=argparse.FileType("w"), 
        help="save output to a file"
    )
    debug.add_argument(
        "-q", 
        "--quiet", 
        action="store_true", 
        help="dont show config before execution"
    )

    # filter args
    filters = parser.add_argument_group("filter options")
    filters.add_argument(
        "-hs",
        "--hs-filter",
        metavar="",
        default=None,
        action=ListParser,
        help="hide responses with the specified status codes. ex: '300,400'",
    )
    filters.add_argument(
        "-hc",
        "--hc-filter",
        metavar="",
        default=None,
        action=ListParser,
        help="hide responses with the specified content lenghts. ex: '1234,4321'",
    )
    filters.add_argument(
        "-hw",
        "--hw-filter",
        metavar="",
        default=None,
        action=ListParser,
        help="hide responses with the specified  web servers. ex: 'apache,nginx'",
    )
    filters.add_argument(
        "-hr",
        "--hr-filter",
        metavar="",
        default=None,
        help="hide responses matching the specified pattern. ex: 'authentication failed'",
    )

    parsed_arguments = parser.parse_args()

    parsed_arguments.request_count = 0  # every time a thread makes a request, this counter is added by one
    parsed_arguments.request_total = get_file_lines(parsed_arguments.wordlist.name)
    parsed_arguments.wordlist.end_of_file = parsed_arguments.wordlist.seek(0, 2)
    parsed_arguments.wordlist.seek(0)

    
    parsed_arguments.screenlock = threading.Semaphore(value=1)  # screenlock to avoid multiple threads printing at once
    parsed_arguments.lock = threading.Lock()                    # Lock to avoid race conditions over same shared variable
    parsed_arguments.run_event = threading.Event()              # run_event to tell every thread when to stop

    parsed_arguments.UserAgent_wordlist = [
        "Mozilla/1.22 (compatible; MSIE 2.0d; Windows NT)",
        "Mozilla/2.0 (compatible; MSIE 3.02; Update a; Windows NT)",
        "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)",
        "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 4.0)",
        "Mozilla/4.79 [en] (WinNT; U)",
        "Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:0.9.2) Gecko/20010726 Netscape6/6.1",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.19) Gecko/20081204 SeaMonkey/1.1.14",
        "Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaE90-1/210.34.75 Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413",
        "Mozilla/5.0 (iPhone; U; CPU iPhone OS 2_2 like Mac OS X; en-us) AppleWebKit/525.18.1 (KHTML, like Gecko) Version/3.1.1 Mobile/5G77 Safari/525.20",
        "Mozilla/5.0 (Linux; U; Android 1.5; en-gb; HTC Magic Build/CRB17) AppleWebKit/528.5+ (KHTML, like Gecko) Version/3.1.2 Mobile Safari/525.20.1",
        "Opera/9.27 (Windows NT 5.1; U; en)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.4.154.25 Safari/525.19",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.48 Safari/525.19",
        "Wget/1.8.2",
        "Mozilla/5.0 (PLAYSTATION 3; 1.00)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; (R1 1.6))",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1",
        "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10 (.NET CLR 3.5.30729) JBroFuzz/1.4",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20050923 CentOS/1.0.7-1.4.1.centos4 Firefox/1.0.7",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727)",
        "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5",
        "Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.7) Gecko/20070606",
        "Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.8.1.14) Gecko/20080520 Firefox/2.0.0.14",
        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.0.5) Gecko/2008120121 Firefox/3.0.5",
    ]

    return parsed_arguments


def usage():
    """Only show ussage messages"""
    target = "https://google.com/"
    magic = "FUZZ"
    wordlist = "/path/wordlist.txt"
    proxies = "http;http://localhost:8080,https;http://localhost:8000"

    print("### directory enumeration")
    print(f"$ ./webFuzzer.py -ss 200,300 -w {wordlist} -u {target}{magic}\n")
    print("### parameter testing ")
    print(f"$ ./webFuzzer.py -ss 200 -w {wordlist} -u {target}script.php?param1={magic}\n")
    print("### Fuzzing post body data [bruteforce attack]")
    print(
        f"$ ./webFuzzer.py -M POST -hr 'alert=1' -w {wordlist} -B 'username=admin&password={magic}' -u {target}login\n"
    )
    print("### using proxies ")
    print(f"$ ./webFuzzer.py -P {proxies} -w {wordlist} -u {target}{magic}\n")
    print("### specifying user agent and cookie ")
    print(
        f"$ ./webFuzzer.py --user-agent FirefoxBOT -C cookie=monster&cookie2=monster2 -w {wordlist} -u {target}{magic}\n"
    )

    exit(0)


def get_file_lines(file):
    """retorna la cantidad de lineas de un archivo"""

    # detecting encoding
    with open(file, "rb") as f:
        codification = detect_encoding(f.read())["encoding"]

    # getting lines
    with open(file, "r", encoding=codification) as f:
        total = sum(1 for line in f)

    return total


def validate_arguments(args):
    """validate_arguments checks that every argument is valid or in the correct format"""

    validate_url(args.url)

    if args.http_method == "POST":
        validate_body_data(args.body_data, args.json)

    # validating hs-filter (hide status code filter)
    validate_filters(args.hs_filter, args.hc_filter, args.hw_filter, args.hr_filter)


def validate_url(url):
    """validate url using URLValidator from django"""
    val = URLValidator()
    try:
        val(url)
    except:
        show_error(f"Error while validating url --> {url}", f"function::{currentframe().f_code.co_name}")


def validate_body_data(post_data, js):
    if post_data == None:
        show_error("No post data specified", f"function::{currentframe().f_code.co_name}")
    elif js:
        try:
            json.loads(post_data)
        except json.decoder.JSONDecodeError:
            show_error(f"Error while decoding json data {post_data}", f"function::{currentframe().f_code.co_name}")
    else:
        # normal body data validations goes here
        pass


def validate_filters(hs_filter, hc_filter, hw_filter, hr_filer):
    # (hide status code filter)
    if hs_filter != None:
        for status_code in hs_filter:
            if status_code.isdigit == False:
                show_error(f" incorrect hs_filter value {status_code}", f"function::{currentframe().f_code.co_name}")

    # (hide content length filter)
    if hc_filter != None:
        for content_length in hc_filter:
            if content_length.isdigit == False:
                show_error(f" incorrect hc_filter value {status_code}", f"function::{currentframe().f_code.co_name}")

    # (hide web server filter)
    # (hide regex filter)


def initial_checks(args):
    """Initial checks before proceeds with the program execution"""

    # testing target connection
    try:
        requests.request(args.http_method, args.url, data=args.body_data, timeout=args.timeout)
    except requests.exceptions.ConnectionError:
        show_error(f"Failed to establish a new connection to {args.url}", f"function::{currentframe().f_code.co_name}")

    # testing proxy connection
    if len(args.proxies) > 0:
        try:
            requests.get(args.url + "/proxy_test", timeout=args.timeout, proxies=args.proxies)
        except:
            show_error(f"Proxy server is not responding", f"function::{currentframe().f_code.co_name}")

    # searching for magic word inside arguments
    if args.magic not in args.url:
        state = False

        # searching for magic word inside HTTP headers
        for  value in args.headers.values():
            if args.magic in value:
                state = True
                break
        
        # searching for magic word inside HTTP cookies
        for value in args.cookies.values():
            if args.magic in value:
                state = True
                break

        # searching for magic word inside HTTP proxies
        for value in args.proxies.values():
            if args.magic in value:
                state = True
                break
                
        # searching for magic word inside user_agent
        if args.magic in args.user_agent:
            state = True

        # searching for magic word inside body_data
        if args.body_data is not None:
            if args.magic in args.body_data:
                state = True

        if state == False:
            show_error(f"No magic word supplied.", f"function::{currentframe().f_code.co_name}")
        
    # checking GET request
    if ((args.http_method == "GET") or (args.http_method == "HEAD")):
        if args.body_data is not None:
            show_error(f"Body data supplied to a GET|HEAD request.", f"function::{currentframe().f_code.co_name}")

    # checking POST request
    if args.http_method == "POST":
        if args.body_data is None:
            show_error("No body data specified...", f"function::{currentframe().f_code.co_name}")


def show_error(msg, origin):
    print(f"\n {origin} --> {AsciiColors.FAIL}error{AsciiColors.ENDC}")
    print(f" [X] {AsciiColors.FAIL}{msg}{AsciiColors.ENDC}")
    exit(-1)


def show_config(args):
    print(f"[!] %-20s %s" % (f"{AsciiColors.HEADER}GENERAL{AsciiColors.ENDC}", "=" * 40))
    print("%-20s:%s" % ("TARGET", args.url))
    print("%-20s:%s" % ("WORDLIST", args.wordlist.name))
    print("%-20s:%s" % ("MAGIC WORD", str(args.magic)))
    print("%-20s:%s" % ("METHOD", args.http_method))
    print("%-20s:%s" % ("JSON FORMAT", str(args.json)))
    print("%-20s:%s" % ("BODY", args.body_data))
    print("%-20s:%s" % ("COOKIES", str(args.cookies)))
    print("%-20s:%s" % ("HEADERS", str(args.headers)))
    print("%-20s:%s" % ("PROXIES", str(args.proxies)))
    print("%-20s:%s" % ("USER-AGENT", str(args.user_agent)))
    print("%-20s:%s" % ("RAND-USER-AGENT", str(args.rand_user_agent)))
    print("%-20s:%s" % ("FOLLOW REDIRECT", str(args.follow)))
    print("%-20s:%s" % ("IGNORE ERRORS", str(args.ignore_errors)))
    print()
    print(f"[!] %-20s %s" % (f"{AsciiColors.HEADER}PERFORMANCE{AsciiColors.ENDC}", "=" * 40))
    print("%-20s:%s" % ("THREADS", args.threads))
    print("%-20s:%s" % ("TIMEOUT", args.timeout))
    print("%-20s:%s" % ("TIMEWAIT", args.timewait))
    print("%-20s:%s" % ("RETRIES", args.retries))
    print()
    print(f"[!] %-20s %s" % (f"{AsciiColors.HEADER}DEBUGGING{AsciiColors.ENDC}", "=" * 40))
    print("%-20s:%s" % ("VERBOSE", args.verbose))
    print("%-20s:%s" % ("DEBUG", args.debug))
    print("%-20s:%s" % ("OUTPUT", args.output))
    print()
    print(f"[!] %-20s %s" % (f"{AsciiColors.HEADER}FILTERS{AsciiColors.ENDC}", "=" * 40))
    print("%-20s:%s" % ("HIDE STATUS CODE", args.hs_filter))
    print("%-20s:%s" % ("HIDE CONTENT LENGTH", args.hc_filter))
    print("%-20s:%s" % ("HIDE WEB SERVER", args.hw_filter))
    print("%-20s:%s" % ("HIDE RE PATTERN", args.hr_filter))
    print()
    sleep(2)


def verbose(state, msg):
    if state == True:
        print("[!] verbose:", msg)


def prog_bar(args):
    """Progress bar"""

    # setting global variable bar because it will be called from other threads
    # every time bar is called, progress var increments is bar in 1
    global bar

    # starting alive_bar
    with alive_bar(args.request_total, title=f"Progress", enrich_print=False) as bar:
        while True:
            # stop thread if run_event not set
            if not args.run_event.is_set() and threading.active_count() <= 3:
                break
            
            sleep(0.1)


def fuzzing(args):
    """
    fuzzing do the next jobs
        - read line by line the specified wordlist (args.wordlist)
        - replaces every magic word (args.magic) in the HTTP request with the line read before
        - sends the HTTP request and filters output with status code, content length, server or matching patterns

    """

    global bar

    word = " "
    retry_counter = 0

    while args.run_event.is_set() and args.request_count < args.request_total:
        # iterating to next word only when retry_counter = 0
        if retry_counter == 0:
            with args.lock:
                word = quote(args.wordlist.readline().strip())

        # replacing magic word from url
        new_url = args.url.replace(args.magic, word)

        # replacing magic word from headers
        headers = str(args.headers)
        headers = headers.replace(args.magic, word).replace("'", '"')
        headers = json.loads(headers)

        headers.setdefault(
            "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        )
        headers.setdefault("Accept-Language", "en-US,en;q=0.5")
        headers.setdefault("Accept-Encoding", "gzip, deflate")
        headers.setdefault("Connection", "close")

        # setting user_agent if not specified
        headers.setdefault("User-Agent", args.user_agent)

        # setting json content type header if specified
        if args.json:
            headers.setdefault("Content-Type", "application/json")

        # random user agent
        if args.rand_user_agent == True:
            headers["User-Agent"] = random_choice(args.UserAgent_wordlist)

        # replacing magic word from cookies
        cookies = str(args.cookies)
        cookies = cookies.replace(args.magic, word).replace("'", '"')
        cookies = json.loads(cookies)

        # replacing magic word from body data
        body_data = None
        if args.http_method == "POST":
            body_data = args.body_data
            body_data = body_data.replace(args.magic, word)

        # forming payload
        payload = ""
        if args.magic in args.url:
            payload = "%-40s" % (new_url.replace(" ", ""))
        if args.magic in str(args.headers):
            payload = "%-s - %-20s" % (payload, str(headers).replace(" ", ""))
        if args.magic in str(args.cookies):
            payload = "%-s - %-20s" % (payload, str(cookies).replace(" ", ""))
        if args.magic in str(args.body_data):
            payload = "BODY_DATA_FUZZ -> " + word
            #payload = "%-s - %-20s" % (payload, body_data.replace(" ", ""))
        
        try:
            req = requests.request(
                method=args.http_method,
                url=new_url,
                data=body_data,
                timeout=int(args.timeout),
                allow_redirects=args.follow,
                proxies=args.proxies,
                cookies=cookies,
                headers=headers,
            )


            # calling bar to increment bar progress
            with args.lock:
                bar()
                args.request_count += 1
                args.words_requested.append(word)

        except (socket.error, requests.ConnectTimeout):
            if args.ignore_errors:
                args.request_count += 1
                args.words_requested.append(word)
                bar()
                continue

            if retry_counter < args.retries:
                retry_counter += 1
                args.screenlock.acquire()
                print(
                    f" {AsciiColors.WARNING}// Retrying connection PAYLOAD[{payload}] retries[{retry_counter}] {AsciiColors.ENDC}"
                )
                args.screenlock.release()
                continue

            args.run_event.clear()
            show_error(
                f"Error stablishing connection  PAYLOAD[{payload}]", f"function::{currentframe().f_code.co_name}"
            )
        
        sleep(1)
        retry_counter = 0

        # in case server didnt send back content length and server info

        req.headers.setdefault("Content-Length", len(req.content))
        req.headers.setdefault("Server", "UNK")

        # using hide filters
        if args.hs_filter != None or args.hc_filter != None or args.hw_filter != None or args.hr_filter != None:
            if response_filter(args.hs_filter, args.hc_filter, args.hw_filter, args.hr_filter, req) == False:
                output_string = (
                    f"{AsciiColors.OKGREEN}PAYLOAD{AsciiColors.ENDC}[{AsciiColors.HEADER}%-100s{AsciiColors.ENDC}]" % (payload[:100])
                    + " "
                )
                output_string += f"{AsciiColors.OKGREEN}SC{AsciiColors.ENDC}[%s]" % (req.status_code) + " "
                output_string += f"{AsciiColors.OKGREEN}CL{AsciiColors.ENDC}[%s]" % (req.headers["Content-Length"]) + " "
                output_string += f"{AsciiColors.OKGREEN}SERVER{AsciiColors.ENDC}[%s]" % (req.headers["Server"]) + " "
                args.screenlock.acquire()
                print(output_string)
                args.screenlock.release()

                # write output to a file (log) if specified
                if args.output != None:
                    args.output.write(output_string)
        else:
            # if no filters specified, then prints everything
            output_string = (
                f"{AsciiColors.OKGREEN}PAYLOAD{AsciiColors.ENDC}[{AsciiColors.HEADER}%-110s{AsciiColors.ENDC}]" % (payload[:110]) + " "
            )
            output_string += f"{AsciiColors.OKGREEN}SC{AsciiColors.ENDC}[%s]" % (req.status_code) + " "
            output_string += f"{AsciiColors.OKGREEN}CL{AsciiColors.ENDC}[%s]" % (req.headers["Content-Length"]) + " "
            output_string += f"{AsciiColors.OKGREEN}SERVER{AsciiColors.ENDC}[%s]" % (req.headers["Server"]) + " "
            args.screenlock.acquire()
            print(output_string)
            args.screenlock.release()

            # write output to a file (log) if specified
            if args.output != None:
                args.output.write(output_string)

        

        # timewait
        sleep(args.timewait)

        with args.lock:
            if args.wordlist.tell() == args.wordlist.end_of_file:
                break

    return 0


def response_filter(hs_filter, hc_filter, hw_filter, hr_filter, response):
    filter_status = False
    # show filters
    if hs_filter != None:
        # show matching status code filter
        if str(response.status_code) in hs_filter:
            filter_status = True

    elif hc_filter != None:
        # show matching content length filter
        if response.headers["Content-Length"] != "UNK":
            if str(response.headers["Content-Length"]) in hc_filter:
                filter_status = True

    elif hw_filter != None:
        # show matching web server name filter
        if response.headers["Server"] in hw_filter:
            filter_status = True

    elif hr_filter != None:
        # show matching pattern filter
        # searching matching patterns in response headers
        matching = False

        for header in response.headers.keys():
            if re.search(hr_filter, str(response.headers[header])) is not None:
                matching = True
                break

        if matching == True:
            filter_status = True
        else:
            # searching matching patterns in response content
            aux = re.search(hr_filter, response.content.decode("latin-1"))
            if aux != None:
                filter_status = True

    return filter_status


def thread_starter(args):
    """this functions prepare and execute (start) every thread"""

    # initializating run_event to stop threads when required
    
    args.run_event.set()

    args.words_requested = []  # words already requested. used to avoid repeating the same request

    # creating thread lists
    thread_list = []
    # thread[0] is a specific thread for progress bar
    thread_list.append(threading.Thread(target=prog_bar, args=[args]))
    for _ in range(args.threads):
        thread_list.append(threading.Thread(target=fuzzing, args=[args]))

    # starting threads
    for i, thread in enumerate(thread_list): 
        thread.start()

        # giving thread[0] some time to set up progress bar global variables
        # in order to avoid calls to undefined variables from other threads
        if i == 0:
            sleep(0.3)

    exit_msg = ""
    try:
        # if a thread clean run_event variable, that means a error has happened
        # for that reason, all threads must stop and the program itself should stop too
        while args.run_event.is_set() and threading.active_count() > 3:
            sleep(0.4)

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
        thread_list[0].join()  # first thread of thread_list (prog_bar) should be the last one

    """ FOR DEBUGGING PURPOUSE
    with open("output.txt", "w") as file:
        for word in args.words_requested:
            file.write(f"{word}\n")
    """

    print(exit_msg)
    return exit_code


def main():
    banner()

    if "--usage" in argv:
        usage()

    parsed_arguments = parse_arguments()

    validate_arguments(parsed_arguments)

    initial_checks(parsed_arguments)

    if parsed_arguments.quiet == False:
        show_config(parsed_arguments)

    return thread_starter(parsed_arguments)


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        show_error("User Keyboard Interrupt", f"function::main")


##  FUNCIONALIDADES PARA AGREGAR
# TODO: Basic Auth
# TODO: Codificadores para los payloads
# TODO: Aceptar rangos de valores en los content length y status code
# TODO: implementar debug/verbose output
# TODO: refactorizar algunas funciones
# TODO: Si no se especifica retries, al primer fallo, o error de conexion, el programa va a terminarse
# TODO: al comparar el resultado con otras herramientas como gobuster, webFuzzer muestra resultados diferentes.
# TODO: actualizar usage
# TODO: si la ventana reduce su tamano, el formato de salida se va a estropear.
# TODO: implementar multiproceso combinado con multhilo
# TODO: mejorar el output cuando se reintenta una conexion o cuando ocurre un error de conexion 