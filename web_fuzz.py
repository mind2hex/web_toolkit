#!/usr/bin/python3


"""
web_fuzz.py

Asynchronous web fuzzer designed for security testing of web applications.
It allows users to perform HTTP fuzzing attacks by sending a series of 
modified requests to target URLs, where each request potentially contains 
different input values to test the application's handling of edge cases and 
potential vulnerabilities.

The fuzzer supports a variety of configuration options via command-line 
arguments, enabling customization of request headers, methods, body data, and 
handling of cookies and proxies. It utilizes asynchronous I/O provided by 
`aiohttp` to handle multiple requests concurrently, significantly increasing 
the efficiency of the fuzzing process.

Key features:
- Asynchronous request handling using `aiohttp`.
- Support for both GET and POST request methods.
- Adjustable performance settings, such as the number of concurrent tasks 
  and request timeout.
- Detailed logging of request and response data to identify potential 
  vulnerabilities.

This script also provides utilities for handling signals and logging, ensuring 
graceful shutdowns and comprehensive reporting.

Examples of usage:
- Running a fuzz test with a wordlist: 
`./webFuzz.py -u http://example.com/_FUZZ_/ -w /path/to/wordlist.txt`

Please refer to the command-line help (`-h` option) for more detailed 
information on all available options.
"""


import asyncio
import argparse
import time
import re
import logging
import sys
import signal
from urllib.parse import urlparse, ParseResult
import aiohttp
import aiohttp.client_exceptions
import aiofiles
from prettytable import PrettyTable
from alive_progress import alive_bar
from colorama import Fore
from fake_useragent import UserAgent


class Config:
    """This class is simply to store parsed arguments"""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog="./webFuzz.py",
            usage="./webFuzz.py [options] -u http://example.com/{MAGIC_WORD}/ -w /wordlist/path",
            description="a simple asynchronous python web fuzzer.",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )

        self.add_arguments(parser)
        self.args = self.parse_arguments(parser)
        # tasks will run while this variable is True
        self.exec_status = True
        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock = asyncio.Lock()
        # table used to save results in diferent formats
        self.table = PrettyTable(
            field_names=[
                "URL",
                "STATUS CODE",
                "CONTENT-LENGTH",
                "RESPONSE TIME",
                "SERVER",
                "CONTENT-TYPE",
            ],
            align="l"
        )

    def add_arguments(self, parser) -> None:
        """
        Configures and adds CLI arguments to the parser.

        Args:
            parser (ArgumentParser): The parser for adding command-line options.
        """

        def add_general_arguments(parser):
            # General options
            parser.add_argument(
                "-u",
                "--url",
                metavar="",
                type=self.url_type,
                required=True,
                help="Target url. REQUIRED.",
            )
            parser.add_argument(
                "-w",
                "--wordlist",
                metavar="",
                type=argparse.FileType("r", encoding="latin-1"),
                required=True,
                help="Path to the wordlist to use. REQUIRED.",
            )
            parser.add_argument(
                "-m",
                "--http-method",
                metavar="",
                choices=["GET", "POST"],
                default="GET",
                help="HTTP method to use.",
            )
            parser.add_argument(
                "-M",
                "--magic-word",
                metavar="",
                default="_FUZZ_",
                help="Specify a magic word to fuzz. default: _FUZZ_",
            )
            parser.add_argument(
                "-H",
                "--http-headers",
                metavar="",
                default={},
                type=self.key_value_pairs_type,
                help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2",
            )
            parser.add_argument(
                "-a",
                "--user-agent",
                metavar="",
                help="User-Agent to use in the HTTP request",
            )
            parser.add_argument(
                "-r",
                "--random-ua",
                action="store_true",
                help="Randomize user agent.",
            )
            parser.add_argument(
                "-c",
                "--cookies",
                metavar="",
                default={},
                type=self.key_value_pairs_type,
                help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2",
            )
            parser.add_argument(
                "-b",
                "--body-data",
                metavar="",
                default={},
                type=self.key_value_pairs_type,
                help="Body data to use in the HTTP POST request.",
            )
            parser.add_argument(
                "-p",
                "--proxy",
                metavar="",
                type=self.url_type,
                help="Proxy to use. Ex: http;http://localhost:8080",
            )
            parser.add_argument(
                "-x",
                "--extensions",
                metavar="",
                default=[],
                type=self.extensions_type,
                help="Add file extensions to every request. Ex: php,js,...",
            )
            parser.add_argument(
                "-j",
                "--json",
                action="store_true",
                help="Use json formatted data in the HTTP POST request. ",
            )
            parser.add_argument(
                "-s",
                "--add-slash",
                action="store_true",
                help="Add slash to every request.",
            )
            parser.add_argument(
                "-f",
                "--follow",
                action="store_true",
                default=False,
                help="Follow HTTP redirections",
            )
            parser.add_argument(
                "-V",
                "--verify-cert",
                action="store_true",
                help="Verify SSL certificates. Default -> False",
            )

        def add_performance_arguments(parser):
            # Performance arguments
            performance = parser.add_argument_group("performance options")
            performance.add_argument(
                "-t",
                "--tasks",
                metavar="",
                type=int,
                default=1,
                help="How many tasks to use.",
            )
            performance.add_argument(
                "-to",
                "--timeout",
                metavar="",
                type=int,
                default=60,
                help=("Total number of seconds for the whole request."
                    "Very Low values can cause connection problems. "
                )
            )
            performance.add_argument(
                "-tw",
                "--timewait",
                metavar="",
                type=int,
                default=0,
                help="Time to wait between each request per thread.",
            )
            performance.add_argument(
                "-rt",
                "--retries",
                metavar="",
                type=int,
                default=1,
                help="Times to retry failed HTTP requests",
            )

        def add_debugging_arguments(parser):
            # Debugging arguments
            debug = parser.add_argument_group("debugging options")
            debug.add_argument(
                "-v", "--verbose", action="store_true", help="Enable verbose mode."
            )
            debug.add_argument(
                "-o",
                "--output",
                metavar="",
                type=argparse.FileType("w"),
                help="Specify file to store data.",
            )
            debug.add_argument(
                "-of",
                "--output-format",
                metavar="",
                default="text",
                choices=["text", "html", "json", "csv", "latex"],
                help="Format to store data.",
            )
            debug.add_argument(
                "-q",
                "--quiet",
                action="store_true",
                help="Supress banner and configuration printing.",
            )

        def add_filter_arguments(parser):
            # Filter arguments
            filters = parser.add_argument_group("filter options")
            filters.add_argument(
                "-hsc",
                "--hide-status-code",
                metavar="",
                default=[404, 503],
                type=self.status_code_type,
                help="Hide responses with the specified status code. Ex: -hsc 404,400",
            )
            filters.add_argument(
                "-hcl",
                "--hide-content-length",
                metavar="",
                help="Hide responses with the specified content length",
            )
            filters.add_argument(
                "-hws",
                "--hide-web-server",
                metavar="",
                help="Hide responses with the specified webserver",
            )
            filters.add_argument(
                "-hre",
                "--hide-regex",
                metavar="",
                type=self.regex_type,
                help="Hide responses that match the specified expression",
            )

        add_general_arguments(parser)
        add_performance_arguments(parser)
        add_debugging_arguments(parser)
        add_filter_arguments(parser)

    def parse_arguments(self, parser) -> argparse.Namespace:
        """
        Parse arguments and add additional info to the Parsed Namespace.

        Args:
            parser (ArgumentParser): The parser containing all the arguments.

        Returns:
            argparse.Namespace: Namespace containing all parsed arguments.
        """
        # converting args into a dictionary
        args = parser.parse_args()
        # dynamic user agent for random user generation
        args.dynamic_ua =  UserAgent()
        # create wordlist generator to yield words instead of loading all words to memory
        args.wordlist= {
            "path": args.wordlist.name,
            "generator": self.wordlist_generator(args.wordlist.name),
            "count": self.count_lines(args.wordlist.name),
        }
        # setting static headers to simulate a normal browser.
        user_agent = UserAgent()
        default_http_headers = {
            "User-Agent": args.user_agent if args.user_agent else user_agent.random,
            "Accept": ",".join([
                "text/html",
                "application/xhtml+xml",
                "application/xml;q=0.9",
                "image/webp",
                "image/apng",
                "*/*;q=0.8,"
            ]),
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age",
        }

        for header, value in default_http_headers.items():
            args.http_headers.setdefault(header, value)
        if args.json:
            args.http_headers["Content-Type"] = "application/json"

        return args

    def url_type(self, url) -> ParseResult:
        """
        Validates and parses a URL string.

        This method receives a URL as a string, validates its format, and parses it 
        into its components using `urlparse`. If the URL is invalid, an `ArgumentTypeError` 
        is raised.

        Args:
            url (str): The URL string to validate and parse.

        Raises:
            argparse.ArgumentTypeError: If the provided URL is not valid.

        Returns:
            ParseResult: The parsed components of the URL as returned by `urlparse`.
        """
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            raise argparse.ArgumentTypeError(f"'{url}' is not a valid url.")

        return parsed_url

    def extensions_type(self, extensions: str) -> list:
        """
        Convert a comma-separated string of file extensions into a list.

        Args:
            extensions (str): Comma-separated string of file extensions (e.g., "php,js,html").

        Raises:
            argparse.ArgumentTypeError: If any part of the input string is invalid or empty.

        Returns:
            list: A list of individual file extensions (e.g., ['php', 'js', 'html']).
        """
        separated_extensions = extensions.split(",")

        if not all(extensions):
            raise argparse.ArgumentTypeError(
                f"'{extensions}' invalid extensions format, use 'ext1,ext2,ext3'."
            )

        return separated_extensions

    def key_value_pairs_type(self, value) -> dict:
        """
        Parse a comma-separated string of key-value pairs into a dictionary.

        Args:
            value (str): Comma-separated string of key-value pairs (e.g., "Key1=Value1").

        Raises:
            argparse.ArgumentTypeError: If the input string is not in the correct key-value format.

        Returns:
            dict: A dictionary of parsed key-value pairs (e.g., {'Key1': 'Value1'}).
        """
        pairs_dict = {}
        try:
            pairs = value.split(",")
            for pair in pairs:
                key, val = pair.split("=")
                key = key.strip()
                val = val.strip()
                if not key or not val:
                    raise ValueError
                pairs_dict[key] = val
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"'{value}' is not a valid key-value format. Use Key1=Value1,key2=value2..."
            ) from exc

        return pairs_dict

    def status_code_type(self, value) -> list:
        """
        Parse a string representing HTTP status codes or ranges into a list of integers.

        Args:
            value (str): String of comma-separated status codes or ranges (e.g., "200,404,500-502").

        Raises:
            argparse.ArgumentTypeError: If the input string contains invalid status codes or ranges.

        Returns:
            list: A list of parsed HTTP status codes as integers (e.g., [200, 404, 500, 501, 502]).
        """
        result = []
        parts = value.split(",")
        for part in parts:
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    result.extend(range(start, end + 1))
                except ValueError as exc:
                    raise argparse.ArgumentTypeError(
                        f"'{value}' invalid format for -hsc, use -hsc '400-500,503'."
                    ) from exc
            else:
                try:
                    result.append(int(part))
                except ValueError as exc:
                    raise argparse.ArgumentTypeError(
                        f"'{value}' invalid format for -hsc, use -hsc '400-500,503'."
                    ) from exc

        return result

    def regex_type(self, regex) -> str:
        """
        Validate that a string is a properly formatted regular expression.

        Args:
            regex (str): The regular expression string to validate.

        Raises:
            argparse.ArgumentTypeError: If the string is not a valid regular expression.

        Returns:
            str: The validated regular expression string.
        """
        try:
            re.compile(regex)
            return regex
        except re.error as exc:
            raise argparse.ArgumentTypeError(
                f"'{regex}' is not a valid regular expression."
            ) from exc

    async def wordlist_generator(self, wordlist_path):
        """
        Generate words from a wordlist file, optionally adding extensions or slashes.

        Args:
            wordlist_path (str): Path to the wordlist file.
            ext (list, optional): List of extensions to append to each word. 
                Defaults to an empty list ([]).
            add_slash (bool, optional): If True, appends a slash to each word. 
                Defaults to False.

        Yields:
            str: The next word from the wordlist, possibly modified by extensions or slashes.
        """
        async with aiofiles.open(wordlist_path, "r") as wordlist_file:
            async for word in wordlist_file:
                word = word.strip()

                # ignoring lines that start with #
                if word.startswith("#") or word.isspace():
                    continue

                if word:
                    yield word

    def count_lines(self, wordlist_path: str) -> int:
        """
        Count the total number of lines in a file.

        Args:
            wordlist_path (str): Path to the file whose lines will be counted.

        Returns:
            int: The total number of lines in the file.
        """

        try:
            with open(wordlist_path, "rb") as f:
                return sum(1 for line in f)
        except FileNotFoundError:
            logger.warning(f"FileNotFoundError: {wordlist_path}. Retrying ")
            sys.exit(0)

    def show_config(self) -> None:
        """
        Display the current configuration settings.

        The method prints the configuration options, excluding certain attributes, 
        and formats them for readability.

        Excluded attributes: ["dynamic_ua", "table", "lock", "user_agent", "exec_status"]

        The configuration options are displayed in reverse-sorted order.

        Returns:
            None
        """
        exclude = ["dynamic_ua"]
        print("=" * 100)
        args = dict(sorted(vars(self.args).items(), reverse=True))
        for attr, value in args.items():
            if attr.startswith("_") or attr in exclude or not value:
                continue

            if attr == "url":
                print(f"[!] {attr:>15s}: {value.geturl():64s}" )
            elif attr == "wordlist":
                print(f"[!] {'wordlist_path':>15s}: {value['path']:64s}")
                print(f"[!] {'wordlist_count':>15s}: {str(value['count']):64s}")
            elif attr == "http_headers":
                print(f"[!] {attr:>15s}: ")
                for key in value:
                    print("-" * 10, f"{key:>25s}:{value[key]}")
            elif attr == "hide_status_code":
                if len(value) > 10:
                    print(f"[!] {attr:>15s}: {value[:5]}...{value[-5:]}")
                else:
                    print(f"[!] {attr:>15s}: {value}")
            else:
                print(f"[!] {attr:>15s}: {str(value):64s}")
        print("=" * 100)


def signal_handler(sig, frame) -> None:
    """
    Handle system signals to gracefully exit the program.

    Args:
        sig (int): The signal number received.
    
    This function logs a warning message indicating the signal received,
    sets the execution status to `False` in the global `config` object,
    and then exits the program with a status code of 0.

    When the execution status is False, all tasks will be terminated.
    """
    logger.warning(f"Signal {sig} received, finishing program...")
    config.exec_status = False


def print_timestamp(msg=""):
    """
    Print a timestamped message to the console.

    Args:
        msg (str, optional): The message to print before the timestamp. Defaults to an empty string.
    
    This function prints a message with a timestamp to the console,
    logs the message using the logger, and surrounds the message with 
    lines of equal signs for visual separation.
    """
    output_msg = (
        f"{msg} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}"
    )
    print("=" * 100)
    logger.info(output_msg)
    print("=" * 100)


def setup_logger() -> logging.Logger:
    """
    Set up and configure the logger for the application.

    Returns:
        logging.Logger: The configured logger instance.
    
    This function creates a logger named 'logger', sets its logging 
    level to DEBUG, adds a stream handler that also has a DEBUG level, 
    and configures a formatter for the log messages. The logger instance 
    is returned for use throughout the application.
    """
    script_logger = logging.getLogger("logger")
    script_logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ch.setFormatter(formatter)
    script_logger.addHandler(ch)
    return script_logger


async def fuzz(session, url, progress) -> None:
    """
    Executes the fuzzing process by sending asynchronous HTTP requests.

    This function loops through a wordlist, replacing a placeholder in the URL (or other
    request components) with each word, and sending the modified request via the
    provided session. It handles response filtering, updating progress, and storing results.

    Args:
        session (aiohttp.ClientSession): The session used to send HTTP requests.
        url (str): The base URL to which the fuzzing is applied.
        progress (callable): A function to update the progress of the fuzzing process.

    Locks:
        Utilizes an async lock to manage access to shared resources like the wordlist 
        and result table.
    """

    # available http methods
    http_methods = {
        "GET": session.get,
        "POST": session.post
    }

    while config.exec_status:
        async with config.lock:
            try:
                # Replacing magic word from  Yielding the next word of the wordlist generator
                next_word = await anext(config.args.wordlist["generator"])
            except StopAsyncIteration:
                # stop loop if there is no more words in the wordlist generator
                break

        response = await try_request(http_methods[config.args.http_method], url, next_word)

        filter_status = filter_response(response)

        if filter_status == 2:
            if response["status_code"] in range(200, 300):
                sc_color = Fore.GREEN
            elif response["status_code"] in range(300, 400):
                sc_color = Fore.BLUE
            elif response["status_code"] in range(400, 599):
                sc_color = Fore.RED
            else:
                sc_color = Fore.YELLOW

            parsed_url = urlparse(url)
            parsed_response_url = urlparse(str(response["url"]))
            result_fuzz = ""
            if config.args.magic_word in parsed_url.netloc:
                result_fuzz = parsed_response_url.netloc
            elif config.args.magic_word in parsed_url.path:
                result_fuzz = parsed_response_url.path
            elif config.args.magic_word in parsed_url.params:
                result_fuzz = parsed_response_url.params
            elif config.args.magic_word in parsed_url.query:
                result_fuzz = parsed_response_url.query
            elif config.args.magic_word in parsed_url.fragment:
                result_fuzz = parsed_response_url.fragment

            print("".join([
                f"{Fore.CYAN}{result_fuzz:<80} ",
                f"{sc_color}[SC: {response['status_code']:<3}] ",
                f"{Fore.MAGENTA}[CL: {str(len(response['content'])):>5}] ",
                f"{Fore.BLUE}[RT: {str(response['response_time']):>4}] ",
                f"{Fore.WHITE}[SRV: {response['server']:>10}] ",
                f"{Fore.GREEN}{response['content_type']}{Fore.RESET} "
            ]))
            async with config.lock:
                config.table.add_row([
                    result_fuzz,
                    response['status'],
                    len(response['content']),
                    response['response_time'],
                    response['server'],
                    response['content_type']
                ])

        # increasing bar count by 1
        progress()


async def try_request(http_method:str, url:str, next_word:str) -> dict:
    """
    Try a http request and return the response.

    Args:
        http_method (str): The http method to use in the http request.
        url (str): The url used as the target for the request.
        next_word (str): String used to replace all MAGIC WORD ocurrences.

    Returns:
        dict: Results of the request.
    """
    result = {
        "url": "",
        "status": False,
        "status_code": 0,
        "content": "",
        "response_time": 0,
        "server": "",
        "content_type": ""
    }

    # replacing MAGIC_WORD in the url
    path = url.replace(config.args.magic_word, next_word)

    # replacing MAGIC_WORD in headers
    headers = config.args.http_headers.copy()
    for key, value in headers.items():
        headers[key] = value.replace(config.args.magic_word, next_word)

    # replacing MAGIC_WORD in cookies
    cookies = config.args.cookies.copy()
    if cookies:
        for key, value in cookies.items():
            cookies[key] = value.replace(config.args.magic_word, next_word)

    # replacing MAGIC_WORD in body data
    data = config.args.body_data.copy()
    if data:
        for key, value in data.items():
            data[key] = value.replace(config.args.magic_word, next_word)

    # start time of the request
    request_start_time = asyncio.get_event_loop().time()
    for _ in range(config.args.retries + 1):
        try:
            async with http_method(
                path,
                data=data if not config.args.json else None,
                json=data if config.args.json else None,
                headers=headers,
                cookies=cookies,
                proxy=config.args.proxy.geturl() if config.args.proxy else None
            ) as resp:
                if resp.ok:
                    result["url"] = resp.url
                    result["status"] = resp.ok
                    result["content"] = await resp.text(errors="ignore")
                    result["status_code"] = resp.status
                    request_end_time = asyncio.get_event_loop().time()
                    result["response_time"] = (
                        f"{request_end_time - request_start_time:.2f}"
                    )
                    result["server"] = resp.headers.get("Server", "UNKNOWN")
                    result["content_type"] = resp.headers.get("Content-Type", "UNKNOWN")

            # request executed sucessfully, finishing for loop
            break
        except asyncio.TimeoutError:
            logger.warning(f"ASYNCIO TimeoutError: {path}. Retrying ")
            continue
        except aiohttp.client_exceptions.ClientConnectionError:
            logger.warning(f"AIOHTTP ConnectionError: {path}. Retrying ")
            continue
        except aiohttp.client_exceptions.ClientResponseError:
            logger.warning(f"AIOHTTP ClientResponseError: {path}. Retrying ")
            continue
        except aiohttp.client_exceptions.ClientError:
            logger.warning(f"AIOHTTP ClientError: {path}. Retrying ")
            continue

    return result


def filter_response(response:dict) -> int:
    """
    Evaluates a response against configured filters and determines its validity.

    This function applies two main filters: one for HTTP status codes and another 
    for content patterns using regular expressions. It increments the filter 
    status for each passed filter condition.

    Args:
        response (dict): The response dictionary containing 'status', 
        'status_code', and 'content' keys.

    Returns:
        int: The total number of filters the response has passed (0, 1, or 2).
    """

    filter_status = 0
    # checking that the response is not included in the hide_status_code filter
    if response["status"] and response["status_code"] not in config.args.hide_status_code:
        # status code filter passed
        filter_status += 1

    # checking that the response doesn't match with the regex specified by user
    if (
        config.args.hide_regex is not None
        and not re.findall(config.args.hide_regex, response["content"])
    ):
        # regex filter passed
        filter_status += 1
    elif config.args.hide_regex is None:
        # regex filter passed automatically cause is not specified
        filter_status += 1

    return filter_status


async def main():
    """
    Orchestrates the asynchronous web fuzzing process using configured settings.

    This function sets up the client session with timeout and SSL configurations,
    initializes a progress bar, and manages the lifecycle of fuzzing tasks, including
    starting, monitoring, and completing them. It calculates and displays the execution
    time and optionally saves results to a specified output file.
    """
    # client session configuration
    client_session = aiohttp.ClientSession(
        # timeout settings
        timeout=aiohttp.ClientTimeout(
            total=config.args.timeout
        ),
        # connection settings
        connector=aiohttp.TCPConnector(
            ssl=config.args.verify_cert
        )
    )

    # progress bar configuration
    progress_bar = alive_bar(
        config.args.wordlist["count"],
        enrich_print=False,
        title="Processing",
        calibrate=200
    )

    print_timestamp("Starting at")
    start_time = time.time()

    with progress_bar as progress:
        url = config.args.url.geturl()

        async with client_session as session:
            # creating tasks
            tasks = [
                fuzz(session, url, progress)
                for _ in range(config.args.tasks)
            ]

            # waiting until all tasks finish
            await asyncio.gather(*tasks)

    end_time = time.time()
    print_timestamp("Finishing at")

    real_time = end_time - start_time
    user_time = time.process_time()
    syst_time = real_time - user_time
    print(f"\nReal: {real_time:.2f}")
    print(f"User: {user_time:.2f}")
    print(f"Sys:  {syst_time:.2f}")

    # saving results to a file if specified
    if config.args.output:
        with config.args.output as file:
            file.write(
                # using the specified format
                config.table.get_formatted_string(config.args.output_format)
            )

# logger to show events in different levels
logger = setup_logger()

# parsing arguments here to be accessible globally
config = Config()
config.show_config()

# signal for program termination and program interruptions
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    asyncio.run(main())

# TODO: Implement --csrf-token type=hidden,name=user_token
# This will search for a tag with attributes type="hidden" name="user_token" and
# send it using
