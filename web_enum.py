#!/usr/bin/python3

"""
web_enum.py

This script is responsible for enumerating web endpoints and resources.
It provides functionalities for handling wordlists, concurrent connections,
and saving results in html format.

Classes:
- Config: Class used to parse and store all CLI arguments.

Functions:
- main(): Entry point for the script.
- enumerator(): Main functionality of the script.
...

Usage:
    python web_enum.py [options]
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
            prog="./web_enum.py",
            usage="./web_enum.py [options] -u {url} -w {wordlist}",
            description="a simple asynchronous web directory enumerator",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        self.parse_general_arguments(parser)
        self.parse_performance_arguments(parser)
        self.parse_debug_arguments(parser)
        self.parse_filter_arguments(parser)

        args = parser.parse_args()

        self.general = {
            "url": args.url,
            "wordlist": args.wordlist,
            "extensions": args.extensions,
            "add_slash": args.add_slash,
            "http_method": args.http_method,
            "http_headers": args.http_headers,
            "user_agent": args.user_agent,
            "random_ua": args.random_ua,
            "cookies": args.cookies,
            "body_data": args.body_data,
            "proxy": args.proxy,
            "json": args.json,
            "follow": args.follow,
            "verify_cert": args.verify_cert,

            # used to generate random user agents
            "dynamic_ua": UserAgent(),

            # tasks will run until while this variable is True
            "exec_status": True 
        }
        self.performance = {
            "tasks": args.tasks,
            "timeout": args.timeout,
            "timewait": args.timewait,
            "retries": args.retries
        }
        self.debug = {
            "verbose": args.verbose,
            "output": args.output,
            "quiet": args.quiet,

            # table used to save results in diferent formats
            "table": PrettyTable(
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
        }
        self.filters = {
            "hide_status_code": args.hide_status_code,
            "hide_regex": args.hide_regex
        }

        # create wordlist generator to yield words instead of loading all words to memory
        word_count = self.count_lines(self.general['wordlist'].name)
        self.general['wordlist'] = {
            "path": self.general['wordlist'].name,
            "generator": self.wordlist_generator(
                self.general['wordlist'].name, self.general['extensions'], self.general['add_slash']
            ),
            "count": word_count + (word_count * len(self.general['extensions'])),
        }

        # setting static headers to simulate a normal browser.
        if self.general['user_agent']:
            self.general['http_headers'].setdefault("User-Agent", self.general['user_agent'])
        else:
            self.general['http_headers'].setdefault("User-Agent", self.general['dynamic_ua'].random)
        self.general['http_headers'].setdefault(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        )
        self.general['http_headers'].setdefault("Accept-Language", "en-US,en;q=0.5")
        self.general['http_headers'].setdefault("Accept-Encoding", "gzip")
        self.general['http_headers'].setdefault("Connection", "keep-alive")
        self.general['http_headers'].setdefault("Upgrade-Insecure-Requests", "1")
        self.general['http_headers'].setdefault("Sec-Fetch-Dest", "document")
        self.general['http_headers'].setdefault("Sec-Fetch-Mode", "navigate")
        self.general['http_headers'].setdefault("Sec-Fetch-Site", "none")
        self.general['http_headers'].setdefault("Sec-Fetch-User", "?1")
        self.general['http_headers'].setdefault("Cache-Control", "max-age")
        if self.general['json']:
            self.general['http_headers'].setdefault("Content-Type", "application/json")

        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock = asyncio.Lock()

    def parse_general_arguments(self, parser) -> None:
        """
        Adds general argument options to the provided argument parser.

        This method defines and adds a set of general arguments to an `argparse.ArgumentParser` 
        instance. These arguments include options for specifying the target URL, wordlist, HTTP 
        method, custom headers, user-agent settings, proxy configurations, and more.

        Args:
            parser (argparse.ArgumentParser): The argument parser instance to which 
                                            the general arguments will be added.
        """
        # General arguments
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
            type=self.key_value_pairs_type,
            help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2",
        )
        parser.add_argument(
            "-b",
            "--body-data",
            metavar="",
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
            "--usage", action="store_true", help="Print usage message"
        )
        parser.add_argument(
            "-V",
            "--verify-cert",
            action="store_true",
            help="Verify SSL certificates. Default -> False",
        )

    def parse_performance_arguments(self, parser) -> None:
        """
        Adds performance-related argument options to the provided argument parser.

        This method creates a group of performance-related arguments within the 
        provided `argparse.ArgumentParser` instance. These options control various 
        performance aspects such as the number of concurrent tasks, request timeout, 
        wait time between requests, and the number of retries for failed requests.

        Args:
            parser (argparse.ArgumentParser): The argument parser instance to which 
                                            the performance arguments will be added.
        """
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

    def parse_debug_arguments(self, parser) -> None:
        """
        Adds debugging and logging argument options to the provided argument parser.

        This method creates a group of debugging-related arguments within the provided 
        `argparse.ArgumentParser` instance. These options enable verbose mode, specify 
        output file paths, and control the display of banners and configuration information.

        Args:
            parser (argparse.ArgumentParser): The argument parser instance to which 
                                            the debugging arguments will be added.
        """
        # Debugging arguments
        debug = parser.add_argument_group("debugging options")
        debug.add_argument(
            "-v", "--verbose", action="store_true", help="Enable verbose mode."
        )
        debug.add_argument(
            "-o",
            "--output",
            metavar="",
            type=str,
            help="Save output to a file.",
        )
        debug.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Supress banner and configuration printing.",
        )

    def parse_filter_arguments(self, parser) -> None:
        """
        Adds filtering options to the provided argument parser.

        This method creates a group of filtering-related arguments within the provided 
        `argparse.ArgumentParser` instance. These options allow the user to filter HTTP 
        responses based on status codes, content length, web server type, or regular expressions.

        Args:
            parser (argparse.ArgumentParser): The argument parser instance to which 
                                            the filter arguments will be added.
        """
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

    def key_value_pairs_type(self, value) -> list:
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

    async def wordlist_generator(
        self, wordlist_path, ext=None, add_slash=False
    ):
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

                    if ext:
                        for x in ext:
                            yield f"{word}.{x}"

                    if add_slash and not word.endswith("/"):
                        yield f"{word}/"

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
        exclude = ["dynamic_ua", "table", "lock", "user_agent", "exec_status"]
        options = {}
        options.update(self.general)
        options.update(self.performance)
        options.update(self.debug)
        options.update(self.filters)
        options = dict(sorted(options.items(), reverse=True))  # sorting options
        print("=" * 100)
        for attr, value in options.items():
            if attr in exclude or not value:
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
    config.general['exec_status'] = False
    sys.exit(0)


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


async def enumerator(session, url, progress) -> None:
    """
    Perform asynchronous HTTP requests to enumerate resources at the specified URL.

    Args:
        session (aiohttp.ClientSession): The asynchronous session used to make HTTP requests.
        url (str): The base URL to be enumerated.
        progress (alive_progress.core.progress.__AliveBarHandle): Progress bar.

    This function repeatedly sends requests to paths generated from a wordlist, using
    a specified HTTP method (GET or POST). It processes and filters the responses based
    on status codes and content, and prints and stores relevant information for later use.

    The function is designed to handle retries for timeouts and connection errors, and 
    tracks progress with a progress bar. It stops when the wordlist is exhausted or 
    the execution status is set to False.

    Locks:
        A lock (`config.lock`) is used to ensure safe access to shared resources, including 
        the wordlist generator and the result table.

    Returns:
        None
    """

    # http method specified by user
    http_methods = {
        "GET": session.get,
        "POST": session.post
    }

    while config.general['exec_status']:
        async with config.lock:
            try:
                # Yielding the next word of the wordlist generator
                path = f"{url}{await anext(config.general['wordlist']['generator'])}"
            except StopAsyncIteration:
                # stop loop if there is no more words in the asynchronous wordlist generator
                break

        response = await try_request(http_methods[config.general['http_method']], path)

        # checking that the response doesnt match with the hide_regex filter
        if response['request_state']:
            if config.filters['hide_regex'] is None or not re.findall(
                config.filters['hide_regex'], response['content']
            ):
                if response['status_code'] in range(200, 300):
                    sc_color = Fore.GREEN
                elif response['status_code'] in range(300, 400):
                    sc_color = Fore.BLUE
                elif response['status_code'] in range(400, 599):
                    sc_color = Fore.RED
                else:
                    sc_color = Fore.YELLOW

                print(
                    "".join(
                        [
                            f"{Fore.CYAN}{response['target_path']:<50} ",
                            f"{sc_color}[SC: {response['status_code']:<3}] ",
                            f"{Fore.MAGENTA}[CL: {response['content_length']:>5}] ",
                            f"{Fore.BLUE}[RT: {response['response_time']:>5}] ",
                            f"{Fore.WHITE}[SRV: {response['server']:>10}] ",
                            f"{Fore.GREEN}{response['content_type']}{Fore.RESET} ",
                        ]
                    )
                )

                async with config.lock:
                    config.debug['table'].add_row(
                        [
                            response['target_path'],
                            response['status_code'],
                            response['content_length'],
                            response['response_time'],
                            response['server'],
                            response['content_type'],
                        ]
                    )

        # increasing bar count by 1
        progress()


async def try_request(http_request, path) -> dict:
    """
    Attempt to make an asynchronous HTTP request and return the result.

    Args:
        http_request (Callable): The HTTP request method (e.g., session.get or session.post).
        path (str): The URL path to request.

    Returns:
        dict: A dictionary containing the result of the request, with keys:
            - "request_state" (bool): Whether the request was successful.
            - "status_code" (str): The HTTP status code of the response.
            - "content_length" (str): The length of the response content.
            - "response_time" (str): The time taken to receive the response.
            - "target_path" (str): The path of the requested URL.
            - "server" (str): The server information from the response headers.
            - "content_type" (str): The content type of the response.

    Retries the request based on the configured number of retries in case of failures.
    The function handles specific exceptions related to asyncio and aiohttp, and logs
    relevant warning messages on errors.

    Exceptions handled:
        - asyncio.TimeoutError
        - aiohttp.client_exceptions.ClientConnectionError
        - aiohttp.client_exceptions.ClientError
        - aiohttp.client_exceptions.ClientResponseError
    """
    result = {
        "request_state": False,
        "status_code": "",
        "content_length": "",
        "response_time": "",
        "target_path": "",
        "server": "",
        "content_type": ""
    }

    request_start_time = asyncio.get_event_loop().time()
    for _ in range(config.performance['retries'] + 1):
        try:
            async with http_request(
                path,
                data=config.general['body_data'] if not config.general['json'] else None,
                json=config.general['body_data'] if config.general['json'] else None,
                headers=config.general['http_headers'],
                cookies=config.general['cookies'],
                proxy=(
                    config.general['proxy'].geturl() if config.general['proxy'] else None
                ),
                allow_redirects=config.general['follow']
            ) as resp:

                # checking that the response is not included in the hide_status_code filter

                if resp.status not in config.filters['hide_status_code']:
                    request_end_time = asyncio.get_event_loop().time()

                    # getting data from response
                    content = await resp.text(errors="ignore")
                    result['response_time'] = (
                        f"{request_end_time - request_start_time:.2f}"
                    )
                    result['target_path'] = urlparse(str(resp.url)).path
                    result['status_code'] = resp.status
                    result['content_length'] = str(len(content))
                    result['content_type'] = resp.headers.get(
                        "content-type", "UNKNOWN"
                    )
                    result['server'] = resp.headers.get("Server", "UNKNOWN")

                    # DATA EXTRACTED SUCCESFULLY
                    result['request_state'] = True

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

        break

    return result


async def main():
    """
    Main entry point for the asynchronous enumeration process.

    This function configures the HTTP client session and the progress bar, then coordinates 
    the enumeration tasks by distributing them across asynchronous workers. The enumeration 
    is performed using the `enumerator` function, and progress is tracked using the configured 
    progress bar.

    Upon completion, the function records the elapsed time for the process and optionally 
    saves the results to a specified output file.

    The function manages resource cleanup and ensures that all asynchronous operations 
    complete before exiting.

    Configuration:
        - Client session with custom timeout, connection limits, and SSL verification settings.
        - Progress bar setup with a calibration and display title.
        - Wordlist-based URL enumeration with parallel tasks.

    Returns:
        None
    """

    # client session configuration
    client_session = aiohttp.ClientSession(
        # timeout config
        timeout=aiohttp.ClientTimeout(total=config.performance['timeout']),
        # connection config
        connector=aiohttp.TCPConnector(
            # max asynchronous connections to host
            limit=config.performance['tasks'],
            limit_per_host=config.performance['tasks'],
            # (bool) Verify or not SSL certification
            ssl=config.general['verify_cert'],
            # IDK
            force_close=True,
        ),
    )

    # progress bar configuration
    progress_bar = alive_bar(
        config.general['wordlist']["count"],
        enrich_print=False,
        title="Processing",
        calibrate=200,
    )

    print_timestamp("Starting at")
    start_time = time.time()

    with progress_bar as progress:
        url = config.general["url"].geturl()
        async with client_session as session:
            tasks = [
                enumerator(session, url if url.endswith("/") else f"{url}/", progress)
                for _ in range(config.performance['tasks'])
            ]
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
    if config.debug["output"]:
        async with config.lock:
            with open(config.debug["output"], "w", encoding="utf-8") as f:
                f.write(config.debug['table'].get_formatted_string("html"))


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

# - Implement concurrent connections controls. (number of concurrent connexions, timewaits, etc).
# - Implement saving result functionality in json format.
# - Implement adaptative connections to avoid being blocked.
