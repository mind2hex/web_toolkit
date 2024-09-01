#!/usr/bin/python3

"""
web_crawl.py

A Python script for asynchronous web crawling, designed to enumerate
and display content from web pages in a hierarchical tree format.

This script supports a wide range of customization options, including
specifying HTTP methods, depth of search, custom headers, proxies,
and more.

Modules:
- asyncio: Provides support for asynchronous operations.
- argparse: Handles command-line arguments parsing.
- logging: Facilitates event logging for debugging and monitoring.
- urllib.parse: Contains utilities for URL parsing and manipulation.
- collections: Provides specialized container datatypes.
- aiohttp: Supports asynchronous HTTP requests.
- bs4 (BeautifulSoup): Parses HTML and XML documents.
- alive_progress: Displays progress bars for long-running operations.
- colorama: Enables colored terminal text output.
- fake_useragent: Generates random User-Agent strings.

Classes:
- Config: Manages command-line argument parsing and stores configurations.

Functions:
- main(): The main entry point of the script, handles the crawling process.
- crawler(): Performs the asynchronous crawling of URLs.
- filter_links(): Filters and validates crawled URLs based on user settings.
- build_tree(): Constructs a hierarchical tree of URLs from crawled data.
- print_tree(): Prints the hierarchical URL tree to the console.
- show_urls_as_tree(): Displays the URLs in a tree format.
- signal_handler(): Handles system signals for graceful script termination.
- setup_logger(): Configures and returns a logger instance.
- print_timestamp(): Prints a message with a timestamp to the console.

Usage:
    python web_crawl.py [options]

Example:
    python web_crawl.py -u https://example.com -D 5 -m GET
"""

import asyncio
import argparse
import time
import re
import logging
import os
import signal
from urllib.parse import urlparse, urljoin, ParseResult
from collections import defaultdict
import aiohttp
import aiohttp.client_exceptions
from bs4 import BeautifulSoup
from alive_progress import alive_it
from colorama import Fore
from fake_useragent import UserAgent


class Config:
    """
    Handles the parsing and storage of command-line arguments.

    This class manages the configuration of the web crawler by parsing
    command-line arguments and storing them in structured attributes.
    It also sets default HTTP headers and manages asynchronous locks.

    Attributes:
        general (dict): Stores general configurations such as URL, depth, HTTP method, etc.
        performance (dict): Stores performance-related configurations like task limits and timeouts.
        debug (dict): Stores debugging configurations like output options and visited URLs.

    Methods:
        parse_general_arguments(parser): Parses general command-line arguments.
        parse_performance_arguments(parser): Parses performance-related arguments.
        parse_debug_arguments(parser): Parses debugging and output-related arguments.
        url_type(url): Validates and parses a URL string.
        regex_type(regex): Validates and returns a regular expression string.
        extensions_type(extensions): Converts a comma-separated string of file extensions into list.
        key_value_pairs_type(value): Parses a comma-separated string of key-value into a dictionary.
        show_config(): Displays the current configuration settings in a readable format.
    """

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog="./web_crawl.py",
            usage="./web_crawl.py [options] -u {url}",
            description="a simple asynchronous python web crawler",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )

        self.parse_general_arguments(parser)
        self.parse_performance_arguments(parser)
        self.parse_debug_arguments(parser)

        args = parser.parse_args()

        # parsing arguments
        self.general = {
            "url": args.url,
            "depth": args.depth,
            "http_method": args.http_method,
            "netloc": args.netloc,
            "custom_netloc": args.custom_netloc,
            "extensions": args.extensions,
            "json": args.json,
            "http_headers": args.http_headers,
            "user_agent": args.user_agent,
            "cookies": args.cookies,
            "body_data": args.body_data,
            "proxy": args.proxy,
            "verify_cert": args.verify_cert,
            # used to generate random user agents
            "dynamic_ua": UserAgent(),
            "exec_status": True,
        }
        self.performance = {
            "tasks": args.tasks,
            "connect_timeout": args.connect_timeout,
            "read_timeout": args.read_timeout,
        }
        self.debug = {
            "output": args.output,
            "quiet": args.quiet,
            # this will contains all results that will saved to a file if specified.
            "visited_urls": set(),
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
        Parse general command-line arguments for the web crawler.

        This method adds general options to the argument parser, such as
        the target URL, search depth, HTTP method, and custom headers.

        Args:
            parser (argparse.ArgumentParser): The argument parser to which the options are added.

        Returns:
            None
        """
        parser.add_argument(
            "-u",
            "--url",
            metavar="",
            type=self.url_type,
            required=True,
            help="Target url.",
        )
        parser.add_argument(
            "-D",
            "--depth",
            metavar="",
            type=int,
            default=3,
            help="Depth to search for links",
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
            "-N",
            "--netloc",
            action="store_true",
            help="Discard links with different netloc that the target url.",
        )
        parser.add_argument(
            "-CN",
            "--custom-netloc",
            metavar="",
            type=self.regex_type,
            help="Specify a custom netloc. Different netlocs will be discarted.",
        )
        parser.add_argument(
            "-x",
            "--extensions",
            metavar="",
            default=[],
            type=self.extensions_type,
            help="Specify extension of files to download. Ex: pdf,txt,jpg",
        )
        parser.add_argument(
            "-j",
            "--json",
            action="store_true",
            help="Use json formatted data in the HTTP POST request. ",
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
            "-V",
            "--verify-cert",
            action="store_true",
            help="Verify SSL certificates. Default -> False",
        )

    def parse_performance_arguments(self, parser) -> None:
        """
        Parse performance-related command-line arguments.

        This method adds options to the argument parser related to the
        performance of the web crawler, including task limits and timeouts.

        Args:
            parser (argparse.ArgumentParser): The argument parser to which options are added.

        Returns:
            None
        """
        performance = parser.add_argument_group("performance options")
        performance.add_argument(
            "-t",
            "--tasks",
            metavar="",
            type=int,
            default=50,
            help="Total number of tasks. Default 50 tasks",
        )
        performance.add_argument(
            "-ct",
            "--connect-timeout",
            metavar="",
            type=int,
            default=30,
            help="Max time in seconds to connect to a server. Default 30 seconds",
        )
        performance.add_argument(
            "-rt",
            "--read-timeout",
            metavar="",
            type=int,
            default=30,
            help="Max time in seconds to read a response. Default 30 seconds",
        )

    def parse_debug_arguments(self, parser) -> None:
        """
        Parse debugging and output-related command-line arguments.

        This method adds options to the argument parser that control
        debugging, output, and verbosity settings.

        Args:
            parser (argparse.ArgumentParser): The argument parser to which options are added.

        Returns:
            None
        """
        debug = parser.add_argument_group("debugging options")
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

    def url_type(self, url) -> ParseResult:
        """
        Validate and parse a URL string.

        This method validates the format of a provided URL string and
        parses it into its components using `urlparse`. If the URL is
        invalid, an `ArgumentTypeError` is raised.

        Args:
            url (str): The URL string to validate and parse.

        Raises:
            argparse.ArgumentTypeError: If the provided URL is not valid.

        Returns:
            ParseResult: The parsed components of the URL.
        """
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            raise argparse.ArgumentTypeError(f"'{url}' is not a valid url.")

        return parsed_url

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

    def extensions_type(self, extensions: str) -> list:
        """
        Convert a comma-separated string of file extensions into a list.

        This method takes a string of file extensions, separates them by
        commas, and returns them as a list. It also validates the format.

        Args:
            extensions (str): A comma-separated string of file extensions.

        Raises:
            argparse.ArgumentTypeError: If the input string is invalid or empty.

        Returns:
            list: A list of file extensions.
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

        This method converts a string containing key-value pairs separated
        by commas into a dictionary, validating the format as it does so.

        Args:
            value (str): A string of key-value pairs (e.g., "Key1=Value1").

        Raises:
            argparse.ArgumentTypeError: If the input string is not in the correct key-value format.

        Returns:
            dict: A dictionary of parsed key-value pairs.
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

    def show_config(self) -> None:
        """
        Display the current configuration settings.

        This method prints the configuration options stored in the `Config`
        object, excluding certain attributes, and formats them for readability.

        Returns:
            None
        """
        exclude = ["dynamic_ua", "lock", "user_agent", "visited_urls"]
        options = {}
        options.update(self.general)
        options.update(self.performance)
        options.update(self.debug)
        options = dict(
            sorted(options.items(), reverse=True)
        )  # sorting options
        print("=" * 100)
        for attr, value in options.items():
            if attr in exclude or not value:
                continue

            if attr == "url":
                print(f"[!] {attr:>15s}: {value.geturl():64s}")
            elif attr == "wordlist":
                print(f"[!] {'wordlist_path':>15s}: {value['path']:64s}")
                print(
                    f"[!] {'wordlist_count':>15s}: {str(value['count']):64s}"
                )
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


def print_timestamp(msg="") -> None:
    """
    Print a timestamped message to the console.

    This function prints a message with a timestamp to the console
    and logs the message using the configured logger.

    Args:
        msg (str, optional): The message to print before the timestamp. Defaults to an empty string.

    Returns:
        None
    """
    output_msg = (
        f"{msg} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}"
    )
    print("=" * 100)
    logger.info(output_msg)
    print("=" * 100)


def add_to_tree(tree, parts, url) -> None:
    """
    Recursively add URL parts to the hierarchical tree structure.

    This function builds a nested dictionary representing the structure
    of URLs by recursively adding parts of the URL path.

    Args:
        tree (defaultdict): The tree structure to which URL parts are added.
        parts (list): The list of URL parts to add.
        url (str): The full URL being added to the tree.

    Returns:
        None
    """
    if not parts:
        return
    part = parts.pop(0)

    if part not in tree:
        tree[part] = (defaultdict(dict), "")

    if parts:
        add_to_tree(tree[part][0], parts, url)
    else:
        tree[part] = (tree[part][0], url)


def build_tree(urls) -> defaultdict :
    """
    Build a hierarchical tree of URLs.

    This function creates a nested dictionary structure representing
    the hierarchy of the provided URLs.

    Args:
        urls (list): A list of URLs to include in the tree.

    Returns:
        defaultdict: A nested dictionary representing the URL tree.
    """
    tree = defaultdict(lambda: (defaultdict(dict), ""))
    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path_parts = [part for part in parsed_url.path.split("/") if part]
        add_to_tree(tree[domain][0], path_parts, url)
    return tree


def print_tree(tree, prefix=""):
    """
    Print a hierarchical tree of URLs to the console.

    This function recursively prints the structure of URLs in a tree
    format, using indentation to represent the hierarchy.

    Args:
        tree (defaultdict): The tree structure of URLs to print.
        prefix (str, optional): A string to prefix each line of the tree. Defaults to "".

    Returns:
        None
    """
    pointers = ["├── ", "└── "]
    for i, (key, (subtree, full_url)) in enumerate(tree.items()):
        pointer = pointers[i == len(tree) - 1]
        print(
            f"{prefix}{pointer}{key} {Fore.GREEN}{full_url if full_url else ''}{Fore.RESET}"
        )
        if subtree:
            new_prefix = prefix + ("    " if i == len(tree) - 1 else "│   ")
            print_tree(subtree, new_prefix)


def show_urls_as_tree(urls) -> None:
    """
    Display a list of URLs as a hierarchical tree.

    This function builds and prints a tree structure from a list of
    URLs, showing the hierarchy of their paths.

    Args:
        urls (list): A list of URLs to display as a tree.

    Returns:
        None
    """
    tree = build_tree(urls)
    print_tree(tree)


async def crawler(session, url, semaphore) -> list:
    """
    Orchestrates the crawling process for a given URL.

    This function coordinates the crawling of a URL by:
    - Checking if the crawling should continue based on execution status.
    - Fetching the content of the URL using an asynchronous HTTP request.
    - Extracting links if the content is an HTML document.
    - Saving the content if it matches specific file extensions.

    Args:
        session (aiohttp.ClientSession): The asynchronous session used to make requests.
        url (str): The URL to crawl.
        semaphore (asyncio.Semaphore): A semaphore to limit concurrent requests.

    Returns:
        list: A list of links extracted from the crawled URL.
    """
    if not config.general["exec_status"]:
        return []

    links = set()
    async with semaphore:
        try:
            request_result = await fetch_content(session, url)
            if request_result["content"]:
                if request_result["is_html_document"]:
                    links = extract_links(request_result["content"], url)

                if request_result["should_download"]:
                    await save_content_if_needed(request_result["content"], url)
        except ConnectionResetError:
            logging.warning(f"ConnectionResetError: {url}")
        except aiohttp.client_exceptions.ClientConnectionError:
            logging.warning(f"AIOHTTP ConnectionError: {url}")
        except aiohttp.client_exceptions.ClientResponseError:
            logging.warning(f"AIOHTTP ClientResponseError: {url}")
        except aiohttp.client_exceptions.ClientError:
            logging.warning(f"AIOHTTP ClientError: {url}")

    return list(links)


async def fetch_content(session, url):
    """
    Fetches content from a given URL using an asynchronous HTTP request.

    This function retrieves content from the specified URL, determining
    whether the content is an HTML document and whether it should be downloaded 
    based on its file extension.

    Args:
        session (aiohttp.ClientSession): The asynchronous session used to make requests.
        url (str): The URL to fetch.

    Returns:
        dict: A dictionary containing:
              - "is_html_document" (bool): Whether the content is an HTML document.
              - "should_download" (bool): Whether the content should be downloaded.
              - "content" (bytes): The content retrieved from the URL, if any.
    """
    http_methods = {
        "GET": session.get,
        "POST": session.post
    }

    result = {
        "is_html_document": False,
        "should_download": False,
        "content": ""
    }

    url_extension = urlparse(url).path.split(".")[-1]
    async with http_methods[config.general['http_method']](
        url,
        data=config.general['body_data'] if not config.general['json'] else None,
        json=config.general['body_data'] if config.general['json'] else None,
        headers=config.general['http_headers'],
        cookies=config.general['cookies'],
        proxy=(config.general['proxy'].geturl() if config.general['proxy'] else None),
    ) as resp:
        if resp.ok:
            if (
                resp.headers.get("Content-Type").startswith("text/html")
                or url_extension in config.general["extensions"]
            ):
                result["content"] = await resp.read()
                result["is_html_document"] = resp.headers.get("Content-Type").startswith("text/html")
                result["should_download"] = url_extension in config.general["extensions"]
    return result


def extract_links(content, url):
    """
    Extracts all relevant links from HTML content.

    This function parses the HTML content to find and return all relevant links
    based on a set of predefined HTML tags that typically contain URLs.

    Args:
        content (bytes): The HTML content to parse.
        url (str): The base URL used to resolve relative links.

    Returns:
        set: A set of extracted URLs.
    """
    links = set()
    soup = BeautifulSoup(content, "html.parser")
    possible_sources = [
        "a", "link", "img", "script", "iframe", "embed", "object",
        "source", "video", "audio", "track", "area", "base", "meta",
    ]

    for tag in soup.find_all(possible_sources):
        href = (
            tag.get("href")
            or tag.get("src")
            or tag.get("content")
            or tag.get("srcset")
            or tag.get("data")
        )
        if href:
            full_url = urljoin(url, href)
            parsed_link = urlparse(full_url)
            if parsed_link.netloc and parsed_link.scheme:
                links.add(parsed_link.geturl())
    return links


async def save_content_if_needed(content, url):
    """
    Saves content to the LOOT directory if it matches specified file extensions.

    This function checks if the URL's file extension matches any of the specified
    extensions. If it does, the content is saved to a local directory named "LOOT".

    Args:
        content (bytes): The content to save.
        url (str): The URL from which the content was fetched.

    Returns:
        None
    """

    loot_dir = "./LOOT"
    if not os.path.exists(loot_dir):
        os.mkdir(loot_dir)

    filename = urlparse(url).path.split("/")[-1]
    file_path = os.path.join(loot_dir, filename)

    if not os.path.exists(file_path):
        async with config.lock:
            with open(file_path, "wb") as file:
                file.write(content)


def filter_links(links) -> list:
    """
    Filter and validate a list of links based on user settings.

    This function filters out links that have already been visited or
    do not match the specified netloc or custom netloc.

    Args:
        links (list): The list of links to filter.

    Returns:
        list: A filtered list of links that meet the specified criteria.
    """
    results = []
    for link in links:
        # discard all links already visited
        if link in config.debug["visited_urls"]:
            continue

        # discard all links obtained with different netloc if specified by user.
        if (
            config.general["netloc"]
            and config.general["url"].netloc != urlparse(link).netloc
        ):
            continue

        # discard all netlocs different from the netloc specified by the user.
        if config.general["custom_netloc"]:
            match = re.search(
                config.general["custom_netloc"], urlparse(link).netloc
            )
            if not match:
                continue

        # adding link to visited_urls
        config.debug["visited_urls"].add(link)

        results.append(link)

    return results


def signal_handler(sig, frame) -> None:
    """
    Handle system signals to gracefully exit the program.

    This function logs a warning message when a termination signal is
    received, sets the execution status to `False`, and exits the program.

    Args:
        sig (int): The signal number received.
        frame (frame): The current stack frame (not used).

    Returns:
        None
    """
    logger.warning(f"Signal {sig} received, finishing program...")
    config.general["exec_status"] = False


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


async def main():
    """
    The main entry point of the script.

    This function initializes the client session, controls the crawling
    process using asynchronous tasks, and displays the results as a tree.

    Returns:
        None
    """

    # client session configuration
    client_session = aiohttp.ClientSession(
        # timeout config
        timeout=aiohttp.ClientTimeout(
            total=None,
            sock_connect=config.performance["connect_timeout"],
            sock_read=config.performance["read_timeout"],
        ),
        # connection config
        connector=aiohttp.TCPConnector(ssl=config.general["verify_cert"]),
    )

    async with client_session as session:
        semaphore = asyncio.Semaphore(
            config.performance["tasks"]
        )  # limiting concurrency
        links = [config.general["url"].geturl()]

        # alive progress bar initialization
        progress_bar = alive_it(range(config.general["depth"]))
        for depth in progress_bar:

            if not config.general["exec_status"]:
                break

            tasks = [crawler(session, x, semaphore) for x in links]
            results = await asyncio.gather(*tasks, return_exceptions=False)

            links = [link for sublist in results for link in sublist]

            # filtering links
            links = filter_links(links)

            progress_bar.title = f"CURRENT LEVEL {depth + 1}"
            progress_bar.text = f"URLs COLLECTED: {len(config.debug['visited_urls'])}"

    show_urls_as_tree(list(config.debug["visited_urls"]))


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


# TODO:
# - Improve progress bar to show how many urls left to scan instead of showing progress of LEVELS
# - Add new visited URLs in fetch_urls functions instead
# - Implement more parsers to beautiful soup...
# - Implement retries for every connection.

# FIXME:
# - Sometimes a simple connection timeout can make the program end. Fix this to be more reliable.
