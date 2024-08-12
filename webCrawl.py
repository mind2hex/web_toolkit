#!/usr/bin/python3

import aiohttp
import asyncio
import argparse
import time
import re
import os
from bs4 import BeautifulSoup
from inspect import currentframe
from urllib.parse import urlparse, urljoin
from colorama import Fore
from fake_useragent import UserAgent
from alive_progress import alive_it


class Config:
    """This class is simply to store parsed arguments"""

    def __init__(self):    
        parser = argparse.ArgumentParser(
            prog="./webEnum.py",
            usage="./webEnum.py [options] -u {url}",
            description="a simple asynchronous python web directory enumerator",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        
        # General arguments
        parser.add_argument("-u", "--url", metavar="", required=True, help="Target url.",)
        parser.add_argument("-d", "--depth", metavar="", type=int, default=3, help="Depth to search for links",)
        parser.add_argument("-D", "--download", metavar="", help="Specify extension of files to download or specify ALL. Ex: pdf,txt,jpg",)
        parser.add_argument("-N", "--netloc", action="store_true", help="Discard links with different netloc that the target url.",)
        parser.add_argument("-CN", "--custom-netloc", metavar="", help="Specify a custom netloc. Different netlocs will be discarted.")
        parser.add_argument("-m", "--http-method", metavar="", choices=["GET", "HEAD", "POST"], default="GET", help="HTTP method to use.")
        parser.add_argument("-H", "--http-headers", metavar="", help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-a", "--user-agent", metavar="", default="yoMamma", help="User-Agent to use in the HTTP request")
        parser.add_argument("-r", "--random-ua", action="store_true", help="Randomize user agent.")
        parser.add_argument("-c", "--cookies", metavar="", help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2")
        parser.add_argument("-b", "--body-data", metavar="", help="Body data to use in the HTTP POST request.")
        parser.add_argument("-p", "--proxy", metavar="", help="Proxy to use. Ex: http;http://localhost:8080")
        parser.add_argument("-j", "--json", action="store_true", help="Use json formatted data in the HTTP POST request. ")
        parser.add_argument("-f", "--follow", action="store_true", default=False, help="Follow HTTP redirections")
        parser.add_argument("-i", "--ignore-errors", action="store_true", help="Ignore script errors.")
        parser.add_argument("--usage", action="store_true", help="Print usage message")
        parser.add_argument("-V", "--verify-cert", action="store_true", help="Verify SSL certificates. Default -> False")

        # Performance arguments
        performance = parser.add_argument_group("performance options")
        performance.add_argument("-t",  "--tasks", metavar="", type=int, default=50, help="Total number of tasks. Default 50 tasks")
        performance.add_argument("-ct", "--connect-timeout", metavar="", type=int, default=30, help="Max time in seconds to connect to a server. Default 30 seconds")
        performance.add_argument("-rt", "--read-timeout", metavar="", type=int, default=30, help="Max time in seconds to read a response. Default 30 seconds")

        # Debugging arguments
        debug = parser.add_argument_group("debugging options")
        debug.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode.")
        debug.add_argument("-o", "--output", metavar="", type=str, help="Save output to a file.")
        debug.add_argument("-q", "--quiet", action="store_true", help="Supress banner and configuration printing.")

        args = parser.parse_args()

        self.url           = self.validate_url(args.url)
        self.depth         = args.depth
        self.netloc        = args.netloc
        self.custom_netloc = args.custom_netloc
        self.download      = self.validate_extensions(args.download) if args.download else None
        self.http_method   = args.http_method
        self.http_headers  = self.validate_http_headers(args.http_headers) if args.http_headers else None
        self.user_agent    = self.validate_user_agent(args.user_agent) if args.user_agent else None
        self.random_ua     = args.random_ua
        self.cookies       = self.validate_cookies(args.cookies) if args.cookies else None
        self.body_data     = args.body_data
        self.proxy         = self.validate_url(args.proxy) if args.proxy else None
        self.json          = args.json
        self.follow        = args.follow
        self.ignore_errors = args.ignore_errors
        self.usage         = args.usage
        self.verify_cert   = args.verify_cert

        self.tasks    = args.tasks
        self.connect_timeout = args.connect_timeout
        self.read_timeout    = args.read_timeout

        self.verbose = args.verbose
        self.output  = args.output
        self.quiet   = args.quiet 

        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock     = asyncio.Lock()

        # dynamic user agent for random user generation
        self.dynamic_ua = UserAgent()

        # this will contains all results that will saved to a file if specified.
        self.visited_urls = set()
    
    def validate_url(self, url):
        """Validate and return the url.

        This function do the following:
        - Check that the url contain the scheme and netloc

        Args:
            url (str): URL to validate.

        Returns:
            str: Parsed URL into <scheme>://<netloc>/<path>
        """
        try:
            result = urlparse(url)

            if not all([result.scheme, result.netloc]):
                raise ValueError
        except:
            show_error(
                f"Invalid URL --> {url}",
                f"function::{currentframe().f_code.co_name}",
                "try using a correct url format like http://google.com/",
            )
            exit(-1)
        result = f"{result.scheme}://{result.netloc}{result.path}"
        return result

    def validate_extensions(self, raw_extensions: str) -> list:
        """validate extensions following the format "php,js,txt" and 
        returns a list containing the extensions comma separated    

        Args:
            raw_extensions (str): the extensions supposed to follow the format "php,js,txt..."

        Returns:
            list: list containing the comma separated extensions.
        """

        extensions = raw_extensions.split(',')

        if len(extensions) == 0:
            show_error(
                "",
                f"function::{currentframe().f_code.co_name}",
                "Invalid extensions provided. Use -x php,txt,js,..."
            )
            exit(-1)

        for ext in extensions:
            if not ext.isalnum():
                show_error(
                    "",
                    f"function::{currentframe().f_code.co_name}",
                    "Invalid extensions provided. Use -x php,txt,js,..."
                )
                exit(-1)

        return extensions

    def validate_http_headers(self, headers):
        """validate headers specified by user and return a dict containing the validated and parsed headers.

        Args:
            headers (str): string containing the headers specified by the user with the format key1=value1,key2=value2...

        Returns:
            dict: dictionary containing headers. Headers = {KEY1:VALUE1}
        """

        result = dict()
        try:
            separated_headers = headers.split(",")
            for header in separated_headers:
                parts = header.split("=")

                # validating that the header contains a Key and value.
                if len(parts) != 2:
                    raise ValueError(f"Invalid http header format: {header}")
                
                key, value = parts[0].strip(), parts[1].strip()
                if not key or not value:
                    raise ValueError(f"Key or value of the header is empty: {header}")
                
                result[key] = value
                
        except Exception as e:
            show_error(
                str(e),
                f"function::{currentframe().f_code.co_name}",
                "invalid headers specified. Use -H Key1=Value1,Key2=Value...",
            )
            exit(-1)

        return result

    def validate_user_agent(self, user_agent):
        # no validations yet
        return user_agent

    def validate_status_codes(self, status_codes: list) -> list:
        """validate_status_codes check that the specified status code are in a correct format.

        This function checks:
            - the status code is a 3 digits number.
            - the status code is a integer.

        Args:
            status_codes (list): the list containing the status codes.

        Raises:
            ValueError: If the value of a status code is invalid.

        Returns:
            list: The list containing the status code to hide from the output.
        """
        result = list()
        try:        
            for sc in status_codes:
                if len(sc) != 3:
                    raise ValueError
                
                result.append(int(sc))
        except Exception as e:
            show_error(
                str(e),
                f"function::{currentframe().f_code.co_name}",
                "invalid status code filter specified. Use -hsc 400,401,500 "
            )
            exit(1)

        return result        

    def show_config(self):
        print("=" * 100)
        print("[!] %13s: %-64s"%("URL", self.url))
        print("[!] %13s: %-64s"%("METHOD", self.http_method))
        print("[!] %13s: %-64s"%("USER AGENT", self.user_agent))
        print("[!] %13s: %-64s"%("RANDOM UA", self.random_ua))
        print("[!] %13s: %-64s"%("EXTENSIONS", self.extensions))
        print("[!] %13s: %-64s"%("TASKS", self.tasks))
        print("[!] %13s: %-64s"%("TIMEOUT", self.timeout))
        print("[!] %13s: %-64s"%("HIDE STATUS", self.hide_status_code))
        print("=" * 100)


def show_error(error, origin, msg, ):
    print(f"{Fore.RED}=================== ERROR ========================={Fore.RESET}")
    print(f" [X] Location: {origin} --> error")
    print(f" [X] {error}")
    print(f" [X] {msg}")
    print(f"{Fore.RED}===================================================={Fore.RESET}")


def print_timestamp(msg=""):
    output_msg = f"{msg} {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}"
    print("=" * 100)
    print(f"%-78s "%(output_msg))
    print("=" * 100)


def add_to_hierarchy(hierarchy, parts):
    current_level = hierarchy
    for part in parts:
        if part not in current_level:
            current_level[part] = {}
        current_level = current_level[part]


def build_hierarchy(urls):
    hierarchy = {}
    for url in urls:
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip("/").split("/")
        full_parts = [parsed_url.netloc] + path_parts  # Asume que el dominio es parte de la jerarquía
        add_to_hierarchy(hierarchy, full_parts)
    return hierarchy


def print_hierarchy(hierarchy, prefix=''):
    items = list(hierarchy.items())
    for i, (key, sub_hierarchy) in enumerate(items):
        connector = '└── ' if i == len(items) - 1 else '├── '
        if sub_hierarchy:  # Si tiene subdirectorios, continua recursivamente
            new_prefix = prefix + ('    ' if connector.startswith('└') else '│   ')
            print(f"{prefix}{connector}{key}")
            print_hierarchy(sub_hierarchy, new_prefix)
        else:  # Si es un elemento final (sin subdirectorios)
            print(f"{prefix}{connector}{key}")


async def fetch_links(session, url, semaphore):
    async with semaphore:
        links = set()
        # reading response content from the HTTP REQUEST 
        async with session.get(url) as resp:
            timeout = False
            if resp.status == 200:
                try:
                    response_headers = resp.headers
                    content = await resp.read()
                except TimeoutError:
                    timeout = True

                # PARSING HTML DOCUMENTS
                if response_headers.get("Content-Type", "UNKNOWN").startswith("text/html") and not timeout:
                    soup = BeautifulSoup(content, 'html.parser')
                    possible_sources = [
                        'a', 'link', 'img', 
                        'script', 'iframe', 'embed', 
                        'object', 'source', 'video', 
                        'audio', 'track', 'area', 
                        'base', 'meta'
                    ]
                    
                    for tag in soup.find_all(possible_sources):
                        href = tag.get("href") or tag.get("src") or tag.get("content") or tag.get("srcset") or tag.get("data")
                        if href:
                            full_url = urljoin(url, href)
                            parsed_link = urlparse(full_url)

                            # validating that new_link contains scheme and netloc
                            if parsed_link.netloc and parsed_link.scheme:
                                links.add(parsed_link.geturl())
            
        # saving content to LOOT folder if the file extension match the user specified file extension
        if config.download and not timeout:
            if not os.path.exists("./LOOT"):
                os.mkdir("./LOOT")
            
            if urlparse(url).path.split(".")[-1] in config.download:
                filename = urlparse(url).path.split("/")[-1]
                if not os.path.exists(f"./LOOT/{filename}"):
                    async with config.lock:
                        with open(f"./LOOT/{filename}", "wb") as file:
                            file.write(content)

        return list(links)
    

def filter_links(links):
    results = list()
    for link in links:
        # discard all links already visited
        if link in config.visited_urls:
            continue

        # discard all links obtained with different netloc if specified by user.
        if config.netloc and urlparse(config.url).netloc != urlparse(link).netloc:
            continue
        
        # discard all netlocs different from the netloc specified by the user.
        if config.custom_netloc:
            match = re.search(config.custom_netloc, urlparse(link).netloc)
            if not match:
                continue
        
        # adding link to visited_urls
        config.visited_urls.add(link)

        results.append(link)

    return  results


async def main():
    connector = aiohttp.TCPConnector(ssl=config.verify_cert)
    timeout   = aiohttp.ClientTimeout(
        total=None, 
        sock_connect=config.connect_timeout,
        sock_read=config.read_timeout
    )

    # global headers to use in all sessions
    headers = {
        "User-Agent": config.user_agent 
    }

    # client session configuration
    client_session =  aiohttp.ClientSession(
        timeout=timeout, 
        connector=connector,
        headers=headers        
    )

    try:
        async with client_session as session:
            semaphore = asyncio.Semaphore(config.tasks)  # limiting concurrency
            links = [config.url]

            # alive progress bar initialization
            bar = alive_it(range(config.depth))  
            for depth in bar:
                tasks = [fetch_links(session, x, semaphore) for x in links]
                results = await asyncio.gather(*tasks)

                links = [link for sublist in results for link in sublist]
                
                # filt
                links = filter_links(links)

                bar.title = f"CURRENT LEVEL {depth + 1}"
                bar.text  = f"URLs COLLECTED: {len(config.visited_urls)}"

    except KeyboardInterrupt:
        print("Program Finished by user...")

    except Exception as e:
        print(f"Unknown error {e}")

    hierarchy = build_hierarchy(list(config.visited_urls))
    print_hierarchy(hierarchy)


if __name__ == "__main__":
    config = Config()
    asyncio.run(main())



# TODO:
# - Implement validation to config.custom_netloc because some user may input an invalid regex.
# - Improve progress bar to show how many urls left to scan instead of showing progress of LEVELS
# - Add new visited URLs in fetch_urls functions instead
# - In the tree listing, add the url at the end of every entry.

# FIXME:
# - Sometimes a simple connection timeout can make the program end. Fix this to be more reliable.