#!/usr/bin/python3

import aiohttp
import asyncio
import argparse
import time
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from colorama import Fore
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
        parser.add_argument("-u", "--url", metavar="", type=self.url_type, required=True, help="Target url.",)
        parser.add_argument("-d", "--depth", metavar="", type=int, default=3, help="Depth to search for links",)
        parser.add_argument("-N", "--netloc", action="store_true", help="Discard links with different netloc that the target url.",)
        parser.add_argument("-CN", "--custom-netloc", metavar="", type=self.regex_type, help="Specify a custom netloc. Different netlocs will be discarted.")
        parser.add_argument("-x", "--extensions", metavar="", type=self.extensions_type, help="Specify extension of files to download. Ex: pdf,txt,jpg",)
        parser.add_argument("-H", "--http-headers", metavar="", type=self.key_value_pairs_type, help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-a", "--user-agent", metavar="", default="webCrawl", help="User-Agent to use in the HTTP request")
        parser.add_argument("-c", "--cookies", metavar="", type=self.key_value_pairs_type, help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2")
        parser.add_argument("-p", "--proxy", metavar="", type=self.url_type, help="Proxy to use. Ex: http;http://localhost:8080")
        parser.add_argument("-V", "--verify-cert", action="store_true", help="Verify SSL certificates. Default -> False")

        # Performance arguments
        performance = parser.add_argument_group("performance options")
        performance.add_argument("-t",  "--tasks", metavar="", type=int, default=50, help="Total number of tasks. Default 50 tasks")
        performance.add_argument("-ct", "--connect-timeout", metavar="", type=int, default=30, help="Max time in seconds to connect to a server. Default 30 seconds")
        performance.add_argument("-rt", "--read-timeout", metavar="", type=int, default=30, help="Max time in seconds to read a response. Default 30 seconds")

        # Debugging arguments
        debug = parser.add_argument_group("debugging options")
        debug.add_argument("-o", "--output", metavar="", type=str, help="Save output to a file.")
        debug.add_argument("-q", "--quiet", action="store_true", help="Supress banner and configuration printing.")

        args = parser.parse_args()

        self.url           = args.url
        self.depth         = args.depth
        self.netloc        = args.netloc
        self.custom_netloc = args.custom_netloc
        self.extensions    = args.extensions
        self.http_headers  = args.http_headers
        self.user_agent    = args.user_agent
        self.cookies       = args.cookies
        self.proxy         = args.proxy
        self.verify_cert   = args.verify_cert

        self.tasks           = args.tasks
        self.connect_timeout = args.connect_timeout
        self.read_timeout    = args.read_timeout

        self.output  = args.output
        self.quiet   = args.quiet 

        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock     = asyncio.Lock()

        # this will contains all results that will saved to a file if specified.
        self.visited_urls = set()

    def url_type(self, url):
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            raise argparse.ArgumentTypeError(f"'{url}' is not a valid url.")
        
        return parsed_url

    def regex_type(self, regex):
        try:
            re.compile(regex)
            return regex
        except re.error as e:
            raise argparse.ArgumentTypeError(f"'{regex}' is not a valid regular expression.")

    def extensions_type(self, extensions:str) -> list:
        separated_extensions = extensions.split(",")

        if not all(extensions):
            raise argparse.ArgumentTypeError(f"'{extensions}' invalid extensions format, use 'ext1,ext2,ext3'.")
        
        return separated_extensions

    def key_value_pairs_type(self, value) -> list:
        pairs_dict = {}
        try:
            pairs = value.split(',')
            for pair in pairs:
                key, val = pair.split('=')
                key = key.strip()
                val = val.strip()
                if not key or not val:
                    raise ValueError
                pairs_dict[key] = val
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' is not a valid key-value format. Use Key1=Value1,key2=value2...")
        
        return pairs_dict     

    def show_config(self):
        exclude = ["visited_urls", "lock",]
        print("=" * 100)
        for attr, value in self.__dict__.items():
            if not attr.startswith("_") and attr not in exclude and value is not None:
                print("[!] %13s: %-64s"%(attr, value))

        print("=" * 100)


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
    # global headers to use in all sessions
    headers = {
        "User-Agent": config.user_agent 
    }

    async with semaphore:
        links = set()
        # reading response content from the HTTP REQUEST 
        async with session.get(url, headers=headers) as resp:
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
        if config.extensions and not timeout:
            if not os.path.exists("./LOOT"):
                os.mkdir("./LOOT")
            
            if urlparse(url).path.split(".")[-1] in config.extensions:
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
        if config.netloc and config.url.netloc != urlparse(link).netloc:
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

    # client session configuration
    client_session =  aiohttp.ClientSession(
        timeout=timeout, 
        connector=connector,
    )

    try:
        async with client_session as session:
            semaphore = asyncio.Semaphore(config.tasks)  # limiting concurrency
            links = [config.url.geturl()]

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

    

    hierarchy = build_hierarchy(list(config.visited_urls))
    print_hierarchy(hierarchy)


if __name__ == "__main__":
    config = Config()
    config.show_config()
    asyncio.run(main())



# TODO:
# - Improve progress bar to show how many urls left to scan instead of showing progress of LEVELS
# - Add new visited URLs in fetch_urls functions instead
# - In the tree listing, add the url at the end of every entry.

# FIXME:
# - Sometimes a simple connection timeout can make the program end. Fix this to be more reliable.