#!/usr/bin/python3


import aiohttp
import aiohttp.client_exceptions
import asyncio
import argparse
import time
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from colorama import Fore
from alive_progress import alive_it
from collections import defaultdict
from fake_useragent import UserAgent


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
        parser.add_argument("-D", "--depth", metavar="", type=int, default=3, help="Depth to search for links",)
        parser.add_argument("-m", "--http-method", metavar="", choices=["GET", "POST"], default="GET", help="HTTP method to use.")
        parser.add_argument("-N", "--netloc", action="store_true", help="Discard links with different netloc that the target url.",)
        parser.add_argument("-CN", "--custom-netloc", metavar="", type=self.regex_type, help="Specify a custom netloc. Different netlocs will be discarted.")
        parser.add_argument("-x", "--extensions", metavar="", default=[], type=self.extensions_type, help="Specify extension of files to download. Ex: pdf,txt,jpg",)
        parser.add_argument("-j", "--json", action="store_true", help="Use json formatted data in the HTTP POST request. ")
        parser.add_argument("-H", "--http-headers", metavar="", default={}, type=self.key_value_pairs_type, help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-a", "--user-agent", metavar="", help="User-Agent to use in the HTTP request")
        parser.add_argument("-c", "--cookies", metavar="", type=self.key_value_pairs_type, help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2")
        parser.add_argument("-b", "--body-data", metavar="", type=self.key_value_pairs_type, help="Body data to use in the HTTP POST request.")
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

        # parsing arguments
        self.url           = args.url
        self.depth         = args.depth
        self.http_method   = args.http_method
        self.netloc        = args.netloc
        self.custom_netloc = args.custom_netloc
        self.extensions    = args.extensions
        self.json          = args.json
        self.http_headers  = args.http_headers
        self.user_agent    = args.user_agent
        self.cookies       = args.cookies
        self.body_data     = args.body_data
        self.proxy         = args.proxy
        self.verify_cert   = args.verify_cert
        self.tasks           = args.tasks
        self.connect_timeout = args.connect_timeout
        self.read_timeout    = args.read_timeout
        self.output  = args.output
        self.quiet   = args.quiet 

        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock     = asyncio.Lock()

        # dynamic user agent for random user agent generation
        self.dynamic_ua = UserAgent()

        # this will contains all results that will saved to a file if specified.
        self.visited_urls = set()
        
        # setting static headers to simulate a normal browser.
        if self.user_agent:
            self.http_headers.setdefault("User-Agent", self.user_agent)
        else:
            self.http_headers.setdefault("User-Agent", self.dynamic_ua.random)
        self.http_headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
        self.http_headers.setdefault("Connection", "keep-alive" )
        self.http_headers.setdefault("Accept-Language", "en-US,en;q=0.5")
        self.http_headers.setdefault("Accept-Encoding", "gzip, deflate, br")
        self.http_headers.setdefault("Upgrade-Insecure-Requests", "1")
        self.http_headers.setdefault("Sec-Fetch-Dest", "document")
        self.http_headers.setdefault("Sec-Fetch-Mode", "navigate")
        self.http_headers.setdefault("Sec-Fetch-Site", "none")
        self.http_headers.setdefault("Sec-Fetch-User", "?1")
        self.http_headers.setdefault("Cache-Control", "no-cache")
        if self.json:
            self.http_headers.setdefault("Content-Type", "application/json")



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
        exclude = ["visited_urls", "lock", ]
        print("=" * 100)
        for attr, value in self.__dict__.items():
            if not attr.startswith("_") and attr not in exclude and value is not None:
                if attr == "hide_status_code":
                    print("[!] %13s: %s ..."%(attr, value[:10]))
                else:
                    print("[!] %13s: %-64s"%(attr, value))

        print("=" * 100)


def print_timestamp(msg=""):
    output_msg = f"{msg} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}"
    print("=" * 100)
    print(f"%-78s "%(output_msg))
    print("=" * 100)


def add_to_tree(tree, parts, url):
    if not parts:
        return
    part = parts.pop(0)
    
    if part not in tree:
        tree[part] = (defaultdict(dict), '')

    if parts:
        add_to_tree(tree[part][0], parts, url)
    else:
        tree[part] = (tree[part][0], url)


def build_tree(urls):
    tree = defaultdict(lambda: (defaultdict(dict), ''))
    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path_parts = [part for part in parsed_url.path.split('/') if part]
        add_to_tree(tree[domain][0], path_parts, url)
    return tree


def print_tree(tree, prefix='', is_last=True):
    pointers = ['├── ', '└── ']
    for i, (key, (subtree, full_url)) in enumerate(tree.items()):
        pointer = pointers[i == len(tree) - 1]
        print(f"{prefix}{pointer}{key} {Fore.GREEN}{full_url if full_url else ''}{Fore.RESET}")
        if subtree:
            new_prefix = prefix + ("    " if i == len(tree) - 1 else "│   ")
            print_tree(subtree, new_prefix, i == len(tree) - 1)


def show_urls_as_tree(urls):
    tree = build_tree(urls)
    print_tree(tree)


async def fetch_links(session, url, semaphore):
    """
    Make asynchronous HTTP requests to a URL provided as a parameter using an asynchronous session.

    Args:
        session (aiohttp.ClientSession): Asynchronous session used to make requests.
        url (str): The base URL that will be crawled.

    Locks:
        This function uses a lock (config.lock) to protect the access to the list that contains words and the list that contains the results.
    """

    # http method specified by user
    if config.http_method == "GET":
        http_request = session.get
    elif config.http_method == "POST":
        http_request = session.post

    url_extension = urlparse(url).path.split(".")[-1]
    async with semaphore:
        links = set()
        try:
            
            async with http_request(
                url,
                data=config.body_data if not config.json else None,
                json=config.body_data if config.json else None,
                headers=config.http_headers,
                cookies=config.cookies,
                proxy=None if config.proxy is None else config.proxy.geturl()
            ) as resp:
                
                if resp.status == 200:
                    content_type = resp.headers.get("Content-Type")

                    # reading response content only when it is a html document or if the user specified to download the file
                    if content_type.startswith("text/html") or url_extension in config.extensions:
                        try:
                            content = await resp.read()
                        except asyncio.TimeoutError:
                            print(f"Timeout while reading content from {url}")
                            return []

                    # parsing HTML document
                    if content_type.startswith("text/html"):

                        soup = BeautifulSoup(content, 'html.parser')
                        possible_sources = [
                            'a', 'link', 'img', 'script', 'iframe', 'embed', 
                            'object', 'source', 'video',  'audio', 'track', 
                            'area', 'base', 'meta'
                        ]

                        # extracting links from possible sources
                        for tag in soup.find_all(possible_sources):
                            href = tag.get("href") or tag.get("src") or tag.get("content") or tag.get("srcset") or tag.get("data")
                            if href:
                                full_url = urljoin(url, href)
                                parsed_link = urlparse(full_url)

                                # validating the obtained url
                                if parsed_link.netloc and parsed_link.scheme:
                                    links.add(parsed_link.geturl())

            # saving content of the request inside LOOT directory if the extension of url match one of the config.extensions
            if url_extension in config.extensions:
                
                # creating loot directory if not exist
                os.mkdir("./LOOT") if not os.path.exists("HOLA") else None

                # saving file only if it doesn't exist
                filename = urlparse(url).path.split("/")[-1]
                if not os.path.exists(f"./LOOT/{filename}"):
                    async with config.lock:
                        with open(f"./LOOT/{filename}", "wb") as file:
                            file.write(content)

        except aiohttp.ClientConnectionError as e:
            print(f"Connection error occurred for {url}: {str(e)}")
        except aiohttp.ClientError as e:
            print(f"HTTP request failed for {url}: {str(e)}")
        except asyncio.TimeoutError:
            print(f"Asyncio timeout error for {url}")


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
        print("[!] Program Finished by user...")
        print("[!] Finishing tasks.")
        tasks = asyncio.all_tasks()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        print("[!] Tasks finished.")

    finally:
        await client_session.close()
        show_urls_as_tree(list(config.visited_urls))


if __name__ == "__main__":
    config = Config()
    config.show_config()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Program terminated by user.")


# TODO:
# - Improve progress bar to show how many urls left to scan instead of showing progress of LEVELS
# - Add new visited URLs in fetch_urls functions instead
# - Implement more parsers to beautiful soup... Right now the only parser based in the content-type is the html.
# - Implement retries for every connection.

# FIXME:
# - Sometimes a simple connection timeout can make the program end. Fix this to be more reliable.