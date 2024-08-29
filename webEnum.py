#!/usr/bin/python3

import aiohttp
import aiofiles
import asyncio
import argparse
import time
import re
import logging
import sys
import signal
import aiohttp.client_exceptions
from prettytable import PrettyTable
from urllib.parse import urlparse, ParseResult
from alive_progress import alive_bar
from colorama import Fore
from fake_useragent import UserAgent


class Config:
    """This class is simply to store parsed arguments"""

    def __init__(self):    
        parser = argparse.ArgumentParser(
            prog="./webEnum.py",
            usage="./webEnum.py [options] -u {url} -w {wordlist}",
            description="a simple asynchronous python web directory enumerator",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        
        # General arguments
        parser.add_argument("-u", "--url", metavar="", type=self.url_type, required=True, help="Target url. REQUIRED.",)
        parser.add_argument("-w", "--wordlist", metavar="", type=argparse.FileType('r', encoding='latin-1'), required=True, help="Path to the wordlist to use. REQUIRED.")
        parser.add_argument("-m", "--http-method", metavar="", choices=["GET", "POST"], default="GET", help="HTTP method to use.")
        parser.add_argument("-H", "--http-headers", metavar="", default={}, type=self.key_value_pairs_type, help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-a", "--user-agent", metavar="", help="User-Agent to use in the HTTP request")
        parser.add_argument("-r", "--random-ua", action="store_true", help="Randomize user agent.")
        parser.add_argument("-c", "--cookies", metavar="", type=self.key_value_pairs_type, help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2")
        parser.add_argument("-b", "--body-data", metavar="", type=self.key_value_pairs_type, help="Body data to use in the HTTP POST request.")
        parser.add_argument("-p", "--proxy", metavar="", type=self.url_type, help="Proxy to use. Ex: http;http://localhost:8080")
        parser.add_argument("-x", "--extensions", metavar="", default=[], type=self.extensions_type, help="Add file extensions to every request. Ex: php,js,...")
        parser.add_argument("-j", "--json", action="store_true", help="Use json formatted data in the HTTP POST request. ")
        parser.add_argument("-s", "--add-slash", action="store_true", help="Add slash to every request.")
        parser.add_argument("-f", "--follow", action="store_true", default=False, help="Follow HTTP redirections")
        parser.add_argument("-i", "--ignore-errors", action="store_true", help="Ignore script errors.")
        parser.add_argument("--usage", action="store_true", help="Print usage message")
        parser.add_argument("-V", "--verify-cert", action="store_true", help="Verify SSL certificates. Default -> False")

        # Performance arguments
        performance = parser.add_argument_group("performance options")
        performance.add_argument("-t",  "--tasks", metavar="", type=int, default=1, help="How many tasks to use.")
        performance.add_argument("-to", "--timeout", metavar="", type=int, default=60, help="Total number of seconds for the whole request. Very Low values can cause connection problems. ")
        performance.add_argument("-tw", "--timewait", metavar="", type=int, default=0, help="Time to wait between each request per thread.")
        performance.add_argument("-rt", "--retries", metavar="", type=int, default=0, help="Times to retry failed HTTP requests")

        # Debugging arguments
        debug = parser.add_argument_group("debugging options")
        debug.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode.")
        debug.add_argument("-o", "--output", metavar="", type=str, help="Save output to a file.")
        debug.add_argument("-q", "--quiet", action="store_true", help="Supress banner and configuration printing.")

        # Filters arguments
        filters = parser.add_argument_group("filter options")
        filters.add_argument("-hsc", "--hide-status-code", metavar="", default=[404,503], type=self.status_code_type, help="Hide responses with the specified status code. Ex: -hsc 404,400")
        filters.add_argument("-hcl", "--hide-content-length", metavar="", help="Hide responses with the specified content length")
        filters.add_argument("-hws", "--hide-web-server", metavar="", help="Hide responses with the specified webserver")
        filters.add_argument("-hre", "--hide-regex", metavar="", type=self.regex_type, help="Hide responses that match the specified expression")

        args = parser.parse_args()
        self.url           = args.url
        self.wordlist      = args.wordlist
        self.extensions    = args.extensions
        self.add_slash     = args.add_slash
        self.http_method   = args.http_method
        self.http_headers  = args.http_headers
        self.user_agent    = args.user_agent
        self.random_ua     = args.random_ua
        self.cookies       = args.cookies
        self.body_data     = args.body_data
        self.proxy         = args.proxy
        self.json          = args.json
        self.follow        = args.follow
        self.ignore_errors = args.ignore_errors
        self.usage         = args.usage
        self.verify_cert   = args.verify_cert

        self.tasks    = args.tasks
        self.timeout  = args.timeout
        self.timewait = args.timewait
        self.retries  = args.retries

        self.verbose = args.verbose
        self.output  = args.output
        self.quiet   = args.quiet 

        self.hide_status_code    = args.hide_status_code
        self.hide_regex          = args.hide_regex
        #self.hide_content_length = [] if args.hide_content_length is None else self.validate_content_length(args.hide_content_length.split(","))
        #self.hide_web_server     = [] if args.hide_web_server is None else self.validate_web_server(args.hide_web_server.split(","))
        
        # tasks will run until while this variable is True
        self.exec_status = True

        # create wordlist generator to yield words instead of loading all words to memory
        word_count = self.count_lines(self.wordlist.name)
        self.wordlist = {
            "path": self.wordlist.name,
            "generator": self.wordlist_generator(self.wordlist.name, self.extensions, self.add_slash),
            "count": word_count + (word_count * len(self.extensions))
        }

        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock     = asyncio.Lock()

        # dynamic user agent for random user generation
        self.dynamic_ua = UserAgent()

        # setting static headers to simulate a normal browser.
        if self.user_agent:
            self.http_headers.setdefault("User-Agent", self.user_agent)
        else:
            self.http_headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36")
        self.http_headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
        self.http_headers.setdefault("Accept-Language", "en-US,en;q=0.5")
        self.http_headers.setdefault("Accept-Encoding", "gzip")
        self.http_headers.setdefault("Connection", "keep-alive" )
        self.http_headers.setdefault("Upgrade-Insecure-Requests", "1")
        self.http_headers.setdefault("Sec-Fetch-Dest", "document")
        self.http_headers.setdefault("Sec-Fetch-Mode", "navigate")
        self.http_headers.setdefault("Sec-Fetch-Site", "none")
        self.http_headers.setdefault("Sec-Fetch-User", "?1")
        self.http_headers.setdefault("Cache-Control", "max-age")
        if self.json:
            self.http_headers.setdefault("Content-Type", "application/json")
        
        # This table will contain all the results from the web enumeration
        self.table = PrettyTable()
        self.table.field_names = ["URL", "STATUS CODE", "CONTENT-LENGTH", "RESPONSE TIME", "SERVER", "CONTENT-TYPE"]
        self.table.align = "l"

    def url_type(self, url) -> ParseResult:
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            raise argparse.ArgumentTypeError(f"'{url}' is not a valid url.")
        
        return parsed_url
    
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

    def status_code_type(self, value) -> list:
        result = []
        parts = value.split(',')
        for part in parts:
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    result.extend(range(start, end + 1))
                except ValueError:
                    raise argparse.ArgumentTypeError(f"'{value}' invalid format for -hsc, use -hsc '400-500,503'.")
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    raise argparse.ArgumentTypeError(f"'{value}' invalid format for -hsc, use -hsc '400-500,503'.")
        
        return result

    def regex_type(self, regex):
        try:
            re.compile(regex)
            return regex
        except re.error as e:
            raise argparse.ArgumentTypeError(f"'{regex}' is not a valid regular expression.")

    async def wordlist_generator(self, wordlist_path, extensions=None, add_slash=False):
        """generate a wordlist to yield words.

        Args:
            wordlist_path (str): Path to the wordlist to use.
            extensions (list, optional): Add extensions to every word in the wordlist. Defaults to [].
            add_slash (bool, optional): Add a slash to every word in the wordlist. Defaults to False.

        Yields:
            str: The next word iteration in the wordlist.
        """        
        async with aiofiles.open(wordlist_path, 'r') as wordlist_file:
            async for word in wordlist_file:
                word = word.strip()

                # ignoring lines that start with #
                if word.startswith("#") or word.isspace():
                    continue

                if word:
                    yield word

                    if extensions:
                        for ext in extensions:
                            yield f"{word}.{ext}"

                    if add_slash and not word.endswith("/"):
                        yield f"{word}/"

    def count_lines(self, wordlist_path:str) -> int:
        """count the lines of a file.

        Args:
            wordlist_path (str): path to the wordlist to read.

        Returns:
            int: total lines of the file.
        """
        with open(wordlist_path, 'rb') as f:
            return sum(1 for line in f)

    def show_config(self):
        exclude = ["dynamic_ua", "table", "lock", "user_agent"]
        print("=" * 100)
        for attr, value in self.__dict__.items():            
            if not attr.startswith("_") and attr not in exclude and value is not None and value:
                if attr == "url":
                    print("[!] %15s: %-64s"%(attr, value.geturl()))
                elif attr == "wordlist":
                    print("[!] %15s: %-64s"%("wordlist_path", value['path']))    
                    print("[!] %15s: %-64s"%("wordlist_count", value['count']))   
                elif attr == "http_headers":
                    print("[!] %15s: "%(attr))
                    for key in value:
                        print("-" * 10, "%-25s:%s"%(key, value[key]))
                elif attr == "hide_status_code":
                    if len(value) > 10:
                        print("[!] %15s: %s...%s"%(attr, value[:5], value[-5:]))
                    else:
                        print("[!] %15s: %-64s"%(attr, value))
                else:
                    print("[!] %15s: %-64s"%(attr, value))

        print("=" * 100)
        

def signal_handler(sig, frame):
    logger.warning(f"Signal {sig} received, finishing program...")
    config.exec_status = False
    sys.exit(0)


def print_timestamp(msg=""):
    output_msg = f"{msg} {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}"
    print("=" * 100)
    print(f"%-78s "%(output_msg))
    print("=" * 100)
     

def setup_logger() -> logging.Logger:
    logger = logging.getLogger('tool_logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


async def enumerator(session, url):
    """
    Make asynchronous HTTP requests to a URL provided as a parameter using an asynchronous session.

    Args:
        session (aiohttp.ClientSession): Asynchronous session used to make requests.
        url (str): The base URL that will be enumerated.

    Locks:
        This function uses a lock (config.lock) to protect the access to the list that contains words and the list that contains the results.
    """

    # http method specified by user
    if config.http_method == "GET":
        http_request = session.get
    elif config.http_method == "POST":
        http_request = session.post

    while config.exec_status:
        async with config.lock:
            try:
                # Yielding the next word of the wordlist generator
                path = f"{url}{await anext(config.wordlist['generator'])}"
            except StopAsyncIteration:
                # stop loop if there is no more words in the asynchronous wordlist generator
                break
        
        request_successful = False
        request_start_time = asyncio.get_event_loop().time()
        for _ in range(config.retries + 1):
            try:
                async with http_request(
                    path, 
                    data=config.body_data if not config.json else None, 
                    json=config.body_data if config.json else None, 
                    headers=config.http_headers, 
                    cookies=config.cookies,
                    proxy=None if config.proxy is None else config.proxy.geturl()
                ) as resp:
                    
                    # checking that the response is not included in the hide_status_code filter
                    
                    if resp.status not in config.hide_status_code:

                        # getting data from response
                        content = await resp.text(errors="ignore")
                        target_path    = urlparse(str(resp.url)).path
                        status_code    = resp.status 
                        content_length = str(len(content))
                        content_type   = resp.headers.get("content-type", "UNKNOWN")
                        server         = resp.headers.get('Server', 'UNKNOWN')

                        if resp.status in range(200, 300):
                            sc_color = Fore.GREEN
                        elif resp.status in range(300, 400):
                            sc_color = Fore.BLUE
                        elif resp.status in range(400, 599):
                            sc_color = Fore.RED
                        else:
                            sc_color = Fore.YELLOW

                        request_end_time = asyncio.get_event_loop().time()
                        response_time = f"{request_end_time - request_start_time:.2f}"

                        # DATA EXTRACTED SUCCESFULLY
                        request_successful = True

            except asyncio.TimeoutError:
                logger.warning(f"TimeoutError: {path}. Retrying ")
                continue

            except aiohttp.client_exceptions.ClientConnectionError:
                logger.warning(f"ConnectionError: {path}. Retrying ")
                continue

            except Exception as e:
                logger.error(f"UnknownError: {e}. Retrying")

            finally:                
                break

        # checking that the response doesnt match with the hide_regex filter
        
        if request_successful:
            if config.hide_regex is None or not re.findall(config.hide_regex, content):
            
                print("".join([
                    f"{Fore.CYAN}{target_path:<50} ",
                    f"{sc_color}[SC: {status_code:<3}] ",
                    f"{Fore.MAGENTA}[CL: {content_length:>5}] ",
                    f"{Fore.BLUE}[RT: {response_time:>5}] ",
                    f"{Fore.WHITE}[SRV: {server:>10}] ",
                    f"{Fore.GREEN}{content_type}{Fore.RESET} "
                ]))
                        
                async with config.lock:
                    config.table.add_row([
                        resp.url, 
                        resp.status, 
                        content_length, 
                        response_time, 
                        server, 
                        content_type
                    ])

        # increasing bar count by 1  
        config.bar()    


async def main():

    # client session configuration
    client_session =  aiohttp.ClientSession(
        # timeout config
        timeout=aiohttp.ClientTimeout(
            total=config.timeout
        ), 

        # connection config
        connector=aiohttp.TCPConnector(
            # (bool) Verify or not SSL certification
            ssl=config.verify_cert,

            # IDK
            force_close=True,
        )
    )

    # progress bar configuration
    progress_bar = alive_bar(
        config.wordlist['count'], 
        enrich_print=False,
        title="Processing",
        calibrate=200,
    )

    print_timestamp("Starting at")
    start_time = time.time()

    with progress_bar as bar:
        config.bar = bar
        url = config.url.geturl()
        async with client_session as session:
            tasks = [enumerator(session, url if url.endswith("/") else f"{url}/") for _ in range(config.tasks)]
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
    if config.output:
        async with config.lock:
            with open(config.output, "w") as f:
                f.write(config.table.get_formatted_string("html"))

    
if __name__ == "__main__":
    # logger to show events in different levels
    logger = setup_logger()

    # parsing arguments here to be accessible globally
    config = Config()
    config.show_config()

    # signal for program termination and program interruptions
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    asyncio.run(main())
    
    
# TODO:
# - Improve redirection handling
# - Improve error handling to handle errors instead of finishing program at the first error ocurrence.
# - Implement asyncio.gather with return_exceptions=True to continue task execution in case on task fail.
# - Implement concurrent connections controls. (number of concurrent connexions, timewaits, etc).
# - Implement saving result functionality in json format.


# FIXME:
