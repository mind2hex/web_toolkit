#!/usr/bin/python3

import aiohttp
import aiofiles
import asyncio
import argparse
import time
import re
from prettytable import PrettyTable
from inspect import currentframe
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
        parser.add_argument("-w", "--wordlist", metavar="", required=True, help="Path to the wordlist to use. REQUIRED.")
        parser.add_argument("-m", "--http-method", metavar="", choices=["GET", "POST"], default="GET", help="HTTP method to use.")
        parser.add_argument("-H", "--http-headers", metavar="", type=self.key_value_pairs_type, help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-a", "--user-agent", metavar="", default="webEnum", help="User-Agent to use in the HTTP request")
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
        self.wordlist_path = self.validate_wordlist(args.wordlist)
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
        

        # create wordlist generator to yield words instead of loading all words to memory
        self.wordlist       = self.wordlist_generator(self.wordlist_path, self.extensions, self.add_slash)
        self.wordlist_count = self.count_lines(self.wordlist_path)
        self.wordlist_count = self.wordlist_count + (self.wordlist_count * len(self.extensions))

        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock     = asyncio.Lock()

        # dynamic user agent for random user generation
        self.dynamic_ua = UserAgent()
        
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

    def validate_wordlist(self, wordlist_path: str) -> str:
        """simply checks that the wordlist exist and is accessible...

        Args:
            wordlist_path (str): path to the wordlist.

        Returns:
            str: returns the path of the wordlist if checks passed successfully.
        """
        try:
            open(wordlist_path, 'r')
        except FileNotFoundError:
            show_error(
                f"Invalid WORDLIST --> {wordlist_path}",
                f"function::{currentframe().f_code.co_name}",
                "error while trying to open the wordlist. Check that the wordlist exist",
            )
            exit(-1)
        
        except PermissionError:
            show_error(
                f"Invalid WORDLIST --> {wordlist_path}",
                f"function::{currentframe().f_code.co_name}",
                "Insufficient permissions to open the wordlist. Check that the current user has read access to the wordlist",
            )
            exit(-1)
        
        except IsADirectoryError:
            show_error(
                f"Invalid WORDLIST --> {wordlist_path}",
                f"function::{currentframe().f_code.co_name}",
                "The specified wordlist is a directory. You must specify a readable file.",
            )
            exit(-1)

        return wordlist_path

    def wordlist_generator(self, wordlist_path, extensions=None, add_slash=False):
        """generate a wordlist to yield words.

        Args:
            wordlist_path (str): Path to the wordlist to use.
            extensions (list, optional): Add extensions to every word in the wordlist. Defaults to [].
            add_slash (bool, optional): Add a slash to every word in the wordlist. Defaults to False.

        Yields:
            str: The next word iteration in the wordlist.
        """        

        wordlist_file = open(wordlist_path, 'r') 

        for word in wordlist_file.readlines():
            word = word.strip()
            if word:
                yield word

                if extensions:
                    for ext in self.extensions:
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
        exclude = ["dynamic_ua", "wordlist", "table", "lock",]
        print("=" * 100)
        for attr, value in self.__dict__.items():
            if not attr.startswith("_") and attr not in exclude and value is not None:
                print("[!] %13s: %-64s"%(attr, value))

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
     
    
async def fetch(session, url):
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

    # setting static headers.
    headers = {
        # keep the connection open after sending the request.
        "Connection": "keep-alive",

        # user agent specified by user or default.
        "User-Agent": config.user_agent,

        # force target to send the most recent version of the resource.
        "Cache-Control": "no-cache"
    }

    if config.json:
        headers["Content-Type"] = "application/json"

    while True:
        async with config.lock:
            try:
                # Yielding the next word of the wordlist generator
                path = f"{url}{next(config.wordlist)}"
            except StopIteration:
                # stop loop if there is no more words in the wordlist generator
                break
        
        # select a random user agent if specified by user
        if config.random_ua:
            headers["User-Agent"] = config.dynamic_ua.random

        data    = config.body_data if not config.json else None
        json    = config.body_data if config.json else None
        cookies = config.cookies
        proxy   = None if config.proxy is None else config.proxy.geturl()

        request_start_time = asyncio.get_event_loop().time()
        async with http_request(
            path, 
            data=data, 
            json=json, 
            headers=headers, 
            cookies=cookies,
            proxy=proxy) as resp:

            # checking that the response is not included in the hide_status_code filter
            if resp.status not in config.hide_status_code:

                request_end_time = asyncio.get_event_loop().time()
                response_time = f"{request_end_time - request_start_time:.2f}"

                if resp.status in range(200, 300):
                    sc_color = Fore.GREEN
                elif resp.status in range(300, 400):
                    sc_color = Fore.BLUE
                elif resp.status in range(400, 599):
                    sc_color = Fore.RED
                else:
                    sc_color = Fore.YELLOW

                # getting data from response
                content = await resp.text(errors="ignore")

                # checking that the response doesnt match with the hide_regex filter
                if config.hide_regex is None or not re.findall(config.hide_regex, content):
                    
                    content_length = str(len(content))
                    content_type = resp.headers.get("content-type", "UNKNOWN")
                    server =  resp.headers.get('Server', 'UNKNOWN')

                    print("".join([
                        f"{Fore.CYAN}{urlparse(str(resp.url)).path:<50} ",
                        f"{sc_color}[SC: {resp.status:<3}] ",
                        f"{Fore.MAGENTA}[CL: {content_length:>5}] ",
                        f"{Fore.BLUE}[RT: {response_time:>4}] ",
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

    connector = aiohttp.TCPConnector(
        ssl=config.verify_cert,
        force_close=True
    )
    timeout   = aiohttp.ClientTimeout(total=config.timeout)

    # client session configuration
    client_session =  aiohttp.ClientSession(
        timeout=timeout, 
        connector=connector
    )

    # progress bar configuration
    progress_bar = alive_bar(
        config.wordlist_count, 
        enrich_print=False,
        title="Processing",
        calibrate=200
    )

    print_timestamp("Starting at")
    start_time = time.time()

    with progress_bar as bar:
        config.bar = bar
        async with client_session as session:
            tasks = [fetch(session, config.url.geturl()) for _ in range(config.tasks)]
            
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
    # parsing arguments here to be accessible globally
    config = Config()
    config.show_config()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[X] KeyBoard Interrupt...")
        print("[!] Finishing the program")
    
    
# TODO:
# - Finish input validations
# - Improve redirection handling
# - Improve error handling to handle errors instead of finishing program at the first error ocurrence.
# - Implement asyncio.gather with return_exceptions=True to continue task execution in case on task fail.
# - Implement concurrent connections controls. (number of concurrent connexions, timewaits, etc).
# - Implement saving result functionality in json format.
# - Implement boxes to put messages in automatically.
# - Implement custom message for every HTTP STATUS CODE.
# - Implement a dynamic table formatting.

# FIXME:
