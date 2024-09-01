#!/usr/bin/python3

import aiohttp
import asyncio
import argparse
import time
import re
from prettytable import PrettyTable
from inspect import currentframe
from urllib.parse import urlparse
from alive_progress import alive_bar
from colorama import Fore
from fake_useragent import UserAgent


MAGIC_WORD = "_FUZZ_"

class Config:
    """This class is simply to store parsed arguments"""

    def __init__(self):    

        parser = argparse.ArgumentParser(
            prog="./webFuzz.py",
            usage=f"./webFuzz.py [options] -u http://example.com/{MAGIC_WORD}/ -w /wordlist/path",
            description="a simple asynchronous python web fuzzer.",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        
        # General arguments
        parser.add_argument("-u", "--url", metavar="", required=True, help="Target url.",)
        parser.add_argument("-w", "--wordlist", metavar="", required=True, help="Path to the wordlist to use.")
        parser.add_argument("-m", "--http-method", metavar="", choices=["GET", "HEAD", "POST"], default="GET", help="HTTP method to use.")
        parser.add_argument("-H", "--http-headers", metavar="", help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-a", "--user-agent", metavar="", default="yoMamma", help="User-Agent to use in the HTTP request")
        parser.add_argument("-r", "--random-ua", action="store_true", help="Randomize user agent.")
        parser.add_argument("-c", "--cookies", metavar="", help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2")
        parser.add_argument("-b", "--body-data", metavar="", help="Body data to use in the HTTP POST request.")
        parser.add_argument("-p", "--proxy", metavar="", help="Proxy to use. Ex: http;http://localhost:8080")
        parser.add_argument("-x", "--extensions", metavar="", help="Add file extensions to every request. Ex: php,js,...")
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
        filters.add_argument("-hsc", "--hide-status-code", metavar="", help="Hide responses with the specified status code. Ex:[-hsc 404,400]")
        filters.add_argument("-hcl", "--hide-content-length", metavar="", help="Hide responses with the specified content length")
        filters.add_argument("-hws", "--hide-web-server", metavar="", help="Hide responses with the specified webserver")
        filters.add_argument("-hre", "--hide-regex", metavar="", help="Hide responses that match the specified expression")

        args = parser.parse_args()

        self.magic_word    = MAGIC_WORD

        self.url           = self.validate_url(args.url)
        self.wordlist_path = self.validate_wordlist(args.wordlist)
        self.extensions    = self.validate_extensions(args.extensions) if args.extensions else []
        self.add_slash     = args.add_slash
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
        self.timeout  = args.timeout
        self.timewait = args.timewait
        self.retries  = args.retries

        self.verbose = args.verbose
        self.output  = args.output
        self.quiet   = args.quiet 

        self.hide_status_code    = [404, 503] if args.hide_status_code is None else self.validate_status_codes(args.hide_status_code.split(","))
        self.hide_regex          = "" if args.hide_regex is None else args.hide_regex
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
        
        return result.geturl()
    
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
        print("=" * 100)
        print("[!] %13s: %-64s"%("URL", self.url))
        print("[!] %13s: %-64s"%("WORDLIST", self.wordlist_path))
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
     
async def fetch(session, url) -> None:
    """
    Make asynchronous HTTP requests to a URL provided as a parameter using an asynchronous session.

    Args:
        session (aiohttp.ClientSession): Asynchronous session used to make requests.
        url (str): The base URL that will be enumerated.

    Locks:
        This function uses a lock (config.lock) to protect the access to the list that contains words and the list that contains the results.
    """

    if config.http_method == "GET":
        http_request = session.get
    elif config.http_method == "POST":
        http_request = session.post

    while True:
        async with config.lock:
            try:
                # Yielding the next word of the wordlist generator
                path = url.replace(config.magic_word, next(config.wordlist)) #f"{url}{next(config.wordlist)}"
            except StopIteration:
                # stop loop if there is no more words in the wordlist generator
                break

        # local headers
        headers = {}            
        if config.random_ua:
            headers["User-Agent"] = config.dynamic_ua.random
        
        request_start_time = asyncio.get_event_loop().time()
        async with http_request(path, headers=headers, proxy=config.proxy) as resp:

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
                content = await resp.text()

                # checking that the response doesnt match with the hide_regex filter
                if config.hide_regex is not None and re.findall(config.hide_regex, content):
                    content_length = str(len(content))
                    content_type = resp.headers.get("content-type", "UNKNOWN")
                    server =  resp.headers.get('Server', 'UNKNOWN')

                    parsed_url  = urlparse(url)
                    result_fuzz = ""
                    if config.magic_word in parsed_url.netloc:
                        result_fuzz = urlparse(str(resp.url)).netloc
                    elif config.magic_word in parsed_url.path:
                        result_fuzz = urlparse(str(resp.url)).path
                    elif config.magic_word in parsed_url.params:
                        result_fuzz = urlparse(str(resp.url)).params
                    elif config.magic_word in parsed_url.query:
                        result_fuzz = urlparse(str(resp.url)).query
                    elif config.magic_word in parsed_url.fragment:
                        result_fuzz = urlparse(str(resp.url)).fragment

                    print("".join([
                        f"{Fore.CYAN}{result_fuzz:<80} ",
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

    connector = aiohttp.TCPConnector(ssl=config.verify_cert)
    timeout   = aiohttp.ClientTimeout(total=config.timeout)

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
            tasks = [fetch(session, config.url) for _ in range(config.tasks)]
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
    time.sleep(3)    

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[X] KeyBoard Interrupt...")
        print("[!] Finishing the program")
    
    
