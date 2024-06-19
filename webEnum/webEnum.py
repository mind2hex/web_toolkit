#!/usr/bin/python3
#      author: mind2hex
# description: simple web directory enumeration tool

import aiohttp
import asyncio
import argparse
from time import sleep
from inspect import currentframe
from urllib.parse import urlparse
from alive_progress import alive_bar


class Config:
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog="./webEnum.py",
            usage="./webEnum.py [options] -u {url} -w {wordlist}",
            description="a simple asynchronous python web directory enumerator",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        
        # General arguments
        parser.add_argument("-u", "--url", metavar="", required=True, help="Target url.",)
        parser.add_argument("-w", "--wordlist", metavar="", required=True, help="Path to the wordlist to use.")
        parser.add_argument("-M", "--http-method", metavar="", choices=["GET", "HEAD", "POST"], default="GET", help="HTTP method to use.")
        parser.add_argument("-H", "--http-headers", metavar="", help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-A", "--user-agent", metavar="", default="yoMamma", help="User-Agent to use in the HTTP request")
        parser.add_argument("-R", "--random-ua", action="store_true", help="Randomize user agent.")
        parser.add_argument("-C", "--cookies", metavar="", help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2")
        parser.add_argument("-b", "--body-data", metavar="", help="Body data to use in the HTTP POST request.")
        parser.add_argument("-P", "--proxy", metavar="", help="Proxy to use. Ex: http;http://localhost:8080")
        parser.add_argument("-x", "--extension", metavar="", help="Add file extensions to every request. Ex: php,js,...")
        parser.add_argument("-j", "--json", action="store_true", help="Use json formatted data in the HTTP POST request. ")
        parser.add_argument("-s", "--add-slash", action="store_true", help="Add slash to every request.")
        parser.add_argument("-f", "--follow", action="store_true", default=False, help="Follow HTTP redirections")
        parser.add_argument("-I", "--ignore-errors", action="store_true", help="Ignore script errors.")
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
        debug.add_argument("-d", "--debug", action="store_true", help="Enable debug mode.")
        debug.add_argument("-o", "--output", metavar="", type=str, help="Save output to a file.")
        debug.add_argument("-q", "--quiet", action="store_true", help="Supress banner and configuration printing.")

        # Filters arguments
        filters = parser.add_argument_group("filter options")
        filters.add_argument("-hsc", "--hide-status-code", metavar="", help="Hide responses with the specified status code. Ex:[-hsc 404,400]")
        filters.add_argument("-hcl", "--hide-content-length", metavar="", help="Hide responses with the specified content length")
        filters.add_argument("-hws", "--hide-web-server", metavar="", help="Hide responses with the specified webserver")
        filters.add_argument("-hre", "--hide-regex", metavar="", help="Hide responses that match the specified expression")

        args = parser.parse_args()

        self.url           = self.validate_url(args.url)
        self.wordlist      = self.validate_wordlist(args.wordlist)
        self.wordlist_path = args.wordlist
        self.http_method   = self.validate_http_method(args.http_method) if args.http_method else None
        self.http_headers  = self.validate_http_headers(args.http_headers) if args.http_headers else None
        self.user_agent    = self.validate_user_agent(args.user_agent) if args.user_agent else None
        self.random_ua     = args.random_ua
        self.cookies       = self.validate_cookies(args.cookies) if args.cookies else None
        self.body_data     = args.body_data
        self.proxy         = args.proxy
        self.extension     = args.extension
        self.json          = args.json
        self.add_slash     = args.add_slash
        self.follow        = args.follow
        self.ignore_errors = args.ignore_errors
        self.usage         = args.usage
        self.verify_cert   = args.verify_cert

        self.tasks    = args.tasks
        self.timeout  = args.timeout
        self.timewait = args.timewait
        self.retries  = args.retries
        self.lock     = asyncio.Lock()

        self.verbose = args.verbose
        self.debug   = args.debug
        self.output  = args.output
        self.quiet   = args.quiet 

        self.hide_status_code    = [404, 503] if args.hide_status_code is None else self.validate_status_codes(args.hide_status_code.split(","))
        #self.hide_content_length = [] if args.hide_content_length is None else self.validate_content_length(args.hide_content_length.split(","))
        #self.hide_web_server     = [] if args.hide_web_server is None else self.validate_web_server(args.hide_web_server.split(","))
        #self.hide_regex          = args.hide_regex
    
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
        if not result.endswith("/"):
            result += "/"
        return result
    
    def validate_wordlist(self, wordlist):
        """Validate the wordlist and return a list with the words contained inside the wordlist.

        This function do the following:
        - Check that the file exist and is readable.
        - Deletes repeated and empty words.

        Args:
            wordlist (str): Path of the wordlist to read.

        Returns:
            list: List containing the words inside wordlist.
        """
        try:
            wordlist_file = open(wordlist, 'r') 
        except:
            show_error(
                f"Invalid WORDLIST --> {wordlist}",
                f"function::{currentframe().f_code.co_name}",
                "error while trying to open the wordlist. Check that the wordlist exist",
            )
            exit(-1)

        result = set()
        for word in wordlist_file.readlines():
            word = word.strip()
            if word:
                result.add(word)
        
        return list(result)

    def validate_http_method(self, method):
        # no validations yet
        return method

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

        return status_codes
            
    def show_config(self):
        print("="*50)
        print("[!] %15s: %s"%("URL", self.url))
        print("[!] %15s: %s"%("WORDLIST", self.wordlist_path))
        print("[!] %15s: %s"%("METHOD", self.http_method))
        print("[!] %15s: %s"%("EXTENSIONS", self.extension))
        print("[!] %15s: %s"%("TASKS", self.tasks))
        print("[!] %15s: %s"%("TIMEOUT", self.timeout))
        print("="*50)
        print()


class AsciiColors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"


def show_error(error, origin, msg, ):
    print(f"{AsciiColors.FAIL}=================== ERROR ========================={AsciiColors.ENDC}")
    print(f" [X] Location: {origin} --> error")
    print(f" [X] {error}")
    print(f" [X] {msg}")
    print(f"{AsciiColors.FAIL}===================================================={AsciiColors.ENDC}")


async def fetch(session, url):
    while True:
        async with config.lock:
            # veryfing that there are words left to use
            if not config.wordlist:
                break

            # poping a word from worldist 
            path = f"{url}{config.wordlist.pop()}"

        async with session.get(path) as resp:
            if resp.status not in config.hide_status_code:
                print("[status_code: %-3s] -> [url: %s]" % (resp.status, resp.url))
        
        config.bar()


async def main():

    connector = aiohttp.TCPConnector(ssl=config.verify_cert)
    timeout   = aiohttp.ClientTimeout(total=config.timeout) 

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = [fetch(session, config.url) for _ in range(config.tasks)]
        await asyncio.gather(*tasks)

    
if __name__ == "__main__":
    config = Config()
    config.show_config()
    sleep(3)    

    with alive_bar(len(config.wordlist)) as bar:
        config.bar = bar
        asyncio.run(main())


# TODO:
