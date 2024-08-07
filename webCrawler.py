#!/usr/bin/python3
#      author: mind2hex
# description: simple web directory enumeration tool

from bs4 import BeautifulSoup
from django.core.validators import URLValidator
from inspect import currentframe
from sys import argv
from time import sleep
from urllib.parse import urlparse
from os import mkdir
from fake_useragent import UserAgent

import argparse
import asyncio
import aiohttp
import colorama
import time

class Config:
    """This class is simply to store parsed arguments"""

    def __init__(self):    
        parser = argparse.ArgumentParser(
            prog="./webCraw;er.py",
            usage="./webCrawler.py [options] -u {url} -w {wordlist}",
            description="a simple asynchronous python web crawler",
            epilog="https://github.com/mind2hex/",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        
        # General arguments
        parser.add_argument("-u", "--url", metavar="", required=True, help="Target url.",)
        parser.add_argument("-m", "--http-method", metavar="", choices=["GET", "HEAD", "POST"], default="GET", help="HTTP method to use.")
        parser.add_argument("-H", "--http-headers", metavar="", help="Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2")
        parser.add_argument("-a", "--user-agent", metavar="", default="yoMamma", help="User-Agent to use in the HTTP request")
        parser.add_argument("-r", "--random-ua", action="store_true", help="Randomize user agent.")
        parser.add_argument("-c", "--cookies", metavar="", help="Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2")
        parser.add_argument("-b", "--body-data", metavar="", help="Body data to use in the HTTP POST request.")
        parser.add_argument("-p", "--proxy", metavar="", help="Proxy to use. Ex: http;http://localhost:8080")
        parser.add_argument("-j", "--json", action="store_true", help="Use json formatted data in the HTTP POST request. ")
        parser.add_argument("-f", "--follow", action="store_true", default=False, help="Follow HTTP redirections")
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
        self.http_method   = self.validate_http_method(args.http_method) if args.http_method else None
        self.http_headers  = self.validate_http_headers(args.http_headers) if args.http_headers else None
        self.user_agent    = args.user_agent
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
        self.debug   = args.debug
        self.output  = args.output
        self.quiet   = args.quiet 

        self.hide_status_code    = [404, 503] if args.hide_status_code is None else self.validate_status_codes(args.hide_status_code.split(","))
        #self.hide_content_length = [] if args.hide_content_length is None else self.validate_content_length(args.hide_content_length.split(","))
        #self.hide_web_server     = [] if args.hide_web_server is None else self.validate_web_server(args.hide_web_server.split(","))
        #self.hide_regex          = args.hide_regex

        # asynchronous lock to avoid every task accessing the same resource at the same time
        self.lock     = asyncio.Lock()

        # dynamic user agent for random user generation
        self.dynamic_ua = UserAgent()

        # this will contains all results that will saved to a file if specified.
        self.results = list()
    
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
        print("╔" + "═"*80 + "╗")
        print("║ %13s: %-64s║"%("URL", self.url))
        print("║ %13s: %-64s║"%("WORDLIST", self.wordlist_path))
        print("║ %13s: %-64s║"%("METHOD", self.http_method))
        print("║ %13s: %-64s║"%("USER AGENT", self.user_agent))
        print("║ %13s: %-64s║"%("RANDOM UA", self.random_ua))
        print("║ %13s: %-64s║"%("EXTENSIONS", self.extensions))
        print("║ %13s: %-64s║"%("TASKS", self.tasks))
        print("║ %13s: %-64s║"%("TIMEOUT", self.timeout))
        print("║ %13s: %-64s║"%("HIDE STATUS", self.hide_status_code))
        print("╚" + "═"*80 + "╝")
        print()


class ProxyParser(argparse.Action):
    """this class is used to convert an argument directly into a dict using the format key;value,key=value"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        try:
            for query in values.split(","):
                key, val = query.split(";")
                getattr(namespace, self.dest)[key] = val
        except:
            show_error(
                f"uanble to parse {values} due to incorrect format ",
                "ProxyParser",
            )


class ListParser(argparse.Action):
    """this class is used to convert an argument directly into a comma separated list"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, list())
        try:
            for val in values.split(","):
                getattr(namespace, self.dest).append(val)
        except:
            show_error(
                f"unable to parse {values} due to incorrect format",
                "class::ListParser",
            )


def show_banner():
    author = "mind2hex"
    version = "1.0"
    print(
        f"""
               _      _____                    _ 
              | |    / ____|                  | |
 __      _____| |__ | |     _ __ __ ___      _| |
 \ \ /\ / / _ \ '_ \| |    | '__/ _` \ \ /\ / / |
  \ V  V /  __/ |_) | |____| | | (_| |\ V  V /| |
   \_/\_/ \___|_.__/ \_____|_|  \__,_| \_/\_/ |_|
                                                 
    author:  {AsciiColors.HEADER}{author}{AsciiColors.ENDC}
    version: {AsciiColors.HEADER}{version}{AsciiColors.ENDC}
    """
    )


def parse_arguments():
    """return parsed arguments"""

    parser = argparse.ArgumentParser(
        prog="./webCrawler.py",
        usage="./WebCrawler.py [options] -u {url} ",
        description="a simple python web crawler",
        epilog="https://github.com/mind2hex/",
    )

    # general args
    parser.add_argument(
        "-u",
        "--url",
        metavar="",
        required=True,
        help=f"target url. ex --> http://localhost/",
    )
    parser.add_argument(
        "-H",
        "--headers",
        metavar="",
        default={},
        action=DictParser,
        help="set HTTP headers. ex --> 'Header1=lol&Header2=lol'",
    )
    parser.add_argument(
        "-P",
        "--proxies",
        metavar="",
        default={},
        action=ProxyParser,
        help="set proxies.      ex --> 'http;http://proxy1:8080,https;http://proxy2:8000'",
    )
    parser.add_argument(
        "-D",
        "--download",
        metavar="",
        default=None,
        action=ListParser,
        help="coma separated extension files to download. ex --> jpg,pdf,png",
    )
    parser.add_argument(
        "-x",
        "--exclude-url",
        metavar="",
        default=None,
        action=ListParser,
        help=f"comma separated domains to exclude. ex --> google.com,youtube.com",
    )
    parser.add_argument(
        "-U",
        "--user-agent",
        metavar="",
        default="yoMama",
        help="specify user agent",
    )
    parser.add_argument(
        "-N", 
        "--no-follow", 
        action="store_false", 
        help="follow redirections"
    )
    parser.add_argument(
        "--rand-user-agent", 
        action="store_true", 
        help="randomize user-agent"
    )
    parser.add_argument(
        "--usage", 
        action="store_true", 
        help="show usage examples"
    )
    parser.add_argument(
        "--ignore-errors", 
        action="store_true", 
        help="ignore connection errors"
    )
    parser.add_argument(
        "-d", 
        "--depth", 
        metavar="", 
        default=1, 
        type=int, 
        help=f"max crawling depth "
    )

    # performance args
    performance = parser.add_argument_group("performance options")
    performance.add_argument(
        "-rt",
        "--retries",
        metavar="",
        type=int,
        default=0,
        help="retries per connections if connection fail [default 0]",
    )

    # debugging args
    debug = parser.add_argument_group("debugging options")
    debug.add_argument(
        "-v", 
        "--verbose", 
        action="store_true", 
        help="show verbose messages"
    )
    debug.add_argument(
        "--debug", 
        action="store_true", 
        help="show debugging messages"
    )
    debug.add_argument(
        "-o",
        "--output",
        metavar="",
        type=argparse.FileType("w"),
        help="save indexed urls to a file",
    )
    debug.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="dont show config before execution",
    )

    parsed_arguments = parser.parse_args()

    # indexed_urls is used to store already requested urls and avoid an infinite loop
    parsed_arguments.indexed_urls = list()

    # parsing user agents
    parsed_arguments.UserAgent_wordlist = [
        "Mozilla/1.22 (compatible; MSIE 2.0d; Windows NT)",
        "Mozilla/2.0 (compatible; MSIE 3.02; Update a; Windows NT)",
        "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)",
        "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 4.0)",
        "Mozilla/4.79 [en] (WinNT; U)",
        "Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:0.9.2) Gecko/20010726 Netscape6/6.1",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.19) Gecko/20081204 SeaMonkey/1.1.14",
        "Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaE90-1/210.34.75 Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413",
        "Mozilla/5.0 (iPhone; U; CPU iPhone OS 2_2 like Mac OS X; en-us) AppleWebKit/525.18.1 (KHTML, like Gecko) Version/3.1.1 Mobile/5G77 Safari/525.20",
        "Mozilla/5.0 (Linux; U; Android 1.5; en-gb; HTC Magic Build/CRB17) AppleWebKit/528.5+ (KHTML, like Gecko) Version/3.1.2 Mobile Safari/525.20.1",
        "Opera/9.27 (Windows NT 5.1; U; en)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.4.154.25 Safari/525.19",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.48 Safari/525.19",
        "Wget/1.8.2",
        "Mozilla/5.0 (PLAYSTATION 3; 1.00)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; (R1 1.6))",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1",
        "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10 (.NET CLR 3.5.30729) JBroFuzz/1.4",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20050923 CentOS/1.0.7-1.4.1.centos4 Firefox/1.0.7",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727)",
        "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5",
        "Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.7) Gecko/20070606",
        "Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.8.1.14) Gecko/20080520 Firefox/2.0.0.14",
        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.0.5) Gecko/2008120121 Firefox/3.0.5",
    ]

    return parsed_arguments


def usage():
    """Only show ussage messages"""
    print("No usage messages yet")
    exit(0)


def validate_arguments(args):
    """validate_arguments checks that every argument is valid or in the correct format"""

    validate_url(args.url)

    # TODO: add more validations if needed


def validate_url(url, supress_error=False):
    """validate url using URLValidator from django
    if supress_error == True, then returns False instead of showing error
    """
    val = URLValidator()
    try:
        val(url)
    except:
        if not supress_error:
            show_error(
                f"Error while validating url --> {url}",
                f"function::{currentframe().f_code.co_name}",
            )
        return False
    return True


def initial_checks(args):
    """Initial checks before proceeds with the program execution"""
    check_target_connectivity(args.url)
    check_proxy_connectivity(args.url, args.proxies)


def check_target_connectivity(target_url):
    # testing target connection
    try:
        requests.head(target_url, allow_redirects=False)
    except requests.exceptions.ConnectionError:
        show_error(
            f"Failed to establish a new connection to {target_url}",
            f"function::{currentframe().f_code.co_name}",
        )


def check_proxy_connectivity(url, pr):
    # testing proxy connection
    if len(pr) > 0:
        try:
            requests.get(url + "/proxy_test", proxies=pr)
        except:
            show_error(
                f"Proxy server is not responding",
                f"function::{currentframe().f_code.co_name}",
            )


def show_error(msg, origin):
    print(f"\n {origin} --> {AsciiColors.FAIL}error{AsciiColors.ENDC}")
    print(f" [X] {AsciiColors.FAIL}{msg}{AsciiColors.ENDC}")
    exit(-1)


def show_config(args):
    print(f"[!] %-20s %s" % (f"{AsciiColors.HEADER}GENERAL{AsciiColors.ENDC}", "=" * 40))
    print("%-20s:%s" % ("TARGET", args.url))
    print("%-20s:%s" % ("DEPTH", args.depth))
    print("%-20s:%s" % ("HEADERS", str(args.headers)))
    print("%-20s:%s" % ("PROXIES", str(args.proxies)))
    print("%-20s:%s" % ("USER-AGENT", str(args.user_agent)))
    print("%-20s:%s" % ("RAND-USER-AGENT", str(args.rand_user_agent)))
    print("%-20s:%s" % ("FOLLOW REDIRECT", str(args.no_follow)))
    print("%-20s:%s" % ("IGNORE ERRORS", str(args.ignore_errors)))
    print("%-20s:%s" % ("DOWNLOAD FILES:", str(args.download)))
    print(f"\n[!] %-20s %s" % (f"{AsciiColors.HEADER}PERFORMANCE{AsciiColors.ENDC}", "=" * 40))
    print("%-20s:%s" % ("RETRIES", args.retries))
    print(f"\n[!] %-20s %s" % (f"{AsciiColors.HEADER}DEBUGGING{AsciiColors.ENDC}", "=" * 40))
    print("%-20s:%s" % ("VERBOSE", args.verbose))
    print("%-20s:%s" % ("DEBUG", args.debug))
    print("%-20s:%s" % ("OUTPUT", args.output))
    sleep(2)


def crawler(args, current_target, current_depth):
    """
    crawler()
    """

    # downloading file if specified by user
    if args.download is not None:
        download_file(current_target, args.download)

    # if current_target is media file, then return, because media file has no url's... i guess
    if is_media_file(current_target):  
        print(f"[!] {AsciiColors.WARNING} Media file: {AsciiColors.HEADER} {current_target} {AsciiColors.ENDC}")
        return 

    # making HTTP GET request
    html = requests.get(current_target, allow_redirects=args.no_follow).content

    # parsing HTML content
    soup = BeautifulSoup(html, "html.parser")

    # current_urls store all urls found in current_target
    current_urls = list()

    # appending urls found in current_target to current_urls
    elements = soup.find_all(src=True) + soup.find_all(href=True)
    for element in elements:
        if "src" in element.attrs:   # searching new urls in src
            if not validate_url(element["src"], supress_error=True):
                aux = f"{args.url}{element['src'].lstrip('/')}"
            else:
                aux = element["src"]

        if "href" in element.attrs:  # searching new urls in href
            if not validate_url(element["href"], supress_error=True):
                aux = f"{args.url}{element['href'].lstrip('/')}"
            else:
                aux = element["href"]

        # appending urls to current_urls                        
        current_urls.append(aux)

    # deleting repeated url's
    current_urls = list(set(current_urls))

    # saving only non previously indexed_urls
    new_urls = list()
    for url in current_urls:
        if (url not in args.indexed_urls) :
            output = f"[!]{AsciiColors.HEADER} %-100s -> {AsciiColors.OKGREEN} %-100s {AsciiColors.ENDC}" % (url[:100], current_target[:100])
            # showing new url found and where it was found
            print(output)
            
            # saving output to a file if specified by user
            if args.output is not None:
                args.output.write(output + "\n")

            args.indexed_urls.append(url)
            new_urls.append(url)

    # crawling new urls only
    for url in new_urls:
        if compare_url_netloc(url, args.url):  # only crawl pages in the same net location
            crawler(args, url, current_depth + 1)

    return 0


def download_file(url, download_extensions):
    """
    download_file calls is_media_function with download_extensions parameter to check
    if a url media directory should be downloaded or not

    # example
    download_extensions == ["pdf", "jpg"]
    url = "http://someurl/path/to/file.jpg

    if is_media_file(url, download_extensions):  # returns True
        # download file
        ...
    """
    output_dir = "webCrawler_loot"

    try:
        mkdir(output_dir)
    except FileExistsError:
        pass
    except:
        show_error(
            f"Unable to create output directory {output_dir}",
            f"function::{currentframe().f_code.co_name}",
        )
        exit(0)

    if is_media_file(url, download_extensions):
        print(f"[!] {AsciiColors.OKGREEN}Downloading:{AsciiColors.ENDC} {AsciiColors.WARNING}{url}{AsciiColors.ENDC}")
        with open(f"{output_dir}/{urlparse(url).path.replace('/','_')}", "wb") as handler:
            req = requests.get(url)
            handler.write(req.content)


def compare_url_netloc(url_1, url_2):
    return urlparse(url_1).netloc == urlparse(url_2).netloc


def is_media_file(url_path, media_exts=None):
    """
    is_media_file(url_path, media_exts)
    just compares url_path extension with list media_exts and if it matches,
    then is a media file.

    if you give a custom list to media_exts, then this function will check if
    the  extension of url_path is in media_exts

    returns True if url_path extension in media_exts, False otherwise
    """
    ext = url_path.split(".")[-1].lower()
    if media_exts is None:
        media_exts = [
            "svg",
            "js",
            "mp4",
            "mp3",
            "avi",
            "jpg",
            "jpeg",
            "png",
            "pdf",
            "gif",
            "webp",
            "xml",
        ]

    return True if ext in media_exts else False


async def main():
    show_banner()

    if "--usage" in argv:
        usage()

    parsed_arguments = parse_arguments()
    validate_arguments(parsed_arguments)
    initial_checks(parsed_arguments)

    if not parsed_arguments.quiet:
        show_config(parsed_arguments)

    crawler(parsed_arguments, parsed_arguments.url, 0)

    return 0


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
    