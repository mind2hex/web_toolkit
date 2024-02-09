#!/usr/bin/python3
#      author: mind2hex
# description: simple web directory enumeration tool

from bs4 import BeautifulSoup
from django.core.validators import URLValidator
from inspect import currentframe
from sys import argv
from time import sleep
from urllib.parse import urlparse
import argparse
import requests
from os import mkdir


class AsciiColors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"


class DictParser(argparse.Action):
    """this class is used to convert an argument directly into a dict using the format key=value&key=value"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        try:
            for query in values.split("&"):
                key, val = query.split("=")
                getattr(namespace, self.dest)[key] = val
        except:
            show_error(
                f"uanble to parse {values} due to incorrect format ",
                "DictParser",
            )


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


def main():
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
    try:
        exit(main())
    except KeyboardInterrupt:
        show_error("User Keyboard Interrupt", "main")


##  FUNCIONALIDADES PARA AGREGAR
# TODO: basic auth
# TODO: pattern match search
# TODO: multithreading
# TODO: actualizar usage()
# TODO: realizar pruebas para buscar posibles errores
# TODO: agregar mas extensionns posibles de arhivo multimedia a la funcion is_media_file
# TODO: mejorar el formato de salida para las urls (output file) usar JSON 
# TODO: implementar filtros para mostrar unicamente lo que quiero ver

##  CODIGO POR MEJORAR
# HACK: refactorizar algunas funciones
# HACK: mejorar un poco el output (mas color y mejor formato)

## ERRORES POR CORREGIR
# FIXME: si la ventana reduce su tamano, el formato de salida se va a estropear.
# FIXME: al intentar parsear con bs un xml muestra un error
