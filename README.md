# webToolkit
Python tools for web hacking.
```bash
# Current tools
webToolkit
├── webCrawl.py
├── webEnum.py
└── webFuzz.py
```

## Installation
```bash
# clonning this repository
git clone https://github.com/mind2hex/webToolkit

# changing directory to the clonned repository
cd webToolkit

# installing dependencies
pip3 install requirements.txt
```
Thats all, now you should be able to run the tools inside this repo.

## webEnum
High-speed, efficient web directory enumerator designed for security professionals and enthusiasts. Combining the power of asynchronous programming with aiohttp, it swiftly scans and enumerates web directories, providing insightful output in a visually appealing format. Whether you’re conducting penetration tests or exploring web structures, webEnum delivers a seamless and powerful experience.

### Key Features
- Asynchronous Power: Built on the robust asynchronous framework, webEnum leverages aiohttp to handle multiple requests concurrently. This allows for lightning-fast enumeration of web directories, significantly reducing scan times compared to traditional synchronous methods.
- Beautiful Progress Monitoring: webEnum incorporates alive_bar for progress tracking, offering a sleek, animated progress bar that keeps you informed about the scanning status in real-time. No more staring at a static screen wondering about the scan progress.
- Elegant and Informative Output: Enjoy a clean and structured output with webEnum. The results are displayed with thoughtful alignment, color coding, and detailed metrics such as status codes, content lengths, and response times. This makes it easy to analyze the data at a glance.
- High Performance: By harnessing the capabilities of asynchronous programming, webEnum ensures high performance and minimal latency, making it ideal for large-scale enumeration tasks.
- User-Friendly Design: Despite its powerful capabilities, webEnum is designed with simplicity in mind. It's easy to use and integrates seamlessly into your workflow, whether you’re scripting an automated scan or performing a manual assessment.

### Usage
```
usage: ./webEnum.py [options] -u {url} -w {wordlist}

a simple asynchronous python web directory enumerator

options:
  -h, --help            show this help message and exit
  -u , --url            Target url.
  -w , --wordlist       Path to the wordlist to use.
  -m , --http-method    HTTP method to use.
  -H , --http-headers   Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2
  -a , --user-agent     User-Agent to use in the HTTP request
  -r, --random-ua       Randomize user agent.
  -c , --cookies        Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2
  -b , --body-data      Body data to use in the HTTP POST request.
  -p , --proxy          Proxy to use. Ex: http;http://localhost:8080
  -x , --extensions     Add file extensions to every request. Ex: php,js,...
  -j, --json            Use json formatted data in the HTTP POST request. 
  -s, --add-slash       Add slash to every request.
  -f, --follow          Follow HTTP redirections
  -i, --ignore-errors   Ignore script errors.
  --usage               Print usage message
  -V, --verify-cert     Verify SSL certificates. Default -> False

performance options:
  -t , --tasks          How many tasks to use.
  -to , --timeout       Total number of seconds for the whole request. Very Low values can cause connection problems. 
  -tw , --timewait      Time to wait between each request per thread.
  -rt , --retries       Times to retry failed HTTP requests

debugging options:
  -v, --verbose         Enable verbose mode.
  -o , --output         Save output to a file.
  -q, --quiet           Supress banner and configuration printing.

filter options:
  -hsc , --hide-status-code 
                        Hide responses with the specified status code. Ex:[-hsc 404,400]
  -hcl , --hide-content-length 
                        Hide responses with the specified content length
  -hws , --hide-web-server 
                        Hide responses with the specified webserver
  -hre , --hide-regex   Hide responses that match the specified expression

https://github.com/mind2hex/
```

## webCrawl
webCrawl is a powerful and flexible asynchronous web directory enumerator designed to explore and extract URLs from websites efficiently. Utilizing Python's asyncio and aiohttp libraries, this tool performs fast and concurrent requests to gather resources such as HTML pages, images, scripts, and other file types from a target website. With customizable options for URL filtering, depth of search, and file extension targeting, webCrawl is ideal for penetration testers, developers, and cybersecurity professionals who need to map out the structure of a website or find hidden resources.
### Key Features

- Asynchronous Requests: Leverages Python's asyncio and aiohttp to perform multiple requests concurrently, significantly speeding up the URL discovery process.
- Customizable Search Depth: Specify the depth of directory traversal to control how deep the crawler goes within the website’s structure.
- Custom URL Filtering: Filter discovered URLs based on custom regular expressions or by matching specific netlocs (domains).
- File Extension Targeting: Focus the crawler on discovering and downloading specific file types by defining the desired file extensions.
- Session Management: Automatically handles HTTP session management, including cookies, headers, and SSL verification, ensuring consistent and secure connections.
- Progress Tracking: Integrated with alive-progress to provide real-time feedback on the crawling process, including the current depth level and the number of URLs collected.
- Concurrency Control: Limit the number of concurrent tasks to avoid overwhelming the target server, allowing for a more controlled and efficient crawling process.
- Error Handling: Robust handling of connection errors, timeouts, and unexpected interruptions, ensuring the tool remains resilient and continues functioning even under challenging network conditions.
- Download Capabilities: Automatically download and save files of specified types into a local "LOOT" directory, organizing the results of your crawl for further analysis.
- Tree-Directory Visualization: After the crawl is complete, visualize the discovered URLs in a tree-directory format, making it easy to understand the structure of the website.
- Customizable HTTP Requests: Define custom HTTP headers, user agents, and proxy settings to simulate different client environments or bypass specific access restrictions.

### Usage
```
usage: ./webEnum.py [options] -u {url}

a simple asynchronous python web directory enumerator

options:
  -h, --help            show this help message and exit
  -u , --url            Target url.
  -D , --depth          Depth to search for links
  -N, --netloc          Discard links with different netloc that the target url.
  -CN , --custom-netloc 
                        Specify a custom netloc. Different netlocs will be discarted.
  -x , --extensions     Specify extension of files to download. Ex: pdf,txt,jpg
  -H , --http-headers   Set custom HTTP headers. Ex: Header1=Value1,Header2=Value2
  -a , --user-agent     User-Agent to use in the HTTP request
  -c , --cookies        Cookies to use in the HTTP request. Ex: Cookie1=Value1,Cookie2=Value2
  -p , --proxy          Proxy to use. Ex: http;http://localhost:8080
  -V, --verify-cert     Verify SSL certificates. Default -> False

performance options:
  -t , --tasks          Total number of tasks. Default 50 tasks
  -ct , --connect-timeout 
                        Max time in seconds to connect to a server. Default 30 seconds
  -rt , --read-timeout 
                        Max time in seconds to read a response. Default 30 seconds

debugging options:
  -o , --output         Save output to a file.
  -q, --quiet           Supress banner and configuration printing.

https://github.com/mind2hex/
```