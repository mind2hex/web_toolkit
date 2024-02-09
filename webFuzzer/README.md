# webFuzzer

_A simple multithreading python webFuzzer_

## Installation Guide 🚀

_To obtain a copy of webFuzzer use git clone_

```
$ git clone https://github.com/mind2hex/webFuzzer
$ cd webFuzzer
```

_Install python requirements_

```
$ pip3 install -r requirements.txt
$ chmod u+x ./webFuzzer.py
```

## Help
```
               _     ______                      
              | |   |  ____|                     
 __      _____| |__ | |__ _   _ ___________ _ __ 
 \ \ /\ / / _ \ '_ \|  __| | | |_  /_  / _ \ '__|
  \ V  V /  __/ |_) | |  | |_| |/ / / /  __/ |   
   \_/\_/ \___|_.__/|_|   \__,_/___/___\___|_|   
                                                 
    author: mind2hex 
    version: 1.0
    
usage: ./webFuzzer.py [options] -u {url} -w {wordlist}

a simple python multithreading web fuzzer

options:
  -h, --help           show this help message and exit
  -u , --url           target url. ex --> http://localhost/FUZZ
  -w , --wordlist      wordlist
  -b , --body-data     body data to send using POST method. ex --> 'username=admin&password=FUZZ'
  -C , --cookies       set cookies. ex --> 'Cookie1=lol&Cookie2=lol'
  -H , --headers       set HTTP headers. ex --> 'Header1=lol&Header2=lol'
  -P , --proxies       set proxies. ex --> 'http;http://proxy1:8080,https;http://proxy2:8000'
  -U , --user-agent    specify user agent
  -X , --http-method   HTTP method to use. [GET|POST]
  -f, --follow         follow redirections
  --rand-user-agent    randomize user-agent
  --usage              show usage examples

performance options:
  --threads <n>        threads [default 1]
  --timeout <n>        time to wait for response in seconds [default 10]
  --timewait <n>       time to wait between each requests in seconds [default 0]
  --retries <n>        retries per connections if connection fail [default 0]

debugging options:
  -v, --verbose        show verbose messages
  -d, --debug          show debugging messages
  -o , --output        save output to a file

filter options:
  -ss , --ss-filter    show responses with the specified status codes. ex: '200,300,404'
  -sc , --sc-filter    show responses with the specified content lenghts. ex: '1234,4321'
  -sw , --sw-filter    show responses with the specified web servers. ex: 'apache,fakewebserver
  -sr , --sr-filter    show responses matching the specified pattern. ex: 'authentication failed'
  -hs , --hs-filter    hide responses with the specified status codes. ex: '300,400'
  -hc , --hc-filter    hide responses with the specified content lenghts. ex: '1234,4321'
  -hw , --hw-filter    hide responses with the specified web servers. ex: 'apache,nginx'
  -hr , --hr-filter    hide responses matching the specified pattern. ex: 'authentication failed'

https://github.com/mind2hex/

```

## Usage

```
               _     ______                      
              | |   |  ____|                     
 __      _____| |__ | |__ _   _ ___________ _ __ 
 \ \ /\ / / _ \ '_ \|  __| | | |_  /_  / _ \ '__|
  \ V  V /  __/ |_) | |  | |_| |/ / / /  __/ |   
   \_/\_/ \___|_.__/|_|   \__,_/___/___\___|_|   
                                                 
    author: mind2hex 
    version: 1.0
    
### directory enumeration
$ ./webFuzzer.py -ss 200,300 -w /path/wordlist.txt -u https://google.com/FUZZ

### parameter testing 
$ ./webFuzzer.py -ss 200 -w /path/wordlist.txt -u https://google.com/script.php?param1=FUZZ

### Fuzzing post body data [bruteforce attack]
$ ./webFuzzer.py -M POST -hr 'alert=1' -w /path/wordlist.txt -B 'username=admin&password=FUZZ' -u https://google.com/login

### using proxies 
$ ./webFuzzer.py -P http;http://localhost:8080,https;http://localhost:8000 -w /path/wordlist.txt -u https://google.com/FUZZ

### specifying user agent and cookie 
$ ./webFuzzer.py --user-agent FirefoxBOT -C cookie=monster&cookie2=monster2 -w /path/wordlist.txt -u https://google.com/FUZZ

```

