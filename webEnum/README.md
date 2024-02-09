# webEnum
A simple python web enumerator

## Characteristics
- Fast web enumeration
- Different HTTP methods support
- User Agent personalization 
- Proxy support
- Filters support

## Requirements
- see file requirements.txt

## Installation
```bash
# cloning repository
$ git clone https://github.com/mind2hex/webEnum

# changing dir into the previously clonned repo
$ cd webEnum

# installing required libraries 
$ pip install -R requeriments.txt

# adding properly permissions
$ chmod u+x webEnum.py

# creating local executable path
$ mkdir -p ~/.local/bin/

# creating sym link into the new executable path
$ ln --symbolic -T $(pwd)/webEnum.py ~/.local/bin/webEnum

# adding previously executable path created to the executable path $PATH of the shell
echo -e "\n\nPATH=$PATH:~/.local/bin/" >> ~/.{zsh,bash,sh}rc

# now we can open a new {zsh, bash or sh} shell and type
webEnum -h
```

## Usage
```bash
# basic web enumeration with 30 threads
$ webEnum -u http://target.com/ -w /path/to/wordlist.txt -t 30 
    
# using status code filter to hide 404 responses
$ ./webEnum.py -u http://google.com/ -w /path/to/wrodlist.txt -hs 404

# using extensions for every requests
$ ./webEnum.py -u http://google.com/ -w /path/to/wordlist.txt -x php,js,txt
```

## Options
```                                                                                     
usage: ./webEnum.py [options] -u {url} -w {wordlist}

a simple python web directory enumerator

options:
  -h, --help           show this help message and exit
  -u , --url           target url to enumerate                  - example '-u http://localhost:6969/'
  -w , --wordlist      wordlist path to use in enumeration      - example '-w /path/to/wordlist.txt'
  -M , --http-method   HTTP Method to use                       - example '-M GET'
  -H , --headers       http headers to use in every request     - example '-H Header1=foo&Header2=bar'
  -ua , --user-agent   specify user agent. default[yoMamma]     - example '-ua yoMamma'
  -C , --cookies       cookies to use in every request          - example '-C Cookie1=foo&Cookie2=bar'
  -b , --body-data     body data to send using POST method      - example '-b username=admin&password=admin'
  -P , --proxy         proxies to send every request            - example '-P http=http://localhost:6969'
  -x , --extension     additional extensions to probe           - example '-x php,js,txt'
  -j, --json           send post data in json format            - example '-j -b {'username':'admin'}'
  -s, --add-slash      add slash to every word in wordlist      - 
  -f, --follow         follow redirections.                     - default[NO]
  -R, --randomize-ua   randomize user agent.                    - default[NO]
  -I, --ignore-errors  ignore connection errors                 - 
  -S, --skip-updates   skip update check                        - 
  --usage              show usage                               - 

performance options:
  -t , --threads       threads. default[01]                     - example '-t 10'
  -to , --timeout      time to wait for a response default[10]  - example '-to 10'
  -tw , --timewait     time to wait between requests default[0] - example '-tw 10'
  -rt , --retries      retry failed connections                 - example '-rt 10'

debugging options:
  -v, --verbose        show verbose messages                    - 
  -d, --debug          show debugging messages                  - 
  -o , --output        save output to a file                    - example '-o output.txt'
  -q, --quiet          dont show config before execution        - 

filter options:
  -hs , --hs-filter    hide responses using status code         - example '-hs 500,400'
  -hc , --hc-filter    hide responses using content length      - example '-hc nnnn,nnn'
  -hw , --hw-filter    hide responses using web server          - example '-hw nginx'
  -hr , --hr-filter    hide responses using regex               - example '-hr failed'

https://github.com/mind2hex/
```