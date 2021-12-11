# Templating Guide

**Nuclei** is based on the concepts of `YAML` based template files that define how the requests will be sent and processed. This allows easy extensibility capabilities to nuclei.

The templates are written in `YAML` which specifies a simple human readable format to quickly define the execution process.

**Guide to write your own nuclei template -**

------

## Template Details

Each template has a unique ID which is used during output writing to specify the template name for an output line.

The template file ends with **YAML** extension. The template files can be created any text editor of your choice.

```yaml
id: git-config
```

ID must not contain spaces. This is done to allow easier output parsing.

### Information

Next important piece of information about a template is the **info** block. Info block provides **name**, **author**, **severity**, **description**, **reference** and **tags**. It also contain **severity** field which indicates the severity of the template, **info** block also supports dynamic fields, so one can define N number of `key: value` blocks to provide more useful information about the template. **reference** is another popular tag to define external reference links for the template.

Another useful tag to always add in `info` block is **tags**. This allows you to set some custom tags to a template, depending on the purpose like `cve`, `rce` etc. This allows nuclei to identify templates with your input tags and only run them.

Example of an info block -

```yaml
info:
  name: Git Config File Detection Template
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.
  reference: https://www.acunetix.com/vulnerabilities/web/git-repository-found/
  tags: git,config
```

Actual requests and corresponding matchers are placed below the info block and they perform the task of making requests to target servers and finding if the template request was successful.

Each template file can contain multiple requests to be made. The template is iterated and one by one the desired requests are made to the target sites.

The best part of this is you can simply share your crafted template with your team mates, triage/security team to replicate the issue on the other side with ease.



# HTTP

## Base requests

**Requests**

Nuclei offers extensive support for various features related to HTTP protocol. Raw and Model based HTTP requests are supported, along with options Non-RFC client requests support too. Payloads can also be specified and raw requests can be transformed based on payload values along with many more capabilities that are shown later on this Page.

HTTP Requests start with a `request` block which specifies the start of the requests for the template.

```yaml
# Start the requests for the template right here
requests:
```

**Method**

Request method can be **GET**, **POST**, **PUT**, **DELETE**, etc depending on the needs.

```yaml
# Method is the method for the request
method: GET
```

**Redirects**

Redirection conditions can be specified per each template. By default, redirects are not followed. However, if desired, they can be enabled with `redirects: true` in request details. 10 redirects are followed at maximum by default which should be good enough for most use cases. More fine grained control can be exercised over number of redirects followed by using `max-redirects` field.

An example of the usage:

```yaml
requests:
  - method: GET
    path:
      - "{{BaseURL}}/login.php"
    redirects: true
    max-redirects: 3
```

**Warning**

> Currently redirects are defined per template, not per request.

**Path**

The next part of the requests is the **path** of the request path. Dynamic variables can be placed in the path to modify its behavior on runtime.

Variables start with `{{` and end with `}}` and are case-sensitive.

**{{BaseURL}}** - This will replace on runtime in the request by the input URL as specified in the target file.

**{{RootURL}}** - This will replace on runtime in the request by the root URL as specified in the target file.

**{{Hostname}}** - Hostname variable is replaced by the hostname including port of the target on runtime.

**{{Host}}** - This will replace on runtime in the request by the input host as specified in the target file.

**{{Port}}** - This will replace on runtime in the request by the input port as specified in the target file.

**{{Path}}** - This will replace on runtime in the request by the input path as specified in the target file.

**{{File}}** - This will replace on runtime in the request by the input filename as specified in the target file.

**{{Scheme}}** - This will replace on runtime in the request by protocol scheme as specified in the target file.

An example is provided below - [https://example.com:443/foo/bar.php](https://example.com/foo/bar.php)

| Variable     | Value                                                        |
| :----------- | :----------------------------------------------------------- |
| {{BaseURL}}  | [https://example.com:443/foo/bar.php](https://example.com/foo/bar.php) |
| {{RootURL}}  | [https://example.com:443](https://example.com/)              |
| {{Hostname}} | example.com:443                                              |
| {{Host}}     | example.com                                                  |
| {{Port}}     | 443                                                          |
| {{Path}}     | /foo                                                         |
| {{File}}     | bar.php                                                      |
| {{Scheme}}   | https                                                        |

Some sample dynamic variable replacement examples:

```yaml
path: "{{BaseURL}}/.git/config"
# This path will be replaced on execution with BaseURL
# If BaseURL is set to  https://abc.com then the
# path will get replaced to the following: https://abc.com/.git/config
```

Multiple paths can also be specified in one request which will be requested for the target.

#### Headers

Headers can also be specified to be sent along with the requests. Headers are placed in form of key/value pairs. An example header configuration looks like this:

```yaml
# headers contains the headers for the request
headers:
  # Custom user-agent header
  User-Agent: Some-Random-User-Agent
  # Custom request origin
  Origin: https://google.com
```

#### Body

Body specifies a body to be sent along with the request. For instance:

```yaml
# Body is a string sent along with the request
body: "{\"some random JSON\"}"

# Body is a string sent along with the request
body: "admin=test"
```

#### Session

To maintain cookie based browser like session between multiple requests, you can simply use `cookie-reuse: true` in your template, Useful in cases where you want to maintain session between series of request to complete the exploit chain and to perform authenticated scans.

```yaml
# cookie-reuse accepts boolean input and false as default
cookie-reuse: true
```

#### Request Condition

Request condition allows to check for condition between multiple requests for writing complex checks and exploits involving multiple HTTP request to complete the exploit chain.

with DSL matcher, it can be utilized by adding `req-condition: true` and numbers as suffix with respective attributes, `status_code_1`, `status_code_3`, and`body_2` for example.

```yaml
    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 404 && status_code_2 == 200 && contains((body_2), 'secret_string')"
```

#### **Example HTTP Template**

The final template file for the `.git/config` file mentioned above is as follows:

```yaml
id: git-config

info:
  name: Git Config File
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
```

## RAW HTTP requests

Another way to create request is using raw requests which comes with more flexibility and support of DSL helper functions, like the following ones (as of now it's suggested to leave the `Host` header as in the example with the variable `{{Hostname}}`), All the Matcher, Extractor capabilities can be used with RAW requests in same the way described above.

```yaml
requests:
  - raw:
    - |
        POST /path2/ HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        a=test&b=pd
```

Requests can be fine tuned to perform the exact tasks as desired. Nuclei requests are fully configurable meaning you can configure and define each and every single thing about the requests that will be sent to the target servers.

RAW request format also supports [various helper functions](https://nuclei.projectdiscovery.io/templating-guide/helper-functions/) letting us do run time manipulation with input. An example of the using a helper function in the header.

```yaml
    raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('username:password')}} # Helper function to encode input at run time.
```

## HTTP Fuzzing

**Info**

Nuclei engine supports fuzzing module that allow to run various type of payloads in multiple format, It's possible to define placeholders with simple keywords (or using brackets `{{helper_function(variable)}}` in case mutator functions are needed), and perform **batteringram**, **pitchfork** and **clusterbomb** attacks. The wordlist for these attacks needs to be defined during the request definition under the Payload field, with a name matching the keyword, Nuclei supports both file based and in template wordlist support and Finally all DSL functionalities are fully available and supported, and can be used to manipulate the final values.

Payloads are defined using variable name and can be referenced in the request in between `§ §` or `{{ }}` marker.

An example of the using payloads with local wordlist:

```yaml
    # HTTP Intruder fuzzing using local wordlist.

    payloads:
      paths: params.txt
      header: local.txt
```

An example of the using payloads with in template wordlist support:

```yaml
    # HTTP Intruder fuzzing using in template wordlist.

    payloads:
      password:
        - admin
        - guest
        - password
```

**Note:** be careful while selecting attack type, as unexpected input will break the template.

For example, if you used `clusterbomb` or `pitchfork` as attack type and defined only one variable in the payload section, template will fail to compile, as `clusterbomb` or `pitchfork` expect more than one variable to use in the template.

#### Attack mode

Nuclei engine supports multiple attack types, including `batteringram` as default type which generally used to fuzz single parameter, `clusterbomb` and `pitchfork` for fuzzing multiple parameters which works same as classical burp intruder.

| Type    | batteringram | pitchfork | clusterbomb |
| :------ | ------------ | --------- | ----------- |
| Support | Y            | Y         | Y           |

**batteringram**

The battering ram attack type places the same payload value in all positions. It uses only one payload set. It loops through the payload set and replaces all positions with the payload value.

**pitchfork**

The pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

**clusterbomb**

The cluster bomb attack tries all different combinations of payloads. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

This attack type is useful for a brute-force attack. Load a list of commonly used usernames in the first payload set, and a list of commonly used passwords in the second payload set. The cluster bomb attack will then try all combinations.

More details [here](https://www.sjoerdlangkemper.nl/2017/08/02/burp-intruder-attack-types/).

An example of the using `clusterbomb` attack to fuzz.

```yaml
requests:
  - raw:
      - |
        POST /?file={{path}} HTTP/1.1
        User-Agent: {{header}}
        Host: {{Hostname}}

    payloads:
      path: helpers/wordlists/prams.txt
      header: helpers/wordlists/header.txt
    attack: pitchfork # Defining HTTP fuzz attack type
```

## Unsafe HTTP Requests

Nuclei supports [rawhttp](https://github.com/projectdiscovery/rawhttp) for complete request control and customization allowing **any kind of malformed requests** for issues like HTTP request smuggling, Host header injection, CRLF with malformed characters and more.

**rawhttp** library is disabled by default and can be enabled by including `unsafe: true` in the request block.

Here is an example of HTTP request smuggling detection template using `rawhttp`.

```yaml
requests:
  - raw:
    - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 150
        Transfer-Encoding: chunked

        0

        GET /post?postId=5 HTTP/1.1
        User-Agent: a"/><script>alert(1)</script>
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 5

        x=1
    - |+
        GET /post?postId=5 HTTP/1.1
        Host: {{Hostname}}

    unsafe: true # Enables rawhttp client
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "<script>alert(1)</script>")'
```

## Advance Fuzzing

We’ve enriched nuclei to allow advanced fuzzing of web servers. Users can now use multiple options to tune HTTP fuzzing workflows.

#### Pipelining

HTTP Pipelining support has been added which allows multiple HTTP requests to be sent on the same connection inspired from [http-desync-attacks-request-smuggling-reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn).

Before running HTTP pipelining based templates, make sure the running target supports HTTP Pipeline connection, otherwise nuclei engine fallbacks to standard HTTP request engine.

If you want to confirm the given domain or list of subdomains supports HTTP Pipelining, [httpx](https://github.com/projectdiscovery/) has a flag `-pipeline` to do so.

An example configuring showing pipelining attributes of nuclei.

```yaml
    unsafe: true
    pipeline: true
    pipeline-max-connections: 40
    pipeline-max-workers: 25000
```

An example template demonstrating pipelining capabilities of nuclei has been provided below-

```yaml
id: pipeline-testing
info:
  name: pipeline testing
  author: pdteam
  severity: info

requests:
  - raw:
      - |+
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Referer: {{BaseURL}}

    attack: batteringram
    payloads:
      path: path_wordlist.txt

    unsafe: true
    pipeline: true
    pipeline-max-connections: 40
    pipeline-max-workers: 25000

    matchers:
      - type: status
        part: header
        status:
          - 200
```

#### Connection pooling

While the earlier versions of nuclei did not do connection pooling, users can now configure templates to either use HTTP connection pooling or not. This allows for faster scanning based on requirement.

To enable connection pooling in the template, `threads` attribute can be defined with respective number of threads you wanted to use in the payloads sections.

`Connection: Close` header can not be used in HTTP connection pooling template, otherwise engine will fail and fallback to standard HTTP requests with pooling.

An example template using HTTP connection pooling-

```yaml
id: fuzzing-example
info:
  name: Connection pooling example
  author: pdteam
  severity: info

requests:

  - raw:
      - |
        GET /protected HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('admin:§password§')}}

    attack: batteringram
    payloads:
      password: password.txt
    threads: 40

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "Unique string"
        part: body
```

#### Smuggling

HTTP Smuggling is a class of Web-Attacks recently made popular by [Portswigger’s Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) into the topic. For an in-depth overview, please visit the article linked above.

In the open source space, detecting http smuggling is difficult particularly due to the requests for detection being malformed by nature. Nuclei is able to reliably detect HTTP Smuggling vulnerabilities utilising the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine.

The most basic example of a HTTP Smuggling vulnerability is CL.TE Smuggling. An example template to detect a CE.TL HTTP Smuggling vulnerability is provided below using the `unsafe: true` attribute for rawhttp based requests.

```yaml
id: CL.TE-http-smuggling

info:
  name: HTTP request smuggling, basic CL.TE vulnerability
  author: pdteam
  severity: info
  lab: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

requests:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G      
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G

    unsafe: true
    matchers:
      - type: word
        words:
          - 'Unrecognized method GPOST'
```

More examples are available in [template-examples](https://nuclei.projectdiscovery.io/template-examples/http-smuggling/) section for smuggling templates.

#### Race conditions

Race Conditions are another class of bugs not easily automated via traditional tooling. Burp Suite introduced a Gate mechanism to Turbo Intruder where all the bytes for all the requests are sent expect the last one at once which is only sent together for all requests synchronizing the send event.

We have implemented **Gate** mechanism in nuclei engine and allow them run via templates which makes the testing for this specfic bug class simple and portable.

To enable race condition check within template, `race` attribute can be set to `true` and `race_count` defines the number of simultaneous request you want to initiate.

Below is an example template where the same request is repeated for 10 times using the gate logic.

```yaml
id: race-condition-testing

info:
  name: Race condition testing
  author: pdteam
  severity: info

requests:
  - raw:
      - |
        POST /coupons HTTP/1.1
        Host: {{Hostname}}

        promo_code=20OFF        

    race: true
    race_count: 10

    matchers:
      - type: status
        part: header
        status:
          - 200
```

You can simply replace the `POST` request with any suspected vulnerable request and change the `race_count` as per your need and it's ready to run.

```bash
nuclei -t race.yaml -target https://api.target.com
```

**Multi request race condition testing**

For the scenario when multiple requests needs to be sent in order to exploit the race condition, we can make use of threads.

```yaml
    threads: 5
    race: true
```

`threads` is a total number of request you wanted make with the template to perform race condition testing.

Below is an example template where multiple (5) unique request will be sent at the same time using the gate logic.

```yaml
id: multi-request-race

info:
  name: Race condition testing with multiple requests
  author: pd-team
  severity: info

requests:
  - raw:  
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=1

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=2

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=3

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=4

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=5

    threads: 5
    race: true
```

# Headless

### Headless Requests

Nuclei supports automation of a browser with simple DSL. Headless browser engine can be fully customized and user actions can be scripted allowing complete control over the browser. This allows for a variety of unique and custom workflows.

```yaml
# Start the requests for the template right here
headless:
```

#### Actions

Action is a single piece of Task for the Nuclei Headless Engine. Each action manipulates the browser state in some way, and finally leads to the state that we are interesting in capturing.

Nuclei supports a variety of actions. A list of these Actions along with their arguments are given below -

#### navigate

Navigate visits a given URL. url field supports variables like `{{BaseURL}}`, `{{Hostname}}` to customize the request fully.

```yaml
action: navigate
args: 
  url: "{{BaseURL}}
```

##### SCRIPT

Script runs a JS code on the current browser page. At the simplest level, you can just provide a `code` argument with the JS snippet you want to execute and it will be run on the page.

```yaml
action: script
args:
  code: alert(document.domain)
```

Suppose you want to run a matcher on a JS object to inspect it's value. This type of data extraction use cases are also supported with nuclei headless. As an example, let's say the application sets an object called `window.random-object` with a value and you want to match on that value.

```yaml
- action: script
  args:
    code: window.random-object
  name: script-name
...
matchers:
  - type: word
    part: script-name
    words:
      - "some-value"
```

Nuclei supports running some custom Javascript, before the page load with the `hook` argument. This will always run the provided Javascript, before any of the pages load.

The example provided hooks window.alert so that the alerts that are generated by the application do not stop the crawler.

```yaml
- action: script
  args:
    code: (function() { window.alert=function(){} })()
    hook: true
```

This is one use case, there are many more use cases of function hooking such as DOM XSS Detection and Javascript-Injection based testing techniques. Further examples are provided on examples page.

##### CLICK

Click simulates clicking with the Left-Mouse button on an element specified by a selector.

```yaml
action: click
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

Nuclei supports a variety of selector types, including but not limited to XPath, Regex, CSS, etc. For more information about selectors, see [here](https://nuclei.projectdiscovery.io/templating-guide/protocols/headless/#selectors).

##### RIGHTCLICK

RightClick simulates clicking with the Right-Mouse button on an element specified by a selector.

```yaml
action: rightclick
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

##### TEXT

Text simulates typing something into an input with Keyboard. Selectors can be used to specify the element to type in.

```yaml
action: text
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: username
```

##### SCREENSHOT

Screenshots takes the screenshots of a page and writes it to disk. It supports both full page as well as normal screenshots.

```yaml
action: screenshot
args: 
  to: /root/test/screenshot-web
```

If you require full page screenshot, it can be achieved with `fullpage: true` option in the args.

```yaml
action: screenshot
args: 
  to: /root/test/screenshot-web
  fullpage: true
```

##### TIME

Time enters values into time inputs on pages in RFC3339 format.

```yaml
action: time
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: 2006-01-02T15:04:05Z07:00
```

##### SELECT

Select performs selection on a HTML Input by a selector.

```yaml
action: select
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  selected: true
  value: option[value=two]
  selector: regex
```

##### FILES

Files handles a file upload input on the webpage.

```yaml
action: files
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: /root/test/payload.txt
```

##### WAITLOAD

WaitLoads waits for a page to finish loading and get in Idle state.

```yaml
action: waitload
```

Nuclei's `waitload` action waits for DOM to load, and window.onload event to be received after which we wait for the page to become idle for 1 seconds.

##### GETRESOURCE

GetResource returns the src attribute for an element.

```yaml
action: getresource
name: extracted-value-src
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

##### EXTRACT

Extract extracts either the Text for a HTML Node, or an attribute as specified by the user.

The below code will extract the Text for the given XPath Selector Element, which can then also be matched upon by name `extracted-value` with matchers and extractors.

```yaml
action: extract
name: extracted-value
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

An attribute can also be extracted for an element. For example -

```yaml
action: extract
name: extracted-value-href
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  target: attribute
  attribute: href
```

##### SETMETHOD

SetMethod overrides the method for the request.

```yaml
action: setmethod
args: 
  part: request
  method: DELETE
```

##### ADDHEADER

AddHeader adds a header to the requests / responses. This does not overwrites any pre-existing headers.

```yaml
action: addheader
args: 
  part: response # can be request too
  key: Content-Security-Policy
  value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
```

##### SETHEADER

SetHeader sets a header in the requests / responses.

```yaml
action: setheader
args: 
  part: response # can be request too
  key: Content-Security-Policy
  value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
```

##### DELETEHEADER

DeleteHeader deletes a header from requests / responses.

```yaml
action: deleteheader
args: 
  part: response # can be request too
  key: Content-Security-Policy
```

##### SETBODY

SetBody sets the body for a request / response.

```yaml
action: setbody
args: 
  part: response # can be request too
  body: '{"success":"ok"}'
```

##### WAITEVENT

WaitEvent waits for an event to trigger on the page.

```yaml
action: waitevent
args: 
  event: 'Page.loadEventFired'
```

The list of events supported are listed [here](https://github.com/go-rod/rod/blob/master/lib/proto/definitions.go).

##### KEYBOARD

Keybord simulates a single key-press on the keyboard.

```yaml
action: keyboard
args: 
  keys: '\r' # this simulates pressing enter key on keyboard
```

`keys` argument accepts key-codes.

##### DEBUG

Debug adds a delay of 5 seconds between each headless action and also shows a trace of all the headless events occuring in the browser.

> Note: Only use this for debugging purposes, don't use this in production templates.

```yaml
action: debug
```

##### SLEEP

Sleeps makes the browser wait for a specified duration in seconds. This is also useful for debugging purposes.

```yaml
action: sleep
args:
  duration: 5
```

#### Selectors

Selectors are how nuclei headless engine identifies what element to execute an action on. Nuclei supports getting selectors by including a variety of options -

| Selector             | Description                                         |
| :------------------- | :-------------------------------------------------- |
| `r` / `regex`        | Element matches CSS Selector and Text Matches Regex |
| `x` / `xpath`        | Element matches XPath selector                      |
| `js`                 | Return elements from a JS function                  |
| `search`             | Search for a query (can be text, XPATH, CSS)        |
| `selector` (default) | Element matches CSS Selector                        |

#### Matchers / Extractor Parts

Valid `part` values supported by **Headless** protocol for Matchers / Extractor are -

| Value             | Description                     |
| :---------------- | :------------------------------ |
| request           | Headless Request                |
| `<out_names>`     | Action names with stored values |
| raw / body / data | Final DOM response from browser |

#### **Example Headless Template**

An example headless template to automatically login into DVWA is provided below -

```yaml
id: dvwa-headless-automatic-login
info:
  name: DVWA Headless Automatic Login
  author: pdteam
  severity: high
headless:
  - steps:
      - args:
          url: "{{BaseURL}}/login.php"
        action: navigate
      - action: waitload
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/input
        action: click
      - action: waitload
      - args:
          by: xpath
          value: admin
          xpath: /html/body/div/div[2]/form/fieldset/input
        action: text
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/input[2]
        action: click
      - action: waitload
      - args:
          by: xpath
          value: password
          xpath: /html/body/div/div[2]/form/fieldset/input[2]
        action: text
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/p/input
        action: click
      - action: waitload
    matchers:
      - part: resp
        type: word
        words:
          - "You have logged in as"
```

More complete examples are provided [here](https://nuclei.projectdiscovery.io/template-examples/headless/)

# Network

### Network Requests

Nuclei can act as an automatable **Netcat**, allowing users to send bytes across the wire and receive them, while providing matching and extracting capabilities on the response.

Network Requests start with a **network** block which specifies the start of the requests for the template.

```yaml
# Start the requests for the template right here
network:
```

#### Inputs

First thing in the request is **inputs**. Inputs are the data that will be sent to the server, and optionally any data to read from the server.

At it's most simple, just specify a string and it will be sent across the network socket.

```yaml
# inputs is the list of inputs to send to the server
inputs: 
  - data: "TEST\r\n"
```

You can also send hex encoded text that will be first decoded and the raw bytes will be sent to the server.

```yaml
inputs:
  - data: "50494e47"
    type: hex
  - data: "\r\n"
```

Helper function expressions can also be defined in input and will be first evaluated and then sent to the server. The last Hex Encoded example can be sent with helper functions this way -

```yaml
inputs:
  - data: 'hex_decode("50494e47")\r\n'
```

One last thing that can be done with inputs is reading data from the socket. Specifying `read-size` with a non-zero value will do the trick. You can also assign the read data some name, so matching can be done on that part.

```yaml
inputs:
  - read-size: 8
```

Example with reading a number of bytes, and only matching on them.

```yaml
inputs:
  - read-size: 8
    name: prefix
...
matchers:
  - type: word
    part: prefix
    words: 
      - "CAFEBABE"
```

Multiple steps can be chained together in sequence to do network reading / writing.

#### Host

The next part of the requests is the **host** to connect to. Dynamic variables can be placed in the path to modify its value on runtime. Variables start with `{{` and end with `}}` and are case-sensitive.

1. **Hostname** - variable is replaced by the hostname provided on command line.

An example name value:

```yaml
host: 
  - "{{Hostname}}"
```

Nuclei can also do TLS connection to the target server. Just add `tls://` as prefix before the **Hostname** and you're good to go.

```yaml
host:
  - "tls://{{Hostname}}"
```

If a port is specified in the host, the user supplied port is ignored and the template port takes presedence.

#### Matchers / Extractor Parts

Valid `part` values supported by **Network** protocol for Matchers / Extractor are -

| Value            | Description                         |
| :--------------- | :---------------------------------- |
| request          | Network Request                     |
| data             | Final Data Read From Network Socket |
| raw / body / all | All Data recieved from Socket       |

#### **Example Network Template**

The final example template file for a `hex` encoded input to detect MongoDB running on servers with working matchers is provided below.

```yaml
id: input-expressions-mongodb-detect

info:
  name: Input Expression MongoDB Detection
  author: pd-team
  severity: info
  reference: https://github.com/orleven/Tentacle

network:
  - inputs:
      - data: "{{hex_decode('3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000')}}"
    host:
      - "{{Hostname}}"
    read-size: 2048
    matchers:
      - type: word
        words:
          - "logicalSessionTimeout"
          - "localTime"
```

More complete examples are provided [here](https://nuclei.projectdiscovery.io/template-examples/network/)

# DNS

### DNS Requests

DNS protocol can be modelled in nuclei with ease. Fully Customizable DNS requests can be sent by nuclei to nameservers and matching/extracting can be performed on their response.

DNS Requests start with a **dns** block which specifies the start of the requests for the template.

```yaml
# Start the requests for the template right here
dns:
```

#### Type

First thing in the request is **type**. Request type can be **A**, **NS**, **CNAME**, **SOA**, **PTR**, **MX**, **TXT**, **AAAA**.

```yaml
# type is the type for the dns request
type: A
```

#### Name

The next part of the requests is the DNS **name** to resolve. Dynamic variables can be placed in the path to modify its value on runtime. Variables start with `{{` and end with `}}` and are case-sensitive.

1. **FQDN** - variable is replaced by the hostname/FQDN of the target on runtime.

An example name value:

```yaml
name: {{FQDN}}.com
# This value will be replaced on execution with the FQDN.
# If FQDN is https://this.is.an.example then the
# name will get replaced to the following: this.is.an.example.com
```

As of now the tool supports only one name per request.

#### Class

Class type can be **INET**, **CSNET**, **CHAOS**, **HESIOD**, **NONE** and **ANY**. Usually it's enough to just leave it as **INET**.

```yaml
# method is the class for the dns request
class: inet
```

#### Recursion

Recursion is a boolean value, and determines if the resolver should only return cached results, or traverse the whole dns root tree to retrieve fresh results. Generally it's better to leave it as **true**.

```yaml
# Recursion is a boolean determining if the request is recursive
recursion: true
```

#### Retries

Retries is the number of attempts a dns query is retried before giving up among different resolvers. It's recommended a reasonable value, like **3**.

```yaml
# Retries is a number of retries before giving up on dns resolution
retries: 3
```

#### Matchers / Extractor Parts

Valid `part` values supported by **DNS** protocol for Matchers / Extractor are -

| Value            | Description                 |
| :--------------- | :-------------------------- |
| request          | DNS Request                 |
| rcode            | DNS Rcode                   |
| question         | DNS Question Message        |
| extra            | DNS Message Extra Field     |
| answer           | DNS Message Answer Field    |
| ns               | DNS Message Authority Field |
| raw / all / body | Raw DNS Message             |

#### **Example DNS Template**

The final example template file for performing `A` query, and check if CNAME and A records are in the response is as follows:

```yaml
id: dummy-cname-a

info:
  name: Dummy A dns request
  author: mzack9999
  severity: none
  description: Checks if CNAME and A record is returned.

dns:
  - name: "{{FQDN}}"
    type: A
    class: inet
    recursion: true
    retries: 3
    matchers:
      - type: word
        words:
          # The response must contains a CNAME record
          - "IN\tCNAME"
          # and also at least 1 A record
          - "IN\tA"
        condition: and
```

More complete examples are provided [here](https://nuclei.projectdiscovery.io/template-examples/dns/)

# File

### File Requests

Nuclei allows modelling templates that can match/extract on filesystem too.

```yaml
# Start of file template block
file:
```

#### Extensions

To match on all extensions (except the ones in default denylist), use the following -

```yaml
extensions:
  - all
```

You can also provide a list of custom extensions that should be matched upon.

```yaml
extensions:
  - py
  - go
```

A denylist of extensions can also be provided. Files with these extensions will not be processed by nuclei.

```yaml
extensions:
  - all

denylist:
  - go
  - py
  - txt
```

By default, certain extensions are excluded in nuclei file module. A list of these is provided below-

```yaml
3g2,3gp,7z,apk,arj,avi,axd,bmp,css,csv,deb,dll,doc,drv,eot,exe,flv,gif,gifv,gz,h264,ico,iso,jar,jpeg,jpg,lock,m4a,m4v,map,mkv,mov,mp3,mp4,mpeg,mpg,msi,ogg,ogm,ogv,otf,pdf,pkg,png,ppt,psd,rar,rm,rpm,svg,swf,sys,tar,tar.gz,tif,tiff,ttf,txt,vob,wav,webm,wmv,woff,woff2,xcf,xls,xlsx,zip
```

#### More Options

**max-size** parameter can be provided which limits the maximum size (in bytes) of files read by nuclei engine.

As default the `max-size` value is 5MB (5242880), Files larger than the `max-size` will not be processed.

------

**no-recursive** option disables recursive walking of directories / globs while input is being processed for file module of nuclei.

#### Matchers / Extractor

**File** protocol supports 2 types of Matchers -

| Matcher Type | Part Matched |
| :----------- | :----------- |
| word         | all          |
| regex        | all          |

| Extractors Type | Part Matched |
| :-------------- | :----------- |
| word            | all          |
| regex           | all          |

#### **Example File Template**

The final example template file for a Private Key detection is provided below.

```yaml
id: google-api-key

info:
  name: Google API Key
  author: pdteam
  severity: info

file:
  - extensions:
      - all
      - txt

    extractors:
      - type: regex
        name: google-api-key
        regex:
          - "AIza[0-9A-Za-z\\-_]{35}"
# Running file template on http-response/ directory
nuclei -t file.yaml -target http-response/

# Running file template on output.txt
nuclei -t file.yaml -target output.txt
```

More complete examples are provided [here](https://nuclei.projectdiscovery.io/template-examples/file/)

# Operators

## Matchers

### Matchers

Matchers allow different type of flexible comparisons on protocol responses. They are what makes nuclei so powerful, checks are very simple to write and multiple checks can be added as per need for very effective scanning.

#### Types

Multiple matchers can be specified in a request. There are basically 6 types of matchers:

| Matcher Type | Part Matched                |
| :----------- | :-------------------------- |
| status       | Integer Comparisons of Part |
| size         | Content Length of Part      |
| word         | Part for a protocol         |
| regex        | Part for a protocol         |
| binary       | Part for a protocol         |
| dsl          | Part for a protocol         |

To match status codes for responses, you can use the following syntax.

```yaml
matchers:
  # Match the status codes
  - type: status
    # Some status codes we want to match
    status:
      - 200
      - 302
```

To match binary for hexadecimal responses, you can use the following syntax.

```yaml
matchers:
  - type: binary
    binary:
      - "504B0304" # zip archive
      - "526172211A070100" # rar RAR archive version 5.0
      - "FD377A585A0000" # xz tar.xz archive
    condition: or
    part: body
```

Matchers also support hex encoded data which will be decoded and matched.

```yaml
matchers:
  - type: word
    encoding: hex
    words:
      - "50494e47"
    part: body
```

**Word** and **Regex** matchers can be further configured depending on the needs of the users.

Complex matchers of type **dsl** allows to build more elaborate expressions with helper functions. These function allow access to Protocol Response which contains variety of data based on each protocol. See protocol specific documentation to learn about different returned results.

```yaml
matchers:
  - type: dsl
    dsl:
      - "len(body)<1024 && status_code==200" # Body length less than 1024 and 200 status code
      - "contains(toupper(body), md5(cookie))" # Check if the MD5 sum of cookies is contained in the uppercase body
```

Every part of a Protocol response can be matched with DSL matcher. Some examples -

| Response Part  | Description                                     | Example                |
| :------------- | :---------------------------------------------- | :--------------------- |
| content_length | Content-Length Header                           | content_length >= 1024 |
| status_code    | Response Status Code                            | status_code==200       |
| all_headers    | Unique string containing all headers            | len(all_headers)       |
| body           | Body as string                                  | len(body)              |
| header_name    | Lowercase header name with `-` converted to `_` | len(user_agent)        |
| raw            | Headers + Response                              | len(raw)               |

#### Conditions

Multiple words and regexes can be specified in a single matcher and can be configured with different conditions like **AND** and **OR**.

1. **AND** - Using AND conditions allows matching of all the words from the list of words for the matcher. Only then will the request be marked as successful when all the words have been matched.
2. **OR** - Using OR conditions allows matching of a single word from the list of matcher. The request will be marked as successful when even one of the word is matched for the matcher.

#### Matched Parts

Multiple parts of the response can also be matched for the request, default matched part is `body` if not defined.

Example matchers for HTTP response body using the AND condition:

```yaml
matchers:
  # Match the body word
  - type: word
   # Some words we want to match
   words:
     - "[core]"
     - "[config]"
   # Both words must be found in the response body
   condition: and
   #  We want to match request body (default)
   part: body
```

Similarly, matchers can be written to match anything that you want to find in the response body allowing unlimited creativity and extensibility.

#### Negative Matchers

All types of matchers also support negative conditions, mostly useful when you look for a match with an exclusions. This can be used by adding `negative: true` in the **matchers** block.

Here is an example syntax using `negative` condition, this will return all the URLs not having `PHPSESSID` in the response header.

```yaml
matchers:
  - type: word
    words:
      - "PHPSESSID"
    part: header
    negative: true
```

#### Multiple Matchers

Multiple matchers can be used in a single template to fingerprint multiple conditions with a single request.

Here is an example of syntax for multiple matchers.

```yaml
matchers:
  - type: word
    name: php
    words:
      - "X-Powered-By: PHP"
      - "PHPSESSID"
    part: header
  - type: word
    name: node
    words:
      - "Server: NodeJS"
      - "X-Powered-By: nodejs"
    condition: or
    part: header
  - type: word
    name: python
    words:
      - "Python/2."
      - "Python/3."
    condition: or
    part: header
```

#### Matchers Condition

While using multiple matchers the default condition is to follow OR operation in between all the matchers, AND operation can be used to make sure return the result if all matchers returns true.

```yaml
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        condition: or
        part: header

      - type: word
        words:
          - "PHP"
        part: body
```

## Extractors

### Extractors

Extractors can be used to extract and display in results a match from the response returned by a module.

#### Types

Multiple extractors can be specified in a request. As of now we support two type of extractors.

1. **regex** - Extract data from response based on a Regular Expression.
2. **kval** - Extract `key: value`/`key=value` formatted data from Response Header/Cookie
3. **json** - Extract data from JSON based response in JQ like snytax.
4. **xpath** - Extract xpath based data from HTML Response

Example extractor for HTTP Response body using **regex** -

```yaml
extractors:
  - type: regex # type of the extractor
    part: body  # part of the response (header,body,all)
    regex:
      - "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"  # regex to use for extraction.
```

A **kval** extractor example to extract `content-type` header from HTTP Response.

```yaml
extractors:
      - type: kval  # type of the extractor
        kval:
          - content_type  # header/cookie value to extract from response
```

Note that `content-type` has been replaced with `content_type` because **kval** extractor does not accept dash (`-`) as input and must be substituted with underscore (`_`).

A **json** extractor example to extract value of `id` object from JSON block.

```yaml
      - type: json # type of the extractor
        part: body
        name: user
        json:
          - '.[] | .id'  # JQ like syntax for extraction
```

For more details about JQ - https://github.com/stedolan/jq

A **xpath** extractor example to extract value of `href` attribute from HTML response.

```yaml
    extractors:
      - type: xpath # type of the extractor
        attribute: href # attribute value to extract (optional)
        xpath:
          - "/html/body/div/p[2]/a"  # xpath value for extraction
```

With a simple [copy paste in browser](https://www.scientecheasy.com/2020/07/find-xpath-chrome.html/), we can get the **xpath** value form any web page content.

#### Dynamic extractor

Extractors can be used to capture Dynamic Values on runtime while writing Multi-Request templates. CSRF Tokens, Session Headers, etc can be extracted and used in requests. This feature is only available in RAW request format.

Example of defining a dynamic extractor with name `api` which will capture a regex based pattern from the request.

```yaml
    extractors:
      - type: regex
        name: api
        part: body
        internal: true # Required for using dynamic variables
        regex:
          - "(?m)[0-9]{3,10}\\.[0-9]+"
```

The extracted value is stored in the variable **api**, which can be utilised in any section of the subsequent requests.

If you want to use extractor as a dynamic variable, you must use `internal: true` to avoid printing extracted values in the terminal.

An optional regex **match-group** can also be specified for the regex for more complex matches.

```yaml
extractors:
  - type: regex  # type of extractor
    name: csrf_token # defining the variable name
    part: body # part of response to look for
    # group defines the matching group being used. 
    # In GO the "match" is the full array of all matches and submatches 
    # match[0] is the full match
    # match[n] is the submatches. Most often we'd want match[1] as depicted below
    group: 1
    regex:
      - '<input\sname="csrf_token"\stype="hidden"\svalue="([[:alnum:]]{16})"\s/>'
```

The above extractor with name `csrf_token` will hold the value extracted (by `([[:alnum:]]{16}))` as `abcdefgh12345678`.

If no group option is provided with this regex, the above extractor with name `csrf_html_tag` will hold the full match (by `<input name="csrf_token"\stype="hidden"\svalue="([[:alnum:]]{16})" />`) as `<input name="csrf_token" type="hidden" value="abcdefgh12345678" />`.

# OOB Testing

Since release of [Nuclei v2.3.6](https://github.com/projectdiscovery/nuclei/releases/tag/v2.3.6), Nuclei supports using the [interact.sh](https://github.com/projectdiscovery/interactsh) API to achieve OOB based vulnerability scanning with automatic Request correlation built in. It's as easy as writing `{{interactsh-url}}` anywhere in the request, and adding a matcher for `interact_protocol`. Nuclei will handle correlation of the interaction to the template & the request it was generated from allowing effortless OOB scanning.

### Interactsh Placeholder

`{{interactsh-url}}` placeholder is supported in **http** and **network** requests.

An example of nuclei request with `{{interactsh-url}}` placeholders is provided below. These are replaced on runtime with unique interact.sh URLs.

```yaml
  - raw:
      - |
        GET /plugins/servlet/oauth/users/icon-uri?consumerUri=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
```

### Interactsh Matchers

Interactsh interactions can be used with `word`, `regex` or `dsl` matcher/extractor using following parts.

| part                |
| :------------------ |
| interactsh_protocol |
| interactsh_request  |
| interactsh_response |

# Helper Functions

#### Helper functions

Here is the list of all supported helper functions can be used in the RAW requests / Network requests.

| Helper function        | Description                                                  | Example                                                |
| :--------------------- | :----------------------------------------------------------- | :----------------------------------------------------- |
| len                    | Length of a string                                           | len("Hello")                                           |
| toupper                | String to uppercase                                          | toupper("Hello")                                       |
| tolower                | String to lowercase                                          | tolower("Hello")                                       |
| replace                | Replace string parts                                         | replace("Hello", "He", "Ha")                           |
| replace_regex          | Replace string parts with regex                              | replace_regex("test", "regextomach", "replacewith")    |
| trim                   | Remove trailing unicode chars                                | trim("aaaHelloddd", "ad")                              |
| trimleft               | Remove unicode chars from left                               | trimleft("aaaHelloddd", "ad")                          |
| trimright              | Remove unicode chars from right                              | trimleft("aaaHelloddd", "ad")                          |
| trimspace              | Remove trailing spaces                                       | trimspace(" Hello ")                                   |
| trimprefix             | Trim specified prefix                                        | trimprefix("aaHelloaa", "aa")                          |
| trimsuffix             | Trim specified suffix                                        | trimsuffix("aaHelloaa", "aa")                          |
| reverse                | Reverse the string                                           | reverse("ab")                                          |
| base64                 | Encode string to base64                                      | base64("Hello")                                        |
| base64_py              | Encode string to base64 like python (with new lines)         | base64_py("Hello")                                     |
| base64_decode          | Decode string from base64                                    | base64_decode("SGVsbG8=")                              |
| url_encode             | URL encode a string                                          | url_encode("hxxps://projectdiscovery.io/test?a=1")     |
| url_decode             | URL decode a string                                          | url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1") |
| hex_encode             | Hex encode a string                                          | hex_encode("aa")                                       |
| hex_decode             | Hex decode a string                                          | hex_decode("6161")                                     |
| html_escape            | HTML escape a string                                         | html_escape("test")                                    |
| html_unescape          | HTML unescape a string                                       | html_unescape("<body>test</body>")                     |
| md5                    | Calculate md5 of string                                      | md5("Hello")                                           |
| sha256                 | Calculate sha256 of string                                   | sha256("Hello")                                        |
| sha1                   | Calculate sha1 of string                                     | sha1("Hello")                                          |
| mmh3                   | Calculate mmh3 of string                                     | mmh3("Hello")                                          |
| contains               | Verify if a string contains another one                      | contains("Hello", "lo")                                |
| regex                  | Verify a regex versus a string                               | regex("H([a-z]+)o", "Hello")                           |
| rand_char              | Pick a random char among charset (optional, default letters and numbers) avoiding badchars (optional, default empty) | rand_char("charset", "badchars")                       |
| rand_char              | Pick a random sequence of length l among charset (optional, default to letters and numbers) avoiding badchars (optional, default empty) | rand_base(l, "charset", "badchars")                    |
| rand_text_alphanumeric | Pick a random sequence of length l among letters and numbers avoiding badchars (optional) | rand_text_alphanumeric(l, "badchars")                  |
| rand_text_alpha        | Pick a random sequence of length l among letters avoiding badchars | rand_text_alpha(l, "charset")                          |
| rand_text_numeric      | Pick a random sequence of length l among numbers avoiding badchars | rand_text_numeric(l, "charset")                        |
| rand_int               | Pick a random integer between min and max                    | rand_int(min, max)                                     |
| waitfor                | block the logic execution for x seconds                      | waitfor(10)                                            |

#### Deserialization helper functions

Nuclei allows payload generation for a few commom gadget from [ysoserial](https://github.com/frohoff/ysoserial).

**Supported Payload:**

- dns (URLDNS)
- commons-collections3.1
- commons-collections4.0
- jdk7u21
- jdk8u20
- groovy1

**Supported encodings:**

- base64 (default)
- gzip-base64
- gzip
- hex
- raw

**Deserialization helper function format:**

```yaml
{{generate_java_gadget(payload, cmd, encoding}}
```

**Deserialization helper function example:**

```yaml
{{generate_java_gadget("commons-collections3.1", "wget http://{{interactsh-url}}", "base64")}}
```

# Preprocessors

## Template **Preprocessors**

Certain pre-processors can be specified globally anywhere in the template that run as soon as the template is loaded to achieve things like random ids generated for each template run.

### randstr

Info

Generates a [random ID](https://github.com/rs/xid) for a template on each nuclei run. This can be used anywhere in the template and will always contain the same value. `randstr` can be suffixed by a number, and new random ids will be created for those names too. Ex. `{{randstr_1}}` which will remain same across the template.

`randstr` is also supported within matchers and can be used to match the inputs.

For example:-

```yaml
requests:
  - method: POST
    path:
      - "{{BaseURL}}/level1/application/"
    headers:
      cmd: echo '{{randstr}}'

    matchers:
      - type: word
        words:
          - '{{randstr}}'
```

# Workflows

### Workflows

Workflows allow users to define an execution sequence for templates. The templates will be run on the defined conditions. These are the most efficient way to use nuclei, where all the templates are configured based on needs of users. This means, you can create Technology Based / Target based workflows, like Wordpress Workflow, Jira Workflow which only run when the specific technology is detected.

If the tech stack is known, we recommend creating your custom workflows to run your scans. This leads to much lower scan times with better results.

Workflows can be defined with `workflows` attribute, following the `template` / `subtemplates` and `tags` to execute.

```yaml
workflows:
  - template: technologies/template-to-execute.yaml
```

**Type of workflows**

1. Generic workflows
2. Conditional workflows

#### Generic Workflows

In generic workflow one can define single or multiple template to be executed from a single workflow file. It supports both files and directories as input.

A workflow that runs all config related templates on the list of give URLs.

```yaml
workflows:
  - template: files/git-config.yaml
  - template: files/svn-config.yaml
  - template: files/env-file.yaml
  - template: files/backup-files.yaml
  - tags: xss,ssrf,cve,lfi
```

A workflow that runs specific list of checks defined for your project.

```yaml
workflows:
  - template: cves/
  - template: exposed-tokens/
  - template: exposures/
  - tags: exposures
```

#### Conditional Workflows

You can also create conditional templates which execute after matching the condition from a previous template. This is mostly useful for vulnerability detection and exploitation as well as tech based detection and exploitation. Use-cases for these kind of workflows are vast and varied.

**Templates based condition check**

A workflow that executes subtemplates when base template gets matched.

```yaml
workflows:
  - template: technologies/jira-detect.yaml
    subtemplates:
      - tags: jira
      - template: exploits/jira/
```

**Matcher Name based condition check**

A workflow that executes subtemplates when a matcher of base template is found in result.

```yaml
workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: vbulletin
        subtemplates:
          - template: exploits/vbulletin-exp1.yaml
          - template: exploits/vbulletin-exp2.yaml
      - name: jboss
        subtemplates:
          - template: exploits/jboss-exp1.yaml
          - template: exploits/jboss-exp2.yaml
```

In similar manner, one can create as many and as nested checks for workflows as needed.

**Subtemplate and matcher name based multi level conditional check**

A workflow showcasing chain of template executions that run only if the previous templates get matched.

```yaml
workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: lotus-domino
        subtemplates:
          - template: technologies/lotus-domino-version.yaml
            subtemplates:
              - template: cves/xx-yy-zz.yaml
                subtemplates:
                  - template: cves/xx-xx-xx.yaml
```

Conditional workflows are great examples of performing checks and vulnerability detection in most efficient manner instead of spraying all the templates on all the targets and generally come with good ROI on your time and is gentle for the targets as well.

More complete workflow examples are provided [here](https://nuclei.projectdiscovery.io/template-examples/workflow/)