# xss-finder

## Overview
This tool checks a URL for XSS vulnerabilities. 
It starts with an initial entry point URL and then recursively searches for XSS vulnerabilities in all HTML links.

A sqlite database is created to store processing urls and injectable parameters. The database schema is automatically created if it does not exist (for example first execution or changed database location with [--output | -o] option.

## Build
1. Clone this repo locally
2. Make sure to have [Apache Maven](http://maven.apache.org/) installed
3. Execute ```mvn clean install```

## Additional build features
- Please note that tests run automatically as part of the normal build compilation. If you want to ommit tests run ```mvn clean install -DskipTests```
- A docker image is provided by running maven with the profile "docker": ```mvn clean install -P docker -DskipTests``

## Usage
Multithreading is supported by adding the option [--threads | -t]. By default the value is 1. Any new link to be processed is intended to be executed by a new thread (managed by a fix thread pool).
If needed, cookies can be send along with HTTP requests; for this [--cookies | -c] must be added as an option.

There are some other options showed below in command usage.

Usage: <main class> [options]
  Options:
    --cookies, -c
      Specify any useful cookie
    --help, -h
      Display usage information
    --output, -o
      Output directory of sqlite database named 'xss-finder.db'
      Default: ./
    --threads, -t
      Maximum number of threads
      Default: 1
  * --url, -u
      Url to scan for XSS vulnerabilities
    --verbose, -v
      Display verbosity
      Default: false


## Docker image
In order to run the docker image execute ```docker run <image_id> <command_line_arguments>```




