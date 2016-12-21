# Arachne [![GoDoc][doc-img]][doc] [![Build Status][ci-img]][ci] 

Arachne is a packet loss detection system and an underperforming path detection
system. It provides fast and easy active end-to-end functional testing
of all the components in Data Center and Cloud infrastructures.
Arachne is able to detect intra-DC, inter-DC, DC-to-Cloud, and
DC-to-External-Services issues by generating minimal traffic:
 
- Reachability
- Round-trip and 1-way latency
- Silent packet drops and black holes
- Jitter (average of the deviation from the network mean latency)
- PMTU or Firewall issues too related possibly to network config changes
(accidental or not)
- Network-level SLAs are met?


## Usage


Either import this package and call Arachne from your service with
```go
    arachne.Run(config, arachne.ReceiverOnlyMode(false))
```
where the option provided above is among the few optional ones,

or run Arachne as a standalone program (it's Debian packaged already too).

Below is the list of all the CLI options available. The default options should
be good enough for most users.



```
$ arachne --help

____________________________________________________________/\\\______________________________________
 ___________________________________________________________\/\\\______________________________________
  ___________________________________________________________\/\\\______________________________________
   __/\\\\\\\\\_____/\\/\\\\\\\___/\\\\\\\\\________/\\\\\\\\_\/\\\__________/\\/\\\\\\_______/\\\\\\\\__
    _\////////\\\___\/\\\/////\\\_\////////\\\_____/\\\//////__\/\\\\\\\\\\__\/\\\////\\\____/\\\/////\\\_
     ___/\\\\\\\\\\__\/\\\___\///____/\\\\\\\\\\___/\\\_________\/\\\/////\\\_\/\\\__\//\\\__/\\\\\\\\\\\__
      __/\\\/////\\\__\/\\\__________/\\\/////\\\__\//\\\________\/\\\___\/\\\_\/\\\___\/\\\_\//\\///////___
       _\//\\\\\\\\/\\_\/\\\_________\//\\\\\\\\/\\__\///\\\\\\\\_\/\\\___\/\\\_\/\\\___\/\\\__\//\\\\\\\\\\_
        __\////////\//__\///___________\////////\//_____\////////__\///____\///__\///____\///____\//////////__


Usage: arachne [--foreground] [-c=<config_file_path>] [--receiver_only] [--sender_only] [--orchestrator]

Utility to echo the Uber DC and Cloud Infrastructure

Options:
  -v, --version                                     Show the version and exit
  --foreground=false                                Force foreground mode
  -c, --config="/etc/arachne/arachne_config.json"   Configuration file path
  (by default in /etc/arachne/)
  --receiver_only=false                             Force TCP receiver-only mode
  --sender_only=false                               Force TCP sender-only mode
  --orchestrator=false                              Force orchestrator mode
```


### Note on required privileges to run

Arachne is granted access to raw sockets without the need to run with sudo or
as root user, by being granted`CAP_NET_RAW` capability
(see: [capabilities][]).


## License

Copyright (c) 2016 Uber Technologies, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

[doc-img]: https://godoc.org/github.com/uber/arachne?status.svg
[doc]: https://godoc.org/github.com/uber/arachne
[ci-img]: https://travis-ci.org/uber/arachne.svg?branch=master
[ci]: https://travis-ci.org/uber/arachne
[capabilities]: http://linux.die.net/man/7/capabilities