# Arachne [![GoDoc][doc-img]][doc] [![Build Status][ci-img]][ci] [![Go Report Card][gorep-img]][gorep]

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
- Whether network-level SLAs are met

## Usage

There are two ways to use the Arachne package.

### As a standalone program
Run Arachne as a standalone program (it's Debian packaged already too).

### As a library in your own program
Import this package and call Arachne from your program/service with
```go
    arachne.Run(config, arachne.ReceiverOnlyMode(false))
```
where the option provided above is among the few optional ones.


Below is the list of all the CLI options available, when Arachne is
used as a standalone program. The default options should be good
enough for most users.

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


Usage: arachne [--foreground] [-c=<config_file>] [--receiver_only] [--sender_only]

Arachne is a packet loss detection system and an underperforming path detection
system for Data Center and Cloud infrastructures.

Options:
  -v, --version                                     Show the version and exit
  --foreground=false                                Force foreground mode
  -c, --config_file="/usr/local/etc/arachne/arachne.yaml"     Config file path
  (default: /usr/local/etc/arachne/arachne.yaml)
  --receiver_only=false                             Force TCP receiver-only mode
  --sender_only=false                               Force TCP sender-only mode
```


### Note on required privileges to run

Arachne is granted access to raw sockets without the need to run with sudo or
as root user, by being granted `CAP_NET_RAW` capability
(see: [capabilities][]).


### Note on BPF filtering

When receiving packets, Arachne attempts to apply a BPF filter to the raw socket
so that processing of packets occurs on a much smaller set (ones destined
specifically for Arachne agent testing). This is currently supported only on
Linux and thus performance will be worse on BSD-based systems where a larger
number of packets must be inspected.

<hr>

Released under the [MIT License](LICENSE.md).


[doc-img]: https://godoc.org/github.com/uber/arachne?status.svg
[doc]: https://godoc.org/github.com/uber/arachne
[ci-img]: https://travis-ci.org/uber/arachne.svg?branch=master
[ci]: https://travis-ci.org/uber/arachne
[capabilities]: http://linux.die.net/man/7/capabilities
[gorep-img]: https://goreportcard.com/badge/github.com/uber/arachne
[gorep]: https://goreportcard.com/report/github.com/uber/arachne
