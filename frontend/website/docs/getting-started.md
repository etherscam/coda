# Getting Started

This section will walk you through the requirements needed to run a Coda protocol node on your local machine and connect to the network.

!!! note
    Last updated for release v0.0.1

## Requirements

**Software**: macOS (10.x.x and above) or Linux (currently supports Debian 9 and Ubuntu 18.04 LTS)

**Hardware**: Sending and receiving coda does not require any special hardware, but participating as a node operator currently requires:
- at least a 4-core processor
- at least 8 GB of RAM

GPU's aren't currently required, but may be required for node operators when the protoctol is upgraded.

**Network**: At least 1 Mbps connection

## Installation

The newest binary releases can be found below. Instructions are provided for macOS and Linux below:

### macOS

- Download [coda.zip](https://s3-us-west-2.amazonaws.com/wallet.o1test.net/coda-daemon-macos.zip) -- NOTE: This is a large file (~2.2 GB), so this step might take some time
- Unzip anywhere, `cd` to navigate to the Coda directory. This directory will contain a coda binary, a kademlia binary, related libraries, and the proving and verification keys.
- These next commands make sure the proving and verification keys for SNARK checking are in the right place. Run
```
sudo mkdir /var/lib/coda
sudo cp var/lib/coda/* /var/lib/coda
```
- Run `brew install miniupnpc` to install [MiniUPnP client](https://github.com/miniupnp/miniupnp). You'll need Homebrew installed on your system.
- Set up port forwarding ([see below](/docs/getting-started/#port-forwarding))
- Run `export PATH=$PWD:$PATH` so we can access `coda` instead of `./coda`
- `coda -help` to see if it works

### Linux (Ubuntu 18.04 / Debian 9)

- Add the Coda debian repo and install -- NOTE: This is a large file (~2.2 GB), so this step might take some time

```
sudo echo "deb [trusted=yes] http://packages.o1test.net unstable main" > /etc/apt/sources.list.d/coda.list
sudo apt-get update
sudo apt-get install --force-yes -t unstable coda-testnet-postake-medium-curves=0.0.1-release-beta-8afe7755 -y
```

- You'll need forward some ports. Run `apt-get install miniupnpc` to install [MiniUPnP client](https://github.com/miniupnp/miniupnp). When running in the cloud this is unnecessary, instead you should configure security groups for your cloud provider. See below for more info on this.
- `coda -help` to see if it works


### Windows

Windows is not yet supported. If you have any interest in developing Coda for Windows, please reach out to contact@codaprotocol.org or reach out in the [Discord server](https://discord.gg/ShKhA7J).

### Build from source (other Linux distros; macOS)

To build from source code, please follow [the instructions in the Coda protocol repo](https://github.com/CodaProtocol/coda/blob/master/README-dev.md#building-coda).

## Port forwarding

If you're running a Coda node on a home or office machine, you'll have to set up [port forwarding](https://en.wikipedia.org/wiki/Port_forwarding) to make your node visible on the internet to other Coda nodes.

Run the following commands to use MiniUPnP to reconfigure ports on your IP address:

1. First run `ifconfig` to get your internal IP address - you can find this in the output corresponding to the field `en0` on macOS and `wlan0` on a linux system:


        $ ifconfig
        ...
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                ether 8c:85:90:c9:a2:01 
                inet6 fe80::1458:bdd4:e7dc:518e%en0 prefixlen 64 secured scopeid 0x8 
                inet 192.168.101.7 netmask 0xffffff00 broadcast 192.168.101.255
                nd6 options=201<PERFORMNUD,DAD>
                media: autoselect
                status: active
        ...

2. Then run the following commands, with the IP address next to the `inet` field in the previous step. Note that you'll have to run it twice for the two ports below:

        $ sudo upnpc -a 192.168.101.7 8302 8302 TCP
        $ sudo upnpc -a 192.168.101.7 8303 8303 UDP

If these commands succeed, you will have successfully forwarded ports `8302` & `8303`. Otherwise, you may see the following error messages:

    No IGD UPnP Device found on the network !

Or

    connect: Connection refused

If so, find your router model and Google `<model> port forwarding` and follow the instructions to forward the ports from your router to your device running the Coda node. You'll need to open the TCP port 8302, and the UDP port 8303 by default.

## Next

Now that you've installed the Coda binary and configured settings, let's move on to the fun part - [sending a transaction](/docs/my-first-transaction/)!