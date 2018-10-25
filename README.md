# AVVEM
AWS VPC VPN Endpoint Manager

## Introduction
AVVEM is a script that both creates a VPN Connection associated with a VGW and configures IPSec to connect to it. It was created to allow VPN Connections to be built and torn down as needed, rather than paying for them to merely exist, even when they are not in use.

The design also considers the presence of the desired VPN Connection within the VPC and will reuse it if an address is available. The intention is to allow the script to be used in a high-availability setup.

## Status
It mostly works, but this code is crap. It was written to serve a personal need at the time and doesn't get much love now. Beyond creating and destroying connections from the host it was developed on, it hasn't been tested.
