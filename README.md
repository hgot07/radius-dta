# RADIUS-DTA: Disruption-Tolerant Authentication demo

## Description

This is a Proof-of-Concept (PoC) implementation of 
the local authentication method presented in the following paper.  

Hideaki Goto, "Disruption-tolerant Local Authentication Method
for Network Roaming Systems," Journal of Information Processing (JIP),
Vol. 32,  pp.407-416, 2024.  
[https://doi.org/10.2197/ipsjjip.32.407](https://doi.org/10.2197/ipsjjip.32.407)

The demo script generates a random User-Name, and emulates
Local Authentication.

The DTA method realizes Local Authentication using some distributed 
AAA (Authentication, Authorization, and Accounting) servers
without copying a large user database.
Each local AAA server holds
an HMAC (Hash-based Message Authentication Code) key
and an ECDSA (Elliptic Curve Digital Signature Algorithm) public key.
The password is derived from the user name using the HMAC key.

The presented method is compatible with some existing 
EAP methods including EAP-TTLS and PEAP.
MSCHAPV2 also works well.
The functionality has been confirmed on 
a wide variety of Operating Systems (OSs) including
Android, iOS/iPadOS, macOS, Windows 10 & 11, and ChromeOS.

Some potential use cases include In-Flight Wi-Fi,
Wi-Fi systems on cruise ships, 
secure public Wi-Fi tolerant of the network disruptions by disasters, etc.,
and scalable Wi-Fi systems with fast network connection.


## Usage
1. Open **dtauth-poc.pl** by a text editor, and set your own realm and HMAC key.
2. Run **make** command to generate an EC key pair.
3. Install required perl modules if the following command line shows any missing one.  
 $ perl -c dtauth-poc.pl
4. Run the script by  
 $ perl dtauth-poc.pl

## TIPS for buiding a real AAA system
It is strongly recommended to use a web-based provisioning system
because the generated User-Name is very long.
In addition, manual configuration of server authentication is cumbersome.

For example, 
- [Passpoint Provisioning Tools](https://github.com/hgot07/PasspointProvisioningTools)
- [eduroam Provisioning Tools](https://github.com/hgot07/eduroamProvisioningTools) 

would help you develop a profile issuing website.

FreeRADIUS provides Perl and Python modules.
You can implement the Local Authentication by writing a short script.

