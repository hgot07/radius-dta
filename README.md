# RADIUS-DTA: Disruption-Tolerant Authentication demo

## Description

This is a PoC implementation of the method presented in  
Hideaki Goto, "Disruption-tolerant Local Authentication Method
for Network Roaming Systems," Journal of Information Processing (JIP),
Vol. 32,  pp.407-416, 2024.  
[https://doi.org/10.2197/ipsjjip.32.407](https://doi.org/10.2197/ipsjjip.32.407)

This demo script generates a random User-Name, and emulates
Local Authentication.

## Usage
1. Open **dtauth-poc.pl** by a text editor, and set your own realm and HMAC key.
2. Run **make** command to generate an EC key pair.
3. Install required perl modules if the following command line shows any missing ones.  
 $ perl -c dtauth-poc.pl
4. Run the script by  
 $ perl dtauth-poc.pl

## TIPS for buiding a real AAA system
It is strongly recommended to use a web-based provisioning system.
For example, 
- [Passpoint Provisioning Tools](https://github.com/hgot07/PasspointProvisioningTools)
- [eduroam Provisioning Tools](https://github.com/hgot07/eduroamProvisioningTools) 

would help you develop a profile issuing website.

FreeRADIUS supports Perl script execution.
You can realize the Local Authentication by writing a short code.

