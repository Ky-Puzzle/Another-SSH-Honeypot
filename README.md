# Another-SSH-Honeypot

WiP

This is just another SSH Honeypot with an added "find out where the ip address is coming from" functionality (optional and shouldn't be used to identify addresses or households).

## How to Use:

*Required libraries: paramiko and geoip2*
    
    pip install paramiko
    pip install geoip2
    

*Will need the maxmind free databases if you want to use the functionality that tells you information about the ip address. Located at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data. Requires an account*


Example Usage:  

    python3 Another_SSH-Honeypot --p 2222 --h 0.0.0.0

OPTIONS:  
    
    To set the port: --p
    To set the host: --h
    To set the location of the GeoIP City DB: --c
    To set the location of the GeoIP Country: --a
    To set the banner: --b
    
    
 NOTE: SSH Honeypot does not require the GeoIP databases (the script will still run as designed), but if you want to gather information on public IP addresses that connect to the honeypot you will need the databases


  
 
