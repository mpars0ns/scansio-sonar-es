When I started this project SSL Certs weren't being displayed by passivetotal or the awesome new effort by 
https://censys.io/. With that being said I think being able to have this data locally and searchable for your own 
efforts is useful.

The current implementation is to take the sonar ssl scans https://scans.io/study/sonar.ssl and the umich daily scans 
~~https://scans.io/series/443-https-tls-full_ipv4~~ (this data set is no longer valid as of 10/14/2015)
and put them in separate indexes:

Certificate Related
passive-ssl-certs-sonar
passive-ssl-certs-umich

Host Related
passive-ssl-hosts-sonar
passive-ssl-certs-umich

Then we will create an alias for searching:
passive-ssl-certs
passive-ssl-hosts

The certs indexes are the results of parsing the raw base64 certificate that is provided both by sonar and umich in 
their scans. I initially used some of the code in this <a href="https://gist.github.com/major/9606037gist">gist</a> 
to get my creative juices flowing and have expanded on it from there.

The hosts indexes are the SHA1 hash of the certificate to IP mapping with a little bit of geolocation and 
asn enrichment (pew pew map anyone?)

#Usage#
##Install Requirements##
You will need a few python libraries. Just install them with the following
`$sudo pip install -r requirements.txt `

##Update GEOIP##
You will need to download/update the GeoLite from maxmind. To do that run the update_geoip.sh script

`$ sh update_geoip.sh`

##Create Indexes##
First start by creating the elastic search indexes we need by running:

`$ python make_indexes.py --server localhost --port 9200 `

Feel free to change --server and --port for your needs

##General Usage##
Once the indexes are created I suggest you try downloading the rapid7 sonar ssl data. If you can do this from a host 
with a lot of cores it will speed up pushing it to your elasticsearch instance/cluster. 

To download the sonar ssl data the command is:

`$ python sonar_ssl.py --server localhost --port 9200`

Again you can change your server/port as needed. This will start to spider all the certs and hosts files that are part 
of the sonar ssl scans. This will take several days to run :) so have it going under screen will be helpful.

The first file you have to grab from sonar is about 25gb the last time I checked. This will take a while to download 
about 3 hours in my testing. So please be patient.


#Licenses#

MaxMind GeoIP Databases used under CC licence
This product includes GeoLite data created by MaxMind, available from maxmind.com.









