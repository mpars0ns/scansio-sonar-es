#!/bin/sh

wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
gunzip GeoIP.dat.gz
mv GeoIP.dat geoip/.
gunzip GeoIPASNum.dat.gz
mv GeoIPASNum.dat geoip/.
