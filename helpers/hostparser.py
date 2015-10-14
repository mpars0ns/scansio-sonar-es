import pygeoip

gi_country = pygeoip.GeoIP('geoip/GeoIP.dat', pygeoip.MEMORY_CACHE)
gi_asn = pygeoip.GeoIP('geoip/GeoIPASNum.dat', pygeoip.MEMORY_CACHE)


def proccess_host(host):
    """

    :param host: This should be a dict where host['host'] is an ip address
    :return:
    """
    host['country_code'] = gi_country.country_code_by_addr(host['host'])
    host['country_name'] = gi_country.country_name_by_addr(host['host'])
    host['asn'] = gi_asn.asn_by_addr(host['host'])
    return host

