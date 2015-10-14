from elasticsearch import Elasticsearch
import json
import argparse
import sys
import logging
from datetime import datetime

logger = logging.getLogger('SSLIndexCreator')
logger_format = logging.Formatter('\033[1;32m%(levelname)-5s %(module)s:%(funcName)s():%(lineno)d %(asctime)s\033[0m| '
                                  '%(message)s')
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logger_format)
logger.addHandler(stream_handler)

elastic_logger = logging.getLogger('elasticsearch')
elastic_logger.addHandler(stream_handler)


DEFAULT_SERVER = u'localhost'
DEFAULT_PORT = 9200


def create_host_index(es, index_name):
    """
    :param es: Elasticsearch Connection
    :param index_name: name of index to be created
    :return:

    This will create the index. If the index already exists it will see the 400 error and just move on
    """

    hosts_map_json = open('mappings/hosts-mapping.json')
    hosts_mapping = json.load(hosts_map_json)
    host_settings = dict({"settings": {"number_of_shards": 5, "number_of_replicas": 0}})
    host_settings['mappings'] = hosts_mapping
    es.indices.create(index=index_name, body=host_settings, ignore=400)


def create_cert_index(es, index_name):
    """

    :param es: Elasticsearch Connection
    :param index_name: name of index to be created
    :return:
    """
    certs_map_json = open('mappings/certs-mapping.json')
    certs_mapping = json.load(certs_map_json)
    certs_settings = dict({"settings": {"number_of_shards": 5, "number_of_replicas": 0}})
    certs_settings['mappings'] = certs_mapping
    es.indices.create(index=index_name, body=certs_settings, ignore=400)


def create_sonar_imported_index(es, index_name):
    index_settings = dict({"settings": {"number_of_shards": 5, "number_of_replicas": 0}})
    es.indices.create(index=index_name, body=index_settings, ignore=400)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', default=DEFAULT_SERVER,
                        help=u'Elasticsearch hostname or IP (default {0})'.format(DEFAULT_SERVER))
    parser.add_argument('--port', default=DEFAULT_PORT,
                        help=u'Elasticsearch port (default {0})'.format(DEFAULT_PORT))

    args = parser.parse_args(argv[1:])
    create_es = Elasticsearch([{u'host': args.server, u'port': args.port}])
    create_host_index(create_es, 'passive-ssl-hosts-umich')
    create_cert_index(create_es, 'passive-ssl-certs-umich')
    create_host_index(create_es, 'passive-ssl-hosts-sonar')
    create_cert_index(create_es, 'passive-ssl-certs-sonar')
    create_es.indices.put_alias(index="passive-ssl-hosts-umich,passive-ssl-hosts-sonar", name='passive-ssl-hosts')
    create_es.indices.put_alias(index="passive-ssl-certs-umich,passive-ssl-certs-sonar", name='passive-ssl-certs')
    create_sonar_imported_index(create_es, 'scansio-sonar-ssl-imported')
    create_sonar_imported_index(create_es, 'scansio-umich-ssl-imported')

if __name__ == "__main__":
    main(sys.argv)
    logger.warning("Indexes have been created. Start indexing scans.io ssl at will now :)")