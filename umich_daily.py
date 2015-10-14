import argparse
import sys
from multiprocessing import cpu_count, Process, Queue
import json
import logging
from datetime import datetime

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, scan
import hashlib

from helpers.certparser import process_cert
from helpers.hostparser import proccess_host

logger = logging.getLogger('SSLImporter')
logger_format = logging.Formatter('\033[1;32m%(levelname)-5s %(module)s:%(funcName)s():%(lineno)d %(asctime)s\033[0m| '
                                  '%(message)s')
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logger_format)
logger.addHandler(stream_handler)

elastic_logger = logging.getLogger('elasticsearch')
elastic_logger.addHandler(stream_handler)

DEFAULT_SERVER = u'localhost'
DEFAULT_PORT = 9200


def process_scan_certs(q, es):
    """
    :param q: The Queue object that certs should be pulled off of
    :param es: An Elasticsearch connection. This way each worker has its own connection and you don't have to share it
               across multiple workers/processes
    :return:
    """
    bulk_certs = []
    while True:
        certs = q.get()
        if certs == "DONE":
            bulk(es, bulk_certs)
            return True
        for cert in certs['certs']:
            newcert = process_cert(cert)
            if newcert:
                newcert['import_date'] = certs['time']
                newcert['source'] = 'umich'
                newcert_action = {"_index": "passive-ssl-certs-umich", "_type": "cert", '_id': newcert['hash_id'],
                                  '_source': newcert}
                bulk_certs.append(newcert_action)
            if len(bulk_certs) == 500:
                bulk(es, bulk_certs)
                bulk_certs = []


def process_hosts(q, es, initial):
    """

    :param q: The Queue object that hosts should be pulled off of
    :param es: An Elasticsearch connection. This way each worker has its own connection and you don't have to share it
               across multiple workers/processes
    :param initial: If this is the initial upload then we set the first_seen = last_seen. Other wise first_seen is left
           blank and will be cleaned up later
    :return:
    """
    bulk_hosts = []

    while True:
        line = q.get()
        if line == "DONE":
            bulk(es, bulk_hosts)
            return True
        host = proccess_host(line)
        cert_hash = hashlib.sha1(host['host']+host['hash']+host['source'])
        cert_hash = cert_hash.hexdigest()
        if initial:
            host['first_seen'] = host['last_seen']
        action = {"_op_type": "update", "_index": 'passive-ssl-hosts-umich', "_type": "host", "_id": cert_hash,
                  "doc": line, "doc_as_upsert": "true"}
        bulk_hosts.append(action)
        if len(bulk_hosts) == 500:
            bulk(es, bulk_hosts)
            bulk_hosts = []


def parse_scanfile(f, host_queue, cert_queue):
    """

    :param f:  json file from University of Michigan that has been lz4 decompressed.
    :param host_queue: Queue to send host info to
    :param cert_queue: Queue to send cert info to
    :return:
    """
    certs_set = set()
    with open(f) as scan_file:
        for line in scan_file:
            item = json.loads(line)
            item['log'].pop(0)
            for entry in item['log']:
                if entry['data']:
                    if 'server_certificates' in entry['data'] and entry['data']['server_certificates'] is not None:
                        if entry['data']['server_certificates']['certificate'] is not None:
                            if 'fingerprint_sha1' in entry['data']['server_certificates']['certificate']:
                                server_cert = entry['data']['server_certificates']['certificate']['fingerprint_sha1']
                                doc = {'host': item['host'], 'source': 'umich', 'last_seen': item['time'],
                                       'hash': server_cert}
                                host_queue.put(doc)
                                if server_cert in certs_set:
                                    pass  # We already have this sha1 and we don't need to attempt parsing it
                                else:
                                    if entry['data']['server_certificates']['certificate'] is not None:
                                        if 'raw' in entry['data']['server_certificates']:
                                            raw_cert = dict()
                                            raw_cert['time'] = item['time']
                                            raw_cert['certs'] = entry['data']['server_certificates']['raw']
                                        else:
                                            raw_cert = None
                                        if raw_cert:
                                            cert_queue.put(raw_cert)
                                            certs_set.add(server_cert)  # We have added this hash to be processed so we
                                            #  don't need to process it again
        print "Finished processing file....now printing the length of the certs set"
        print len(certs_set)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', default=DEFAULT_SERVER,
                        help=u'Elasticsearch hostname or IP (default {0})'.format(DEFAULT_SERVER))
    parser.add_argument('--port', default=DEFAULT_PORT,
                        help=u'Elasticsearch port (default {0})'.format(DEFAULT_PORT))
    parser.add_argument('--scanfile', help=u'Path to umich scan file you are ingesting. '
                                           u'Please make sure to decompress it')
    parser.add_argument('--initial', help=u'If this is the first file you are importing please use this flag',
                        action='store_true')
    args = parser.parse_args(argv[1:])

    if args.scanfile is None:
        logger.error("Please include a scanfile")
        sys.exit(1)

    workers = cpu_count()
    process_hosts_queue = Queue(maxsize=20000)
    process_certs_queue = Queue(maxsize=20000)

    for w in xrange(workers/2):
        #  Establish elasticsearch connection for each process
        es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=30)
        p = Process(target=process_hosts, args=(process_hosts_queue, es, args.initial))
        p.daemon = True
        p.start()

    for w in xrange(workers/2):
        #  Establish elasticsearch connection for each process
        es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=30)
        p = Process(target=process_scan_certs, args=(process_certs_queue, es))
        p.daemon = True
        p.start()

    logger.warning("Starting processing of {file} at {date}".format(file=args.scanfile, date=datetime.now()))

    # This is the bottle neck of the process but it works for now
    parse_scanfile(args.scanfile, process_hosts_queue, process_certs_queue)

    #  Once all the json lines have been put onto the queue. Add DONE so the queue workers know when to quit.
    for w in xrange(workers):
        process_hosts_queue.put("DONE")
        process_certs_queue.put("DONE")

    #  Close out the queue we are done
    process_hosts_queue.close()
    process_hosts_queue.join_thread()
    process_certs_queue.close()
    process_certs_queue.join_thread()

    #  this is kinda dirty but without looking up everything at insert time (slow) I don't know of a better way to do
    #  this based on the number of documents we will have
    refresh_es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=30)
    # construct an elasticsearch query where the filter is looking for any entry that is missing the field first_seen
    q = {'size': 500, "query": {"match_all": {}}, "filter": {"missing": {"field": "first_seen"}}}

    new_updates = refresh_es.search(index='passive-ssl-hosts-umich', body=q)

    logger.warning("Numer of hosts to update is {count}".format(count=new_updates['hits']['total']))

    # Scan across all the documents missing the first_seen field and bulk update them
    missing_first_seen = scan(refresh_es, query=q, scroll='30m', index='passive-ssl-hosts-umich')

    bulk_miss = []
    for miss in missing_first_seen:
        last_seen = miss['_source']['last_seen']
        first_seen = last_seen
        action = {"_op_type": "update", "_index": "passive-ssl-hosts-umich", "_type": "host", "_id": miss['_id'],
                  "doc": {'first_seen': first_seen}}
        bulk_miss.append(action)
        if len(bulk_miss) == 500:
            bulk(refresh_es, bulk_miss)
            bulk_miss = []

    #  Get the remaining ones that are less than 000 and the loop has ended
    bulk(refresh_es, bulk_miss)
    logger.warning("{file} import finished at {date}".format(file=args.scanfile, date=datetime.now()))

    # Now we should optimize each index to max num segments of 1 to help with searching/sizing and just over all
    # es happiness
    logger.warning("Optimizing index: {index} at {date}".format(index='passive-ssl-hosts-umich', date=datetime.now()))
    refresh_es.indices.optimize(index='passive-ssl-hosts-umich', max_num_segments=1, request_timeout=7500)
    logger.warning("Optimizing index: {index} at {date}".format(index='passive-ssl-certs-umich', date=datetime.now()))
    refresh_es.indices.optimize(index='passive-ssl-certs-umich', max_num_segments=1, request_timeout=7500)

if __name__ == "__main__":
    main(sys.argv)
