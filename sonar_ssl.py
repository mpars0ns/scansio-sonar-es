import argparse
import sys
from multiprocessing import cpu_count, Process, Queue
import logging
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, scan
import hashlib
import gzip
import requests
import os

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


def process_hosts(q, es):
    """

    :param q: The Queue object that hosts should be pulled off of
    :param es: An Elasticsearch connection. This way each worker has its own connection and you don't have to share it
               across multiple workers/processes
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
        action = {"_op_type": "update", "_index": 'passive-ssl-hosts-sonar', "_type": "host", "_id": cert_hash,
                  "doc": line, "doc_as_upsert": "true"}
        bulk_hosts.append(action)
        if len(bulk_hosts) == 500:
            bulk(es, bulk_hosts)
            bulk_hosts = []


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
                newcert['source'] = 'sonar'
                newcert_action = {"_index": "passive-ssl-certs-sonar", "_type": "cert", '_id': newcert['hash_id'],
                                  '_source': newcert}
                bulk_certs.append(newcert_action)
            if len(bulk_certs) == 500:
                bulk(es, bulk_certs)
                bulk_certs = []


def parse_certs_file(gzfile, queue):
    if gzfile == '20131030-20150518_certs.gz':
        filedate = None
    else:
        filedate = gzfile[0:7]
    logger.warning("Opening file {f} at {d}".format(f=gzfile, d=datetime.now()))
    with gzip.open(gzfile, 'rb') as certfile:
        for line in certfile:
            raw_cert = dict()
            (certhash, cert) = line.split(',', 1)
            raw_cert['time'] = filedate
            raw_cert['certs'] = cert
            if raw_cert:
                queue.put(raw_cert)
    logger.warning("Closing file {f} at {d}".format(f=gzfile, d=datetime.now()))


def parse_hosts_file(gzfile, queue):
    logger.warning("Opening file {f} at {d}".format(f=gzfile, d=datetime.now()))
    with gzip.open(gzfile, 'rb') as hostsfile:
        filedate = gzfile[0:7]
        for line in hostsfile:
            (host, certhash) = line.split(',', 1)
            host_data = dict()
            host_data['hash'] = certhash
            host_data['host'] = host
            host_data['source'] = 'sonar'
            host_data['last_seen'] = filedate
            if gzfile == '20131030_hosts.gz': #  this is only done on the very first imported file
                host_data['first_seen'] = filedate
            queue.put(host_data)
    logger.warning("Closing file {f} at {d}".format(f=gzfile, d=datetime.now()))


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', default=DEFAULT_SERVER,
                        help=u'Elasticsearch hostname or IP (default {0})'.format(DEFAULT_SERVER))
    parser.add_argument('--port', default=DEFAULT_PORT,
                        help=u'Elasticsearch port (default {0})'.format(DEFAULT_PORT))
    args = parser.parse_args(argv[1:])

    workers = cpu_count()
    process_hosts_queue = Queue(maxsize=20000)
    process_certs_queue = Queue(maxsize=20000)

    es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=30)

    imported_sonar = es.search(index='scansio-sonar-ssl-imported', body={"size": 3000, "query": {"match_all": {}}})
    imported_files = []

    for f in imported_sonar['hits']['hits']:
        imported_files.append(f['_id'])

    scansio_feed = requests.get('https://scans.io/json')
    if scansio_feed.status_code == 200:
        feed = scansio_feed.json()
        if 'studies' in feed:
            for result in feed['studies']:
                if result['name'] == 'SSL Certificates':
                    for res in result['files']:
                        scans_file = res['name']
                        if scans_file.endswith('certs.gz'):
                            if scans_file.endswith('20131030-20150518_certs.gz'):
                                certfile = '20131030-20150518_certs.gz'
                            else:
                                certfile = scans_file[48:65]
                            if certfile not in imported_files:
                                logger.warning("We don't have {file} imported lets download it".format(file=certfile))
                                phys_file = requests.get(scans_file)
                                newcerts = open('{f}'.format(f=certfile), 'wb')
                                newcerts.write(phys_file.content)
                                newcerts.close()
                                newcerts = open('{f}'.format(f=certfile))
                                h = hashlib.sha1
                                h.update(newcerts.read())
                                sha1 = h.hexdigest()
                                newcerts.close()
                                if sha1 == res['fingerprint']:
                                    for w in xrange(workers):
                                        queue_es = Elasticsearch([{u'host': args.server, u'port': args.port}],
                                                                 timeout=30)
                                        p = Process(target=process_scan_certs, args=(process_certs_queue, queue_es))
                                        p.daemon = True
                                        p.start()
                                    logger.warning("Importing {f} at {d}".format(f=certfile, d=datetime.now()))
                                    parse_certs_file(certfile, process_certs_queue)
                                    for w in xrange(workers):
                                        process_certs_queue.put("DONE")
                                    logger.warning("Importing finished of {f} at {d}".format(f=certfile,
                                                                                             d=datetime.now()))
                                    es.index(index='scansio-sonar-ssl-imported', doc_type='imported-file', id=certfile,
                                             body={'file': certfile, 'imported_date': datetime.now(), 'sha1': sha1})
                                else:
                                    logger.error("SHA1 did not match for {f} it was not imported".format(f=certfile))
                                os.remove(certfile)
                                # Now we should optimize each index to max num segments of 1 to help with
                                # searching/sizing and just over all es happiness
                                logger.warning("Optimizing index: {index} at {date}".
                                               format(index='passive-ssl-certs-sonar', date=datetime.now()))
                                refresh_es.indices.optimize(index='passive-ssl-certs-umich',
                                                            max_num_segments=1, request_timeout=7500)
                        if scans_file.endswith('hosts.gz'):
                            hostsfile = scans_file[48:65]
                            if hostsfile not in imported_files:
                                logger.warning("We don't have {file} imported lets download it".format(file=hostsfile))
                                phys_host_file = requests.get(scans_file)
                                newhosts = open('{f}'.format(f=hostsfile), 'wb')
                                newhosts.write(phys_host_file.content)
                                newhosts.close()
                                newhosts = open('{f}'.format(f=hostsfile))
                                h = hashlib.sha1()
                                h.update(newhosts.read())
                                sha1 = h.hexdigest()
                                newhosts.close()
                                if sha1 == res['fingerprint']:
                                    for w in xrange(workers):
                                        queue_es = Elasticsearch([{u'host': args.server, u'port': args.port}],
                                                                 timeout=30)
                                        p = Process(target=process_hosts, args=(process_hosts_queue, queue_es))
                                        p.daemon = True
                                        p.start()
                                    logger.warning("Importing {f} at {d}".format(f=hostsfile, d=datetime.now()))
                                    parse_hosts_file(hostsfile, process_hosts_queue)
                                    logger.warning("Hosts updated for {f} now going back and updating first_seen"
                                                   .format(f=hostsfile))
                                    #  this is kinda dirty but without looking up everything at insert time (slow)
                                    #  I don't know of a better way to do
                                    #  this based on the number of documents we will have
                                    update_es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=30)
                                    # construct an elasticsearch query where the filter is looking for any entry
                                    # that is missing the field first_seen
                                    q = {'size': 500, "query": {"match_all": {}},
                                         "filter": {"missing": {"field": "first_seen"}}}
                                    new_updates = update_es.search(index='passive-ssl-hosts-sonar', body=q)
                                    logger.warning("Numer of hosts to update is {count}"
                                                   .format(count=new_updates['hits']['total']))
                                    # Scan across all the documents missing the first_seen field and bulk update them
                                    missing_first_seen = scan(update_es, query=q, scroll='30m',
                                                              index='passive-ssl-hosts-sonar')
                                    bulk_miss = []
                                    for miss in missing_first_seen:
                                        last_seen = miss['_source']['last_seen']
                                        first_seen = last_seen
                                        action = {"_op_type": "update", "_index": "passive-ssl-hosts-sonar",
                                                  "_type": "host", "_id": miss['_id'],
                                                  "doc": {'first_seen': first_seen}}
                                        bulk_miss.append(action)
                                        if len(bulk_miss) == 500:
                                            bulk(update_es, bulk_miss)
                                            bulk_miss = []

                                    #  Get the remaining ones that are less than 500 and the loop has ended
                                    bulk(update_es, bulk_miss)
                                    logger.warning("Importing finished of {f} at {d}".format(f=hostsfile,
                                                   d=datetime.now()))
                                    es.index(index='scansio-sonar-ssl-imported', doc_type='imported-file', id=certfile,
                                             body={'file': certfile, 'imported_date': datetime.now(), 'sha1': sha1})
                                else:
                                    logger.error("SHA1 did not match for {f} it was not imported".format(f=hostsfile))
                                os.remove(hostsfile)
                                # Now we should optimize each index to max num segments of 1 to help with
                                # searching/sizing and just over all es happiness
                                refresh_es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=30)
                                logger.warning("Optimizing index: {index} at {date}".
                                               format(index='passive-ssl-hosts-sonar', date=datetime.now()))
                                refresh_es.indices.optimize(index='passive-ssl-hosts-sonar',
                                                            max_num_segments=1, request_timeout=7500)

        else:
            logger.error("The scans.io/json must have changed or is having issues. I didn't see any studies. Exiting")
            sys.exit()
    else:
        logger.error("There was an error connecting to https://scans.io. I did not get a 200 status code. Exiting")
        sys.exit()

if __name__ == '__main__':
    main(sys.argv)