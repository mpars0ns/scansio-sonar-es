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


def parse_hosts_file(gzfile, queue):
    logger.warning("Opening file {f} at {d}".format(f=gzfile, d=datetime.now()))
    with gzip.open(gzfile, 'rb') as hostsfile:
        filedate = gzfile[0:8]
        for line in hostsfile:
            (host, port, certhash) = line.split(',', 2)
            host_data = dict()
            host_data['hash'] = certhash.strip('\n')
            host_data['host'] = host
            host_data['source'] = 'sonar'
            host_data['port'] = port
            host_data['last_seen'] = datetime.strptime(filedate, "%Y%m%d")
            queue.put(host_data)
    logger.warning("Closing file {f} at {d}".format(f=gzfile, d=datetime.now()))


def process_hosts(q, es):
    """
    :param q: The Queue object that hosts should be pulled off of
    :param es: An Elasticsearch connection. This way each worker has its own connection and you don't have to share it
               across multiple workers/processes
    :param port: the port associated with the ssl scan that was done (25, 465, 993, 143 etc)
    :return:
    """
    bulk_hosts = []

    while True:
        line = q.get()
        if line == "DONE":
            bulk(es, bulk_hosts)
            return True
        host = proccess_host(line)
        cert_hash = hashlib.sha1(host['host']+host['hash']+host['source']+host['port'])
        cert_hash = cert_hash.hexdigest()
        action = {"_op_type": "update", "_index": 'passive-ssl-non443-hosts-sonar', "_type": "host", "_id": cert_hash,
                  "doc": host, "doc_as_upsert": "true"}
        bulk_hosts.append(action)
        if len(bulk_hosts) == 500:
            bulk(es, bulk_hosts)
            bulk_hosts = []


def update_hosts(q, es):
    bulk_update_hosts = []
    while True:
        hosts = q.get()
        if hosts == "DONE":
            bulk(es, bulk_update_hosts)
            return True
        last_seen = hosts['_source']['last_seen']
        first_seen = last_seen
        action = {"_op_type": "update", "_index": "passive-ssl-hosts-sonar", "_type": "host", "_id": hosts['_id'],
                  "doc": {'first_seen': first_seen}}
        bulk_update_hosts.append(action)
        if len(bulk_update_hosts) == 500:
            bulk(es, bulk_update_hosts)
            bulk_update_hosts = []


def process_scan_certs(q, es, port):
    """
    :param q: The Queue object that certs should be pulled off of
    :param es: An Elasticsearch connection. This way each worker has its own connection and you don't have to share it
               across multiple workers/processes
    :param port: the port associated with the ssl scan that was done (25, 465, 993, 143 etc)
    :return:
    """
    bulk_certs = []
    while True:
        certs = q.get()
        if certs == "DONE":
            bulk(es, bulk_certs)
            return True
        newcert = process_cert(certs['certs'])
        if newcert:
            newcert['import_date'] = certs['time']
            newcert['source'] = 'sonar'
            newcert['port'] = port
            cert_hash = hashlib.sha1(newcert['hash_id']+str(port)+newcert['source'])
            cert_hash = cert_hash.hexdigest()
            newcert_action = {"_index": "passive-ssl-non443-certs-sonar", "_type": "cert", '_id': cert_hash,
                              '_source': newcert}
            bulk_certs.append(newcert_action)
        if len(bulk_certs) == 500:
            bulk(es, bulk_certs)
            bulk_certs = []


def parse_certs_file(gzfile, queue):
    filedate = gzfile[0:8]
    logger.warning("Opening file {f} at {d}".format(f=gzfile, d=datetime.now()))
    with gzip.open(gzfile, 'rb') as certfile:
        for line in certfile:
            raw_cert = dict()
            (certhash, cert) = line.split(',', 1)
            raw_cert['time'] = datetime.strptime(filedate, "%Y%m%d")
            raw_cert['certs'] = cert
            if raw_cert:
                queue.put(raw_cert)
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
    update_hosts_queue = Queue(maxsize=20000)

    es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=60)

    imported_sonar = es.search(index='scansio-sonar-ssl-non443-imported', body={"size": 3000, "query": {"match_all": {}}
                                                                                })
    imported_files = []
    for f in imported_sonar['hits']['hits']:
        imported_files.append(f['_id'])

    scansio_feed = requests.get('https://scans.io/json')
    if scansio_feed.status_code == 200:
        feed = scansio_feed.json()
        if 'studies' in feed:
            for result in feed['studies']:
                if result['name'] == "More SSL Certificates (non-443)":
                    for res in result['files']:
                        scans_file = res['name']
                        if scans_file.endswith('certs.gz'):
                            if 'smtp_25' in scans_file:
                                certfile = scans_file[52:86]
                                port = 25
                            if 'smtp_465' in scans_file:
                                certfile = scans_file[52:82]
                                port = 465
                            if 'imap_993' in scans_file:
                                certfile = scans_file[52:82]
                                port = 993
                            if 'imap_143' in scans_file:
                                certfile = scans_file[52:87]
                                port = 143
                            if 'pop3_995' in scans_file:
                                certfile = scans_file[52:82]
                                port = 995
                            if certfile not in imported_files:
                                logger.warning("We don't have {file} imported lets download it".format(file=certfile))
                                phys_file = requests.get(scans_file, stream=True)
                                with open('{f}'.format(f=certfile), 'wb') as newcerts:
                                    for chunk in phys_file.iter_content(chunk_size=1024):
                                        if chunk:
                                            newcerts.write(chunk)
                                with open('{f}'.format(f=certfile), 'rb') as fh:
                                    h = hashlib.sha1()
                                    while True:
                                        data = fh.read(8192)
                                        if not data:
                                            break
                                        h.update(data)
                                sha1 = h.hexdigest()
                                if sha1 == res['fingerprint']:
                                    for w in xrange(workers):
                                        queue_es = Elasticsearch([{u'host': args.server, u'port': args.port}],
                                                                 timeout=60)
                                        p = Process(target=process_scan_certs, args=(process_certs_queue, queue_es,
                                                                                     port))
                                        p.daemon = True
                                        p.start()
                                    logger.warning("Importing {f} at {d}".format(f=certfile, d=datetime.now()))
                                    parse_certs_file(certfile, process_certs_queue)
                                    for w in xrange(workers):
                                        process_certs_queue.put("DONE")
                                    logger.warning("Importing finished of {f} at {d}".format(f=certfile,
                                                                                             d=datetime.now()))
                                    es.index(index='scansio-sonar-ssl-non443-imported', doc_type='imported-file',
                                             id=certfile, body={'file': certfile, 'imported_date': datetime.now(),
                                                                'sha1': sha1})
                                else:
                                    logger.error("SHA1 did not match for {f} it was not imported".format(f=certfile))
                                os.remove(certfile)
                        if scans_file.endswith('endpoints.gz'):
                            if 'smtp_25' in scans_file:
                                hostsfile = scans_file[52:90]
                                port = 25
                            if 'smtp_465' in scans_file:
                                hostsfile = scans_file[52:86]
                                port = 465
                            if 'imap_993' in scans_file:
                                hostsfile = scans_file[52:86]
                                port = 993
                            if 'imap_143' in scans_file:
                                hostsfile = scans_file[52:91]
                                port = 143
                            if 'pop3_995' in scans_file:
                                hostsfile = scans_file[52:86]
                                port = 995
                            if hostsfile not in imported_files:
                                logger.warning("We don't have {file} imported lets download it".format(file=hostsfile))
                                phys_host_file = requests.get(scans_file)
                                with open('{f}'.format(f=hostsfile), 'wb') as hf:
                                    for chunk in phys_host_file.iter_content(chunk_size=1024):
                                        if chunk:
                                            hf.write(chunk)
                                with open('{f}'.format(f=hostsfile), 'rb') as fh:
                                    h = hashlib.sha1()
                                    while True:
                                        data = fh.read(8192)
                                        if not data:
                                            break
                                        h.update(data)
                                sha1 = h.hexdigest()
                                if sha1 == res['fingerprint']:
                                    for w in xrange(workers):
                                        queue_es = Elasticsearch([{u'host': args.server, u'port': args.port}],
                                                                 timeout=60)
                                        p = Process(target=process_hosts, args=(process_hosts_queue, queue_es))
                                        p.daemon = True
                                        p.start()
                                    logger.warning("Importing {f} at {d}".format(f=hostsfile, d=datetime.now()))
                                    parse_hosts_file(hostsfile, process_hosts_queue)
                                    logger.warning("Hosts updated for {f} now going back and updating first_seen"
                                                   .format(f=hostsfile))
                                    update_es = Elasticsearch([{u'host': args.server, u'port': args.port}], timeout=60)
                                    # construct an elasticsearch query where the filter is looking for any entry
                                    # that is missing the field first_seen
                                    # adding a queue processing system here this should hopefully speed things up.
                                    for work in xrange(workers):
                                        p = Process(target=update_hosts, args=(update_hosts_queue, update_es))
                                        p.daemon = True
                                        p.start()
                                    q = {'size': 500, "query": {"match_all": {}},
                                         "filter": {"missing": {"field": "first_seen"}}}
                                    new_updates = update_es.search(index='passive-ssl-non443-hosts-sonar', body=q)
                                    logger.warning("Numer of hosts to update is {count}"
                                                   .format(count=new_updates['hits']['total']))
                                    # Scan across all the documents missing the first_seen field and bulk update them
                                    missing_first_seen = scan(update_es, query=q, scroll='30m',
                                                              index='passive-ssl-non443-hosts-sonar')
                                    for miss in missing_first_seen:
                                        update_hosts_queue.put(miss)
                                    for w in xrange(workers):
                                        update_hosts_queue.put("DONE")
                                    # for some stupid reason I keep missing some at the end of the scan/scroll
                                    # so going to do them manually
                                    new_updates = update_es.search(index='passive-ssl-non443-hosts-sonar', body=q)
                                    logger.warning("Numer of hosts to update is {count}"
                                                   .format(count=new_updates['hits']['total']))
                                    missing_first_seen_again = scan(update_es, query=q, scroll='30m',
                                                                    index='passive-ssl-non443-hosts-sonar')
                                    bulk_update_missed = []
                                    for m in missing_first_seen_again:
                                        last_seen = m['_source']['last_seen']
                                        first_seen = last_seen
                                        action = {"_op_type": "update", "_index": "passive-ssl-non443-hosts-sonar",
                                                  "_type": "host", "_id": m['_id'], "doc": {'first_seen': first_seen}}
                                        bulk_update_missed.append(action)
                                        if len(bulk_update_missed) == 500:
                                            bulk(update_es, bulk_update_missed)
                                            bulk_update_missed = []
                                    bulk(update_es, bulk_update_missed)
                                    logger.warning("Finished updating hosts at {d}".format(d=datetime.now()))

                                    #  Get the remaining ones that are less than 500 and the loop has ended
                                    logger.warning("Importing finished of {f} at {d}".format(f=hostsfile,
                                                   d=datetime.now()))
                                    es.index(index='scansio-sonar-ssl-non443-imported', doc_type='imported-file',
                                             id=hostsfile, body={'file': hostsfile, 'imported_date': datetime.now(),
                                                                 'sha1': sha1})
                                    os.remove(hostsfile)
        else:
            logger.error("The scans.io/json must have changed or is having issues. I didn't see any studies. Exiting")
            sys.exit()
    else:
        logger.error("There was an error connecting to https://scans.io. I did not get a 200 status code. Exiting")
        sys.exit()

if __name__ == "__main__":
    main(sys.argv)
    logger.warning("Indexes have been created. Start indexing scans.io ssl at will now :)")
