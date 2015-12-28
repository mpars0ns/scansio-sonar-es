import logging
import textwrap
import OpenSSL
from datetime import datetime
import sys

logger = logging.getLogger('SSLImporter')
format = logging.Formatter('\033[1;32m%(levelname)-5s %(module)s:%(funcName)s():%(lineno)d %(asctime)s\033[0m| '
                           '%(message)s')
shandler = logging.StreamHandler(sys.stdout)
shandler.setFormatter(format)
logger.addHandler(shandler)


def process_cert(cert):
    """
    :param cert: This should be a string that is the raw base64 of the ssl certificate
    :return:
    """
    cert = "\n".join(textwrap.wrap(cert, 76))
    cert = "-----BEGIN CERTIFICATE-----\n{certtext}\n-----END CERTIFICATE-----".format(certtext=cert)
    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        subject_dict = dict(x509.get_subject().get_components())
        issuer_dict = dict(x509.get_issuer().get_components())
        #  Due to unicode decoding issues we are escaping whats found in these dicts
        for key, value in subject_dict.iteritems():
            subject_dict[key] = value.decode('latin1', 'unicode-escape')
        for key, value in issuer_dict.iteritems():
            issuer_dict[key] = value.decode('latin1', 'unicode-escape')
        md5 = x509.digest('md5').replace(':', '').lower()
        sha1 = x509.digest('sha1').replace(':', '').lower()
        sha256 = x509.digest('sha256').replace(':', '').lower()
        x509_extension_count = int(x509.get_extension_count())
        x509_extensions = {}
        for ext in range(0, x509_extension_count):
            newext = x509.get_extension(ext)
            try:
                x509_extensions[newext.get_short_name()] = str(newext).decode('latin1', 'unicode-escape')
            except:
                pass
        try:
            pubkey = x509.get_pubkey()
            bits = pubkey.bits()
        except:
            bits = 0
        notBefore = x509.get_notBefore()
        try:
            notBefore = datetime.strptime(notBefore, '%Y%m%d%H%M%SZ')
            notBefore = notBefore.isoformat()
        except:
            try:
                notBefore = datetime.strptime(notBefore[:-5], "%Y%m%d%H%M%S")
                notBefore = notBefore.isoformat()
            except:
                try:
                    notBefore = datetime.strptime(notBefore, "%Y%m%d%H%M%S")
                    notBefore = notBefore.isoformat()
                except:
                    logger.error("There is an error with the notBefore time on cert: {cert}".format(cert=sha1))
                    notBefore=None
        notAfter = x509.get_notAfter()
        try:
            notAfter = datetime.strptime(notAfter, '%Y%m%d%H%M%SZ')
            notAfter = notAfter.isoformat()
        except:
            try:
                notAfter = datetime.strptime(notAfter[:-5], "%Y%m%d%H%M%S")
                notAfter = notAfter.isoformat()
            except:
                try:
                    notAfter = datetime.strptime(notAfter, "%Y%m%d%H%M%S")
                    notAfter = notAfter.isoformat()
                except:
                    logger.error("There is an error with the notAfter time on cert: {cert} ".format(cert=sha1))
                    notAfter = None

        subject_name_hash = x509.subject_name_hash()
        version = x509.get_version()
        try:
            alg = x509.get_signature_algorithm()
        except:
            alg = None
        try:
            sn = x509.get_serial_number()
            # This is to conver from a long int to hex which is what most peopel provide the serial number in
            sn = '%x' % sn
        except:
            sn = None
        certificate = {"hash_id": sha1, "md5": md5, "sha1": sha1, 'sha256': sha256, "issuer": issuer_dict,
                       "subject": subject_dict, 'extensions': x509_extensions, 'bits': bits,
                       'notBefore': notBefore, 'notAfter': notAfter, 'version': version, 'SignatureAlgorithm': alg,
                       'subject_name_hash': subject_name_hash, 'sn': sn}
        return certificate
    except OpenSSL.crypto.Error:
        logger.error("We had an error parsing cert")
        return None
