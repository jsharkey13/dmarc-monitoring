# DMARC PARSER
import os
from bs4 import BeautifulSoup as bs
import zipfile
import gzip
import socket
import datetime
import pickle
from dmarc_storage import DMARCStorage

__all__ = ['DMARCReport', 'DMARCRecord', 'parse_reports_in_directory',
           'load_rdns_records', 'save_rdns_records']

socket.setdefaulttimeout(10)
_rdns_records = dict()  # Store domain names successfully resolved from IP addresses.


class DMARCRecord(object):

    def __init__(self, record_xml):
        # Sender Metadata
        self.ip = str(record_xml.find('source_ip').text)
        self.host = _lookup_ip(self.ip)
        # Policy Result:
        self.disposition = str(record_xml.row.policy_evaluated.disposition.text)
        self.spf_pass = None
        self.dkim_pass = None
        if record_xml.row.policy_evaluated.spf is not None:
            assert str(record_xml.row.policy_evaluated.spf.text) in ['pass', 'fail']
            self.spf_pass = (str(record_xml.row.policy_evaluated.spf.text) == 'pass')
        if record_xml.row.policy_evaluated.dkim is not None:
            assert str(record_xml.row.policy_evaluated.dkim.text) in ['pass', 'fail']
            self.dkim_pass = (str(record_xml.row.policy_evaluated.dkim.text) == 'pass')
        else:
            # Manually sanitise the data; if DKIM wasn't included, it failed.
            self.dkim_pass = False
        # Other Data:
        self.header_from = str(record_xml.identifiers.header_from.text) if record_xml.identifiers.header_from else None
        self.envelope_from = str(record_xml.identifiers.envelope_from.text) if record_xml.identifiers.envelope_from else None
        self.count = int(record_xml.find('count').text)
        # SPF Status:
        try:
            spf_result = str(record_xml.auth_results.spf.result.text)
            spf_domain = str(record_xml.auth_results.spf.domain.text)
            self.spf_result = dict(domain=spf_domain, result=spf_result)
        except AttributeError:
            self.auth_spf = None
        xml_dkim_signatures = record_xml.auth_results.find_all("dkim") or []
        self.dkim_signatures = []
        for dkim_sig in xml_dkim_signatures:
            _result = str(dkim_sig.result.text)
            _domain = str(dkim_sig.domain.text)
            _selector = str(dkim_sig.selector.text) if dkim_sig.selector is not None else None
            if _result not in ["none", "neutral"] and _domain != "not.evaluated":
                self.dkim_signatures.append(dict(result=_result, domain=_domain, selector=_selector))


class DMARCReport(object):

    def __init__(self, filename, metadata_xml, policy_xml):
        self.id = str(metadata_xml.report_id.text)
        self.filename = filename
        self.receiver = str(metadata_xml.org_name.text)
        date_range = metadata_xml.date_range
        self.start_date = datetime.datetime.utcfromtimestamp(int(date_range.begin.text))
        self.end_date = datetime.datetime.utcfromtimestamp(int(date_range.end.text))
        self.records = []

    def add_record(self, record):
        self.records.append(record)


def _lookup_ip(ip_address):
    global _rdns_records
    if ip_address not in _rdns_records:
        try:
            print "INFO: Looking up %s" % ip_address
            socket_info = socket.gethostbyaddr(ip_address)
            hostname = socket_info[0]
            _rdns_records[ip_address] = hostname
        except socket.herror:
            hostname = None
        return hostname
    else:
        return _rdns_records[ip_address]


def _process_xml(xml_file, report_filename):
    # Build the report object:
    report_xml = bs(xml_file, features='xml')
    report = DMARCReport(report_filename, report_xml.report_metadata, report_xml.policy_published)
    # Add all of its DMARC records:
    records = report_xml.find_all("record")
    for r in records:
        record = DMARCRecord(r)
        report.add_record(record)
    return report


def _process_zipfile(fname):
    archive_name = fname.split("/")[-1]
    with zipfile.ZipFile(fname, 'r') as archive:
        for subfile_name in archive.namelist():
            if subfile_name.endswith(".xml"):
                xml_file = archive.open(subfile_name, 'rU')
                # Assert only one valid XML file per ZIP file!
                return _process_xml(xml_file, archive_name)


def _process_gzfile(fname):
    archive_name = fname.split("/")[-1]
    # Assume standard gzip file, with single subfile named same minus the .gz:
    subfile_name = archive_name.replace(".gz", "")
    if subfile_name.endswith(".xml"):
        with gzip.open(fname) as gzipfile:
            return _process_xml(gzipfile, archive_name)


def parse_reports_in_directory(persistent_storage, report_dir="./reports"):
    print "INFO: Parsing all reports in directory."
    n = 0
    n_new = 0
    for root, directories, files in os.walk(report_dir):
        for fname in files:
            n += 1
            # Check if we already have this report saved:
            if persistent_storage.report_already_exists(fname):
                continue
            # If not, parse the file in correct manner:
            report = None
            if fname.endswith(".zip"):
                report = _process_zipfile(root + "/" + fname)
            elif fname.endswith(".gz"):
                report = _process_gzfile(root + "/" + fname)
            # Save any parsed report:
            if report is not None:
                n_new += 1
                persistent_storage.save_new_report(report)
    print "INFO: Found %d file%s, parsed %d new report%s." % (n, "" if n == 1 else "s", n_new, "" if n_new == 1 else "s")


def save_rdns_records(rdns_records, rdns_filename='rdns.pickle'):
    with open(rdns_filename, "wb") as f:
        print "INFO: Saving rDNS Records to File."
        pickle.dump(rdns_records, f)


def load_rdns_records(rdns_filename='rdns.pickle'):
    if os.path.isfile(rdns_filename):
        with open(rdns_filename) as f:
            print "INFO: Loading Saved rDNS Records."
            return pickle.load(f)
    else:
        print "INFO: No rDNS Records to Load."
        return dict()


if __name__ == "__main__":
    _rdns_records = load_rdns_records()

    sqlite_storage = DMARCStorage()
    parse_reports_in_directory(persistent_storage=sqlite_storage)

    save_rdns_records(_rdns_records)
