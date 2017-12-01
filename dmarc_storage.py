import sqlite3
import os
import datetime

__all__ = ['DMARCStorage', 'totimestamp']


def totimestamp(datetime_object):
    if datetime_object.utcoffset() is not None:
        utc_naive = datetime_object.replace(tzinfo=None) - datetime_object.utcoffset()
    else:
        utc_naive = datetime_object
    return (utc_naive - datetime.datetime(1970, 1, 1)).total_seconds()


class DMARCStorage(object):

    def __init__(self, database_filename='dmarc.sqlite', database_directory="./results"):
        # Create or connect to the database:
        database_path = os.path.join(database_directory, database_filename)
        if not os.path.exists(database_directory):
            os.makedirs(database_directory)
        self._conn = sqlite3.connect(database_path)
        # Set automcommit to true and initialise cursor:
        self._conn.isolation_level = None
        self._cur = self._conn.cursor()
        # Create the tables if they don't exist already:
        self._init_database()

    def __del__(self):
        if self._conn is not None:
            self._close_connection()

    def _init_database(self):
        self._cur.execute("PRAGMA foreign_keys = ON;")
        self._cur.execute("""CREATE TABLE IF NOT EXISTS dmarc_reports (
                                report_id TEXT PRIMARY KEY,
                                receiver TEXT,
                                report_filename TEXT,
                                report_start INTEGER,
                                report_end INTEGER
                            );""")
        self._cur.execute("""CREATE TABLE IF NOT EXISTS dmarc_records (
                                report_id TEXT REFERENCES dmarc_reports(report_id) ON DELETE CASCADE,
                                record_id INTEGER,
                                ip_address TEXT,
                                hostname TEXT,
                                disposition TEXT,
                                reason TEXT,
                                spf_pass INTEGER,
                                dkim_pass INTEGER,
                                header_from TEXT,
                                envelope_from TEXT,
                                count INTEGER,
                                PRIMARY KEY (report_id, record_id)
                            );""")
        self._cur.execute("""CREATE TABLE IF NOT EXISTS spf_results (
                                report_id TEXT,
                                record_id INTEGER,
                                domain TEXT,
                                result TEXT,
                                PRIMARY KEY (report_id, record_id),
                                FOREIGN KEY (report_id, record_id)
                                    REFERENCES dmarc_records(report_id, record_id)
                                    ON DELETE CASCADE
                            );""")
        self._cur.execute("""CREATE TABLE IF NOT EXISTS dkim_signatures (
                                report_id TEXT,
                                record_id INTEGER,
                                signature_id INTEGER,
                                domain TEXT,
                                result TEXT,
                                selector TEXT,
                                PRIMARY KEY (report_id, record_id, signature_id),
                                FOREIGN KEY (report_id, record_id)
                                    REFERENCES dmarc_records(report_id, record_id)
                                    ON DELETE CASCADE,
                                CONSTRAINT unique_dkim_sig
                                    UNIQUE (report_id, record_id, domain, result, selector)
                            );""")

    def _delete_all_data(self):
        # Drop the tables in the right order:
        self._cur.execute("DROP TABLE dkim_signatures;")
        self._cur.execute("DROP TABLE spf_results;")
        self._cur.execute("DROP TABLE dmarc_records;")
        self._cur.execute("DROP TABLE dmarc_reports;")
        # Recreate them again, empty:
        self._init_database()

    def _close_connection(self):
        self._conn.close()
        self._conn = None

    def report_already_exists(self, report_filename):
        # Check if a report with that filename already exists:
        self._cur.execute("SELECT report_filename FROM dmarc_reports WHERE report_filename=?;", (report_filename,))
        already_exists = self._cur.fetchone() is not None
        return already_exists

    def save_new_report(self, report):
        # Persist the report itself:
        self._cur.execute("INSERT INTO dmarc_reports VALUES (?,?,?,?,?);",
                          [report.id, report.receiver, report.filename,
                           totimestamp(report.start_date), totimestamp(report.end_date)])
        # Persist each record of that report with a generated ID:
        for rec_id, rec in enumerate(report.records):
            self._cur.execute("INSERT INTO dmarc_records VALUES (?,?,?,?,?,?,?,?,?,?,?);",
                              [report.id, rec_id, rec.ip, rec.host, rec.disposition, rec.reason,
                               rec.spf_pass, rec.dkim_pass, rec.header_from, rec.envelope_from,
                               rec.count])
            # Persist the SPF data:
            self._cur.execute("INSERT INTO spf_results VALUES (?,?,?,?);",
                              [report.id, rec_id, rec.spf_result["domain"], rec.spf_result["result"]])
            # Persist all the DKIM signatures with generated IDs
            for sig_id, sig in enumerate(rec.dkim_signatures):
                self._cur.execute("INSERT INTO dkim_signatures VALUES (?,?,?,?,?,?);",
                                  [report.id, rec_id, sig_id, sig["domain"], sig["result"], sig["selector"]])

    def get_reporting_start_date(self):
        self._cur.execute("SELECT min(report_start) FROM dmarc_reports;")
        return datetime.datetime.utcfromtimestamp(self._cur.fetchone()[0])

    def get_reporting_end_date(self):
        self._cur.execute("SELECT max(report_start) FROM dmarc_reports;")
        return datetime.datetime.utcfromtimestamp(self._cur.fetchone()[0])

    def get_number_reports(self):
        self._cur.execute("SELECT count(*) FROM dmarc_reports;")
        return self._cur.fetchone()[0]

    def get_count_by_disposition(self):
        self._cur.execute("SELECT disposition, sum(count) FROM dmarc_records GROUP BY disposition;")
        return {str(r[0]): r[1] for r in self._cur.fetchall()}

    def get_count_by_hostnames(self):
        self._cur.execute("SELECT hostname, ip_address, sum(count) FROM dmarc_records GROUP BY hostname, ip_address;")
        return {str(r[0]) if r[0] is not None else str(r[1]): r[2] for r in self._cur.fetchall()}

    def get_count_by_receiver(self):
        self._cur.execute("SELECT receiver, sum(count) FROM dmarc_reports JOIN dmarc_records " +
                          "ON dmarc_reports.report_id=dmarc_records.report_id GROUP BY receiver;")
        return {str(r[0]): r[1] for r in self._cur.fetchall()}

    def get_count_by_dkim_domain(self):
        self._cur.execute("SELECT domain, sum(count) FROM dmarc_records JOIN dkim_signatures " +
                          "ON dmarc_records.report_id=dkim_signatures.report_id AND " +
                          "dmarc_records.record_id=dkim_signatures.record_id GROUP BY domain;")
        return {str(r[0]): r[1] for r in self._cur.fetchall()}

    def get_count_by_status_string(self):
        self._cur.execute("SELECT spf_pass, dkim_pass, sum(count) FROM dmarc_records GROUP BY spf_pass, dkim_pass;")
        status = {1: "pass", 0: "fail", None: "n/a"}
        return {"SPF:%s, DKIM:%s" % (status[r[0]], status[r[1]]): r[2] for r in self._cur.fetchall()}

    def get_raw_spf_status_count_by_timestamp(self):
        self._cur.execute("SELECT report_start, spf_pass, count FROM dmarc_reports JOIN dmarc_records " +
                          "ON dmarc_reports.report_id=dmarc_records.report_id;")
        return self._cur.fetchall()

    def get_raw_dkim_status_count_by_timestamp(self):
        self._cur.execute("SELECT report_start, dkim_pass, count FROM dmarc_reports JOIN dmarc_records " +
                          "ON dmarc_reports.report_id=dmarc_records.report_id;")
        return self._cur.fetchall()

    def get_raw_dmarc_status_count_by_timestamp(self):
        self._cur.execute("SELECT report_start, spf_pass + dkim_pass, count " +
                          "FROM dmarc_reports JOIN dmarc_records " +
                          "ON dmarc_reports.report_id=dmarc_records.report_id;")
        return self._cur.fetchall()

    def execute_query(self, sql, values=None):
        if values is not None:
            self._cur.execute(sql, values)
        else:
            self._cur.execute(sql)
        return self._cur.fetchall()
