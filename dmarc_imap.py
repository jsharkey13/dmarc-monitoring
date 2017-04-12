import os
import imaplib
import email
import email.header
import re
import argparse

# Should we attempt validation of DKIM signatures on report emails?
# try:
#    import dkim
#    import dnspython
#    DKIM_CHECK = True
# except ImportError:
#    DKIM_CHECK = False

__all__ = ['ReportDownloader', 'IMAPException']


# DMARC report names are of the form:
#     receiverdomain!senderdomain!startt!endt.zip
RUA_NAME_FORMAT = re.compile("^(?:[A-Za-z0-9]+\.[A-Za-z]+!){2}[0-9]+![0-9]+(?:\.zip|\.xml\.gz)$")


class IMAPException(Exception):
    pass


class ReportDownloader(object):

    def __init__(self, email_address, password, imap_url, dmarc_label=None, unread_only=True):
        self.email_address = email_address
        self.email_password = password
        self.imap_url = imap_url
        self.dmarc_label = dmarc_label
        self._search_param = "UNSEEN" if unread_only else "ALL"
        self._logged_in = False
        self._mailbox = imaplib.IMAP4_SSL(self.imap_url)

    def login(self):
        if not self._logged_in:
            try:
                rv, data = self._mailbox.login(self.email_address, self.email_password)
                if rv != "OK":
                    raise IMAPException("Error logging in!")
            except imaplib.IMAP4.error as e:
                print "ERROR: Login Failed! " + e.message
                raise IMAPException("Fatal Error logging in!")
            self._logged_in = True
            print "INFO: Logged in to IMAP server successfully."
        else:
            pass

    def download(self, destination_folder='./reports'):
        # Allow skipping of the extra call to login():
        if not self._logged_in:
            self.login()
        # Create the output directory if it doesn't exist:
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        # If we need to narrow down emails searched by a label:
        if self.dmarc_label is not None:
            rv, data = self._mailbox.select(self.dmarc_label)
            if rv != "OK":
                print "ERROR: Problem selecting label!"
                raise IMAPException("Error selecting label!")

        # Search for all emails matching the read/unread criteria:
        rv, data = self._mailbox.search(None, self._search_param)
        if rv != "OK":
            print "ERROR: Problem searching for emails!"
            raise IMAPException("Error searching for emails!")

        # Iterate through the emails, downloading any zip or gz attachments:
        email_numbers = data[0].split()
        n_expected = len(email_numbers)
        n_found = 0
        n_new = 0
        print "INFO: Scanning %d email%s." % (n_expected, "" if n_expected == 1 else "s")
        for num in email_numbers:
            found = False
            rv, data = self._mailbox.fetch(num, '(RFC822)')
            if rv != 'OK':
                print "ERROR: Problem getting a message!"
                raise IMAPException("Failed to fetch a message!")
            # Turn the message into a string, and search for attachments:
            m = email.message_from_string(data[0][1])
            message_subject = unicode(email.header.decode_header(m['Subject'])[0][0])
            #
            # FIXME: At this point some checking could be done to validate this is actually
            # a *genuine* DMARC report and not fake or spam. Unfortunately not all report
            # providers sign their reporting emails . . .
            #
            # if DKIM_CHECK:
            #    valid = dkim.dkim_verify(data[0][1])
            #    if not valid:
            #        continue
            #
            if (m.get_content_maintype() == 'multipart' or m.get_content_type() in ['application/zip', 'application/gzip']):
                for part in m.walk():
                    if part.get('Content-Disposition', '').startswith("attachment"):
                        filename = part.get_filename()
                        # Process the attachment only if named as expected (RFC 7489, Section 7.2.1.1):
                        if RUA_NAME_FORMAT.match(filename):
                            n_found += 1
                            found = True
                            file_path = os.path.join(destination_folder, filename)
                            # Download the attachment only if it doesn't already exist:
                            if not os.path.isfile(file_path):
                                n_new += 1
                                fp = open(file_path, 'wb')
                                fp.write(part.get_payload(decode=True))
                                fp.close()
                                # Assert only one report per email:
                                break
            # If we expect to only see DMARC emails, note when an email contains no report:
            if self.dmarc_label is not None and not found:
                print "INFO: Message (%s) contained no DMARC report." % message_subject

        # Finished trawling the emails: did we miss anything?
        print "INFO: Examined %d message%s, found %d DMARC report%s." % (n_expected, "" if n_expected == 1 else "s", n_found, "" if n_found == 1 else "s")
        print "INFO: Downloaded %d new DMARC report%s." % (n_new, "" if n_new == 1 else "s")


if __name__ == "__main__":
    # Allow specification of parameters at runtime:
    options = argparse.ArgumentParser(description="Download DMARC reports from an IMAP server.")
    options.add_argument("-e", "--email", help="email address to access", required=True)
    options.add_argument("-pf", "--pwdfile", help="text file containing the IMAP password", required=True)
    options.add_argument("-s", "--server", help="what IMAP server to connect to (default to Google)", default='imap.gmail.com')
    options.add_argument("-a", "--all", help="read all messages, not just unread", action="store_true")
    options.add_argument("-l", "--label", help="the label DMARC messages are stored under", default=None)
    args = options.parse_args()

    # Download reports, to the default directory:
    password = None
    with open(args.pwdfile, 'r') as password_file:
        password = password_file.readline().strip()
    downloader = ReportDownloader(args.email, password, args.server, dmarc_label=args.label, unread_only=not args.all)
    downloader.download()
