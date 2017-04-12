import datetime
from matplotlib import pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import numpy as np
from dmarc_storage import DMARCStorage


def plot_percentage_passing(dates, fail, none, other, passing, category):

    fig = plt.figure(facecolor='white', figsize=(12, 8))
    plt.gca().set_title('%s Status on Messages' % category)
    plt.gca().set_ylabel('Percentage of Messages Received')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%d-%m-%Y'))
    plt.gca().set_ylim([0, 100])
    red_patch = mpatches.Patch(color='#ef3e36', label='FAIL')
    grey_patch = mpatches.Patch(color='#cccccc', label='NONE')
    dark_patch = mpatches.Patch(color='#666666', label='OTHER')
    green_patch = mpatches.Patch(color='#509e2e', label='PASS')
    auth = [fail]
    handles = [red_patch]
    colours = ['#ef3e36']
    if none is not None:
        auth.append(none)
        handles.append(grey_patch)
        colours.append('#cccccc')
    if other is not None:
        auth.append(other)
        handles.append(dark_patch)
        colours.append('#666666')
    auth.append(passing)
    handles.append(green_patch)
    colours.append('#509e2e')
    handles.reverse()
    auth_percents = (auth / np.sum(auth, axis=0).astype(float)) * 100
    plt.stackplot(dates, auth_percents, colors=colours, edgecolor='none')
    plt.legend(handles=handles, loc=2)
    fig.autofmt_xdate()
    fig.savefig('percentage_passing_%s.png' % category, bbox_inches='tight', dpi=600)


def plot_number_passing(dates, fail, none, other, passing, category):
    fig = plt.figure(facecolor='white', figsize=(12, 8))
    ind = np.arange(len(dates))
    plt.gca().set_title('%s Status on Messages' % category)
    plt.gca().set_ylabel('Number of Messages Received')
    red_patch = mpatches.Patch(color='#ef3e36', label='FAIL')
    grey_patch = mpatches.Patch(color='#cccccc', label='NONE')
    dark_patch = mpatches.Patch(color='#666666', label='OTHER')
    green_patch = mpatches.Patch(color='#509e2e', label='PASS')
    fail = np.array(fail)  # Else the + operator appends rather than summing!
    #
    handles = [red_patch]
    plt.bar(ind, fail, color='#ef3e36', edgecolor='none')
    bottom = fail
    if none is not None:
        plt.bar(ind, none, bottom=bottom, color='#cccccc', edgecolor='none')
        handles.append(grey_patch)
        bottom += none
    if other is not None:
        plt.bar(ind, other, bottom=bottom, color='#666666', edgecolor='none')
        handles.append(dark_patch)
        bottom += other
    plt.bar(ind, passing, bottom=bottom, color='#509e2e', edgecolor='none')
    handles.append(green_patch)
    handles.reverse()
    #
    plt.xticks(ind, map(lambda d: datetime.datetime.strftime(d, "%d-%m-%Y"), dates))
    plt.legend(handles=handles, loc=2)
    fig.autofmt_xdate(ha='center')
    fig.savefig('number_passing_%s.png' % category, bbox_inches='tight', dpi=600)


def generate_report(n_reports, min_time, max_time, by_host, by_receiver, dkim_domains, by_status):
    report = "Isaac Emails From %s to %s\n" % (min_time, max_time)
    report += "\t %d emails in %d reports\n" % (sum(by_host.values()), n_reports)
    report += "\n\n"

    TOPN = 25
    LJUST = 64
    RJUST = 6
    LINELENGTH = 74

    report += "Sender Hostname".ljust(LJUST) + "|" + "Sent".rjust(RJUST) + "\n"
    report += "=" * LINELENGTH + "\n"
    for host in sorted(by_host.keys(), key=lambda x: by_host[x], reverse=True)[:TOPN]:
        report += host.ljust(LJUST) + "|" + str(by_host[host]).rjust(RJUST) + "\n"
    if len(by_host) > TOPN:
        report += "...".ljust(LJUST) + "|" + "...".rjust(RJUST) + "\n"
        others = sum(sorted(by_host.values(), reverse=True)[TOPN:])
        report += "[Others]".ljust(LJUST) + "|" + str(others).rjust(RJUST)

    report += "\n\n\n"
    report += "Receiver Name".ljust(LJUST) + "|" + "Count".rjust(RJUST) + "\n"
    report += "=" * LINELENGTH + "\n"
    for rec in sorted(by_receiver.keys(), key=lambda x: by_receiver[x], reverse=True)[:TOPN]:
        report += rec.ljust(LJUST) + "|" + str(by_receiver[rec]).rjust(RJUST) + "\n"
    if len(by_receiver) > TOPN:
        report += "...".ljust(LJUST) + "|" + "...".rjust(RJUST) + "\n"
        others = sum(sorted(by_receiver.values(), reverse=True)[TOPN:])
        report += "[Others]".ljust(LJUST) + "|" + str(others).rjust(RJUST) + "\n"

    report += "\n\n\n"
    report += "DKIM Signing Domain".ljust(LJUST) + "|" + "Count".rjust(RJUST) + "\n"
    report += "=" * LINELENGTH + "\n"
    for domain in sorted(dkim_domains.keys(), key=lambda x: dkim_domains[x], reverse=True)[:TOPN]:
        report += domain.ljust(LJUST) + "|" + str(dkim_domains[domain]).rjust(RJUST) + "\n"
    if len(dkim_domains) > TOPN:
        report += "...".ljust(LJUST) + "|" + "...".rjust(RJUST) + "\n"
        others = sum(sorted(dkim_domains.values(), reverse=True)[TOPN:])
        report += "[Others]".ljust(LJUST) + "|" + str(others).rjust(RJUST) + "\n"

    report += "\n\n\n"
    report += "DMARC Status".ljust(LJUST) + "|" + "Count".rjust(RJUST) + "\n"
    report += "=" * LINELENGTH + "\n"
    for rec in sorted(by_status.keys(), key=lambda x: by_status[x], reverse=True):
        report += rec.ljust(LJUST) + "|" + str(by_status[rec]).rjust(RJUST) + "\n"

    with open("report.txt", "w") as f:
        f.write(report)
    return report


def _parse_and_truncate_timestamp(timestamp):
    # Convert from an interger timestamp to a datetime object:
    dt = datetime.datetime.utcfromtimestamp(timestamp)
    # Turn this into just a date, stripping out the time part!
    return datetime.date(dt.year, dt.month, dt.day)


if __name__ == "__main__":
    sqlite_db = DMARCStorage()
    # Generate a text report summary:
    n_reports = sqlite_db.get_number_reports()

    min_t = sqlite_db.get_reporting_start_date()
    max_t = sqlite_db.get_reporting_end_date()

    by_host = sqlite_db.get_count_by_hostnames()
    by_receiver = sqlite_db.get_count_by_receiver()
    dkim_domains = sqlite_db.get_count_by_dkim_domain()
    by_status = sqlite_db.get_count_by_status_string()

    print generate_report(n_reports, min_t, max_t, by_host, by_receiver, dkim_domains, by_status)
    # Produce graphs showing SPF status of messages:
    res = sqlite_db.get_raw_spf_status_count_by_timestamp()
    spf_passes = dict()
    spf_fails = dict()
    for r in res:
        date = _parse_and_truncate_timestamp(r[0])
        if date not in spf_passes:
            spf_passes[date] = 0
        if date not in spf_fails:
            spf_fails[date] = 0
        if r[1] == 1:
            spf_passes[date] += r[2]
        else:
            spf_fails[date] += r[2]
    dates = sorted(spf_passes.keys())
    spf_passes = [spf_passes[d] for d in dates]
    spf_fails = [spf_fails[d] for d in dates]
    plot_number_passing(dates, spf_fails, None, None, spf_passes, "SPF")
    plot_percentage_passing(dates, spf_fails, None, None, spf_passes, "SPF")
    # Produce graphs showing DKIM status of messages:
    res = sqlite_db.get_raw_dkim_status_count_by_timestamp()
    dkim_passes = dict()
    dkim_fails = dict()
    for r in res:
        date = _parse_and_truncate_timestamp(r[0])
        if date not in dkim_passes:
            dkim_passes[date] = 0
        if date not in dkim_fails:
            dkim_fails[date] = 0
        if r[1] == 1:
            dkim_passes[date] += r[2]
        else:
            dkim_fails[date] += r[2]
    dates = sorted(dkim_passes.keys())
    dkim_passes = [dkim_passes[d] for d in dates]
    dkim_fails = [dkim_fails[d] for d in dates]
    plot_number_passing(dates, dkim_fails, None, None, dkim_passes, "DKIM")
    plot_percentage_passing(dates, dkim_fails, None, None, dkim_passes, "DKIM")
    # Produce graphs showing DMARC status of messages:
    res = sqlite_db.get_raw_dmarc_status_count_by_timestamp()
    dmarc_passes = dict()
    dmarc_fails = dict()
    for r in res:
        date = _parse_and_truncate_timestamp(r[0])
        if date not in dmarc_passes:
            dmarc_passes[date] = 0
        if date not in dmarc_fails:
            dmarc_fails[date] = 0
        if r[1] > 0:  # If one or both of SPF and DKIM passed, DMARC passes
            dmarc_passes[date] += r[2]
        else:
            dmarc_fails[date] += r[2]
    dates = sorted(dmarc_passes.keys())
    dmarc_passes = [dmarc_passes[d] for d in dates]
    dmarc_fails = [dmarc_fails[d] for d in dates]
    plot_number_passing(dates, dmarc_fails, None, None, dmarc_passes, "DMARC")
    plot_percentage_passing(dates, dmarc_fails, None, None, dmarc_passes, "DMARC")
    #
    plt.show()
