#!/usr/bin/python3
#
# Copyright (c) 2015 by Ensoft Ltd. All rights reserved.
#

import argparse
import logging
import os
import pickle
import re
import subprocess
import sys
import textwrap
import time

"""
A script to monitor the health of a Linux server MD RAID array and report 
when the status of the array has changed.

This script will be run periodically by cron, and based on the state of the
RAID array when the script runs, the previous state and the parameters passed
then certain behaviour will be taken.

An example of the crontab entry is given below, this:
- runs the script every five minutes
- uses a temporary file to store the previous status
- sends status updates via email to Sysadmin

From the server to be monitored:
0,5,10,15,20,25,30,35,40,45,50,55 * * * * PATH=/usr/bin/:/bin/ /usr/bin/raid_monitor.py --status-file /proc/mdstat --logfile /var/log/raid_monitor.log --datafile /tmp/raid_status_monitor.dat --status-email sysadmin@localhost
"""

#
# The following shows example 'status file' contents that indicates four
# raid devices with:
#  - md0 being healthy [UU]
#  - md1 having a failed disk [_U]
#  - md2 being in recovery
#  - md3 being checked
#
"""
Personalities : [raid1] [linear] [multipath] [raid0] [raid6] [raid5] [raid4] [raid10]
md0 : active raid1 sdb0[1] sda0[0]
      1953512384 blocks [2/2] [UU]

md1 : active raid1 sdb1[1] sda1[2](F)
      1953512384 blocks [1/2] [_U]

md2 : active raid1 sda2[2] sdb2[1]
      1953512384 blocks [1/2] [_U]
      [>....................]  recovery =  0.0% (4096/1953512384) finish=23753.7min speed=1365K/sec

md3 : active raid1 sda3[2] sdb3[1]
      976760768 blocks [2/2] [UU]
      [===========>.........]  check = 56.6% (553284608/976760768) finish=359.9min speed=19608K/sec

unused devices: <none>
"""


# Constants
class Status(object):
    """
    Possible RAID status values.

    Note: These must be kept in order of severity, so that the highest error
    is reported first.
    """
    HEALTHY = 1
    CHECK = 2
    RECOVER = 3
    FAILED = 4
    

class RaidArray(object):
    """
    An individual RAID array within the MDStat output.
    """
    def __init__(self, members):
        self.members = members
        self.status = Status.HEALTHY
        self.failed_disk = None


class MDStat(object):
    """
    Representation of the current MD RAID status.
    """
    def __init__(self):
        self.arrays = {}

    def overall_status(self):
        overall_status = Status.HEALTHY
        for md in self.arrays:
            # Store the worst (highest value) status.
            if self.arrays[md].status > overall_status:
                overall_status = self.arrays[md].status
        return overall_status

    def message(self):
        message = ""
        for md in sorted(self.arrays):
            if ((self.arrays[md].status == Status.FAILED or
                 self.arrays[md].status == Status.RECOVER) and
                 self.arrays[md].failed_disk is not None):
                failed_disk = "({})".format(self.arrays[md].failed_disk)
            else:
                failed_disk = ""
            message += \
                "    {} ({}): {} {}\n".format(
                   md,
                   ' '.join(disk for disk in self.arrays[md].members),
                   state_to_str(self.arrays[md].status),
                   failed_disk)

        return message


def error(err_str):
    """
    Log an error and exit.
    """
    logging.error(err_str)
    sys.exit(-1)


def debug(log_str):
    """
    Print debug if it is enabled.
    """
    logging.debug(log_str)


def log(log_str):
    """
    Update the logfile and write to debug if it's enabled.
    """
    logging.info(log_str)


def parse_args():
    """
    Parse the arguments given to the script.
    
    Returns an 'options' object.

    The following options are supported:
     - status-file  - file name of status file (defaults to /proc/mdstat)
     - logfile      - file name of the log file
     - datafile     - file name of the data file
     - status-email - email address(es) to send status emails to
     - debug        - enable debugging 
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("--status-file",
                        dest="status_file",
                        default="/proc/mdstat",
                        help="file name of status file (e.g. /proc/mdstat)")
    parser.add_argument("--logfile",
                        dest="logfile",
                        help="file name of log file")
    parser.add_argument("--datafile",
                        dest="datafile",
                        required=True,
                        help="file name of data file")
    parser.add_argument("--status-email",
                        dest="status_email",
                        required=True,
                        help="email address(es) to send status emails to")
    parser.add_argument("--debug",
                        dest="debug",
                        action="store_true",
                        default=False,
                        help="Enable debugging")
    
    args = parser.parse_args()

    # The log and data file names must be specified - and the parent 
    # directory must exist (if the file doesn't exist we'll create a new file)
    if not os.path.exists(os.path.dirname(os.path.abspath(args.datafile))):
        error("Must specify valid data file (specified '%s')" % (args.datafile))

    return args

    
def load_data_file(filename):
    """
    Return the data stored in the given file.
    If the file doesn't exist then return default values.
    """
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            data = pickle.load(f)

        if not isinstance(data, MDStat):
            error("Data file {} not in valid format: {}".format(filename,
                                                                data))
    else:
        log("Data file '%s' does not exist - create" % (filename))
        data = MDStat()

    return data

    
def send_status_email(subject, status_message, to_addresses):
    """
    Send the updated status message to the given address(es).
    """
    log(subject)
    debug(status_message)
    try:
        p = subprocess.Popen(["mail", "-s", subject, to_addresses],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        p.communicate(status_message.encode("utf-8"))
    except Exception as err:
        error("Failed to send status email: {}".format(err))


def state_to_str(status):
    """
    Convert the status to a string for use in log and email messages.
    """
    if status == Status.HEALTHY:
        status_str = "HEALTHY"
    elif status == Status.FAILED:
        status_str = "FAILED"
    elif status == Status.RECOVER:
        status_str = "RECOVERING"
    elif status == Status.CHECK:
        status_str = "CHECKING"
    else:
        error("Unrecognised status ({})".format(status))

    return status_str

#
# General plan:
#
# 1. Parse args, most are mandatory
# 2. Load the datafile, which gives us the previous state
# 3. Build the current state
# 4. Compare the current state with the old state
# 5. Based on the results of #4 take necessary action
# 6. Store latest state
#
def main():

    options = parse_args()
    hostname = os.uname()[1]

    if options.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    if options.logfile is not None:
        logging.basicConfig(filename=options.logfile,
                            level=log_level,
                            format='%(asctime)s %(levelname)s: %(message)s',
                            datefmt='%b %d %H:%M:%S')
    else:
        logging.basicConfig(level=log_level,
                            format='%(asctime)s %(levelname)s: %(message)s',
                            datefmt='%b %d %H:%M:%S')


    old_mdstat = load_data_file(options.datafile)

    mdstat = MDStat()

    # Test the state of the RAID array
    #  - Read the contents of the status file
    #  - Use regular expressions to parse the state 
    #
    # Potential states of each array are:
    #  - Healthy
    #  - Failed
    #  - Rebuilding
    #  - Checking
    # There may be servers with more than one array.
    
    # Regular expressions in the output that indicate status
    double_disk_expr = re.compile('^(md\d) : active raid1 (sd\w\d)\[\d\] (sd\w\d)\[\d\].*$')
    single_disk_expr = re.compile('^(md\d) : active raid1 (sd\w\d)\[\d\].*$')
    disk_status_expr = re.compile('^\s+\d+ blocks.*\[(\d)\/2\] \[(U|_)(U|_)\]$')
    recovery_expr = re.compile('^\s+\[.*\]\s+recovery\s+=\s+(\d+).(\d)%\s+\(\d+\/\d+\)\s+finish=(\d+).\dmin\s+speed=(\d+)K\/sec$')
    check_expr = re.compile('^\s+\[.*\]\s+check\s+=\s+(\d+).(\d)%\s+\(\d+\/\d+\)\s+finish=(\d+).\dmin\s+speed=(\d+)K\/sec$')

    with open(options.status_file, "r") as f:
        for line in f.readlines():
            double_disk_match = re.match(double_disk_expr, line)
            single_disk_match = re.match(single_disk_expr, line)
            disk_status_match = re.match(disk_status_expr, line)
            recovery_match = re.match(recovery_expr, line)
            check_match = re.match(check_expr, line)

            if double_disk_match:
                # Found a new MD device. Grab its name and members.
                current_md = double_disk_match.groups()[0]
                first_disk = double_disk_match.groups()[1]
                second_disk = double_disk_match.groups()[2]
                mdstat.arrays[current_md] = RaidArray([first_disk,
                                                       second_disk])

            elif single_disk_match:
                # Found a new MD device with just a single disk. Grab its name
                # and members.
                current_md = single_disk_match.groups()[0]
                first_disk = single_disk_match.groups()[1]
                mdstat.arrays[current_md] = RaidArray([first_disk])

            elif disk_status_match and '_' in disk_status_match.groups():
                # One of the disks in the array has failed. Mark this array
                # as failed, and store the failed disk.
                mdstat.arrays[current_md].status = Status.FAILED
                if disk_status_match.groups()[1] == '_':
                    mdstat.arrays[current_md].failed_disk = \
                        mdstat.arrays[current_md].members[0]
                else:
                    mdstat.arrays[current_md].failed_disk = \
                        mdstat.arrays[current_md].members[1]

            elif recovery_match:
                # Mark the array as in RECOVER state.
                mdstat.arrays[current_md].status = Status.RECOVER

            elif check_match:
                # Mark the array as in CHECK state.
                mdstat.arrays[current_md].status = Status.CHECK


    # Now compare the new state with the old state to determine if we need
    # to send a mail.
    send_mail = False

    if len(mdstat.arrays) != len(old_mdstat.arrays):
        send_mail = True
        subject = "{}: Number of RAID arrays changed".format(hostname)

    elif set(mdstat.arrays.keys()) != set(old_mdstat.arrays.keys()):
        send_mail = True
        subject = "{}: Set of RAID arrays changed".format(hostname)

    else:
        for md in mdstat.arrays:
            if mdstat.arrays[md].members != old_mdstat.arrays[md].members:
                send_mail = True
                subject = "{}: RAID membership changed".format(hostname)
                break
            elif mdstat.arrays[md].status != old_mdstat.arrays[md].status:
                send_mail = True
                subject = "{} RAID status changed".format(hostname)
                break

    if send_mail:
        # Calculate old and new overall status
        old_status = old_mdstat.overall_status()
        overall_status = mdstat.overall_status()
        subject += " ({})".format(state_to_str(overall_status))

        # Construct the pld and new state messages.
        old_state_message = old_mdstat.message()
        new_state_message = mdstat.message()
        
        message = textwrap.dedent("""\
           At {} a RAID change occurred on {}.

           New state: {}

           {}
           Old state: {}

           {}""").format(time.strftime('%b %d %H:%M:%S %Z'),
                         hostname,
                         state_to_str(overall_status),
                         new_state_message,
                         state_to_str(old_status),
                         old_state_message)

        send_status_email(subject, message, options.status_email)

    with open(options.datafile, "wb") as f:
        pickle.dump(mdstat, f)


if __name__ == "__main__":
    main()
