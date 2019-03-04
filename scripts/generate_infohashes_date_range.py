#!/usr/bin/env python

import datetime
import getopt
import hashlib
import sys

USAGE = """
generate_infohashes filename start_date end_date

args:
    filename: 
        Name of the payload file. Default is config.
    start_date: YYYY-MM-DD
        Compute info hash for YYYY-MM-DD.  Default is the current day. 
    end_date: YYYY-MM-DD
        End date (inclusive) for date range.  Default is the current day. 

""".strip()


def usage(exit_code=0):
    sys.stderr.write(USAGE + '\n')
    sys.exit(exit_code)

def generate_infohashes(filename="config", sdate_arg=None, edate_arg=None):
    """
    1. Get the current date UTC.
    2. Write the date in th eformat D-M-Y-W-Z, where 
        D day of the month
        M month (0=jan)
        Y years since 1900
        W day of the week (0=sun)
        Z number of days since Jan 1 of that year.

    3. sha1 hash the filename
    4.  sha1(D-M-Y-W-Z-sha1hashhex)
    """

    if sdate_arg is None:
        start_date = datetime.datetime.utcnow()
    else:
        start_date = datetime.datetime.strptime(sdate_arg, '%Y-%m-%d')
    if edate_arg is None:
        end_date = datetime.datetime.utcnow()
    else:
        end_date = datetime.datetime.strptime(edate_arg, '%Y-%m-%d')

    #generate info hash for each day in range
    day_count = ((end_date - start_date) + datetime.timedelta(days=1)).days
    for d in (start_date + datetime.timedelta(n) for n in range(day_count)):
        st = d.utctimetuple()
        date_str = '%d-%d-%d-%d-%d' % \
            (st.tm_mday,  st.tm_mon - 1, st.tm_year - 1900, (st.tm_wday + 1) %
                    7, st.tm_yday - 1)

        file_hash_hex = hashlib.sha1(filename).hexdigest()
        id_string = '%s-%s' % (date_str, file_hash_hex)

        info_hash = hashlib.sha1(id_string).hexdigest()
        print "%s %s %04d-%02d-%02d"%(info_hash, filename, st.tm_year, 
                st.tm_mon, st.tm_mday)


def main(argv):
    if len(argv) == 1:
        filename = "config"
        sdate_arg = None
        edate_arg = None
    elif len(argv) == 2:
        filename = argv[1]
        sdate_arg = None
        edate_arg = None
    elif len(argv) == 4:
        filename = argv[1]
        sdate_arg = argv[2]
        edate_arg = argv[3]
    else:
        sys.stderr.write('%s\n'%sys.argv)
        usage(1);
    
    generate_infohashes(filename, sdate_arg, edate_arg)

    #if len(args) != 2:
    #    usage(1)

    #filename = args[0]


if __name__ == '__main__':
    main(sys.argv)
