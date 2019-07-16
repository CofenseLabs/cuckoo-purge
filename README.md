# Custom Cuckoo data purge script

A custom data purge script for Cuckoo. At CofenseLabs we use the Cuckoo
sandbox as a source of dynamic analysis of malware samples. Because Cuckoo
sandbox reports can generate a large volume of data, we needed a programmatic
way to purge old data from all Cuckoo data sources (filesystem and databases)
and maintain the a maximum number of days of sandbox reports for real-time
hunting and malware analysis.

### Integration with cuckoo sandbox

The script uses Cuckoo's own modules and functions to load configuration data
(e.g. database location and credentials) and determine the current CWD (Cuckoo
Working Directory).

### Installation

The easiest solution for installing the script is to copy it into your
$CWD/stuff directory.

The script has two modes of operation: run as a daemon or run as a daily task.
To run the script as a daemon, you can use either the provided supervisord or
systemd files. Simply update it to match your environment (virtualenv as the
working directory, full path to your virtualenv or system's python
interpreter, full path to the purge.py script). To run the script as a
scheduled task, simply add a line to your crontab to execute the script daily.

##### Example crontab entry

```00 00 * * * /opt/venv/bin/python /opt/venv/.cuckoo/stuff/purge.py```

#### (Optional)

CofenseLabs has also provided a patch file to fully integrate configuration
into the existing Cuckoo configuration files.

##### Patch Cuckoo

```patch -u /opt/venv/lib/python2.7/site-packages/cuckoo/common/config.py -i ~/cuckoo.patch```

### Configuration

There are two ways to configure the purge script: update the global variables
within the script file or add the configuration items to conf/cuckoo.py (if
you applied cuckoo patch).

There are 5 configuration variables:
* THRESHOLD - the low water mark for the filesystem to determine with the
script should start purging data
* DAEMON - define whether the script continually runs as a daemon or
periodically run by a scheduled task
* ARCHIVE - define with the each report.json and original binaries should be
archived
* BINARIES_FOLDER - either the full path to save the original binaries, or a
folder within the CWD to save those binaries
* REPORTS_FOLDER - either the full path to save the report.json files, or a
folder within the CWD to save those report.json files

### Operation

The script iteratively deletes all data for the oldest task until the
filesystem's free space rises above the defined threshold. This includes all
logs, artifacts, and reports saved to the filesystem, all task metadata saved
to the database, and all artifacts and reports saved to the web database
(MongoDB).

### Development

This script was tested and is running on the following system configuration:
* Ubuntu 16.04 LTS
* PostgreSQL 9.5
* MongoDB 3.6.12
