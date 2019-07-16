from cuckoo.core.database import Database, Task, Submit, Sample, Error, Guest
from cuckoo.common.config import config
from cuckoo.misc import decide_cwd
from cuckoo.misc import cwd as get_cwd
from cuckoo.common.exceptions import CuckooDatabaseError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import timedelta
from datetime import datetime as dt
from time import sleep
from sys import exit
import click
import os
import shutil
import gzip
import logging

# Globals. These could move to cuckoo conf files, but would require updates to
#          the configuration parser in cuckoo.common.config
THRESHOLD = None  # IN GB
# Setting to False will iteratively delete a single day of tasks per script run
DAEMON = False
ARCHIVE = False
BINARIES_FOLDER = 'binaries'
REPORTS_FOLDER = 'reports'

class CuckooDatabase:
    """A simple object to wrap up the postgres database calls and handle
    deleting the rows in each table in the correct order.
    """

    def __init__(self):
        db = Database()
        try:
            db.connect(schema_check=False)
        except CuckooDatabaseError:
            exit('Invalid cuckoo database credentials')
        db.engine.echo = False
        db.engine.pool_timeout = 60
        self.session = sessionmaker(bind=db.engine)()

    def oldest_id(self):
        """Query for the oldest analysis task.

        Returns:
            row: Oldest Task ID object
        """
        search = self.session.query(Task)
        return search.order_by(Task.added_on.asc()).first()

    def tasks_byday(self, day):
        """Query and returns all tasks added on a certain day.

        Args:
            day: datetime.date value to query against
        Returns:
            tuple: A tuple containing the IDs for the Task, Submit
            and Sample
        """
        search = self.session.query(Task)
        return [(task.id, task.submit_id, task.sample_id)
                for task in search.filter(Task.added_on < day).all()]

    def delete_bytable(self, table, column, id):
        """Builds the Query object for the given Table and iteratively
        deletes the rows by ID.

        Args:
            table: The postgres table
            column: The column to query
            id: ID of the row to delete from the given Table
        """
        search = self.session.query(table)
        for row in search.filter(column == id):
            try:
                self.session.delete(row)
                self.session.commit()
            except SQLAlchemyError as e:
                logging.warning("Database error deleting row: {0}".format(e))
                self.session.rollback()

    def isorphan(self, column, id):
        """Determine if a Submit or Sample row has an associated Task or have
        all Tasks been deleted.

        Args:
            column: The column to query
            id: Sample or Submit ID column in Task row
        """
        search = self.session.query(Task)
        if len(search.filter(column == id).all()) > 0:
            return False
        return True


class CuckooWeb:
    """A simple object to wrap up the mongo database calls and handle
    deleting the documents from each table.
    """

    def __init__(self):
        client = MongoClient()
        self.db = client[config("reporting:mongodb:db")]

    def deletes(self, id):
        """Queries mongo for the _id of the analysis document associated with a
        given postgres Task ID. The _id of any connected file documents and call
        documents are also extracted from the queried analysis document.

        Args:
            id: The postgres Task ID to delete
        """
        analysis = self.db.analysis.find_one({'info.id': id})
        files = []
        if analysis:
            if 'target' in analysis.keys():
                files += [analysis['target'].get('file_id', None)]
            files += [shot['original'] for shot in analysis.get('shots', [])]
            if 'network' in analysis.keys():
                files += [analysis['network'].get('pcap_id', None)]
                files += [analysis['network'].get('sorted_pcap_id', None)]
            self._delete_files(files)
            if 'behavior' in analysis.keys():
                self._delete_calls(
                    [call for process in
                     analysis['behavior'].get('processes', [])
                     for call in process['calls']]
                )
            self.db.analysis.delete_one({'_id': analysis['_id']})

    def _delete_calls(self, calls):
        """Iterates over a list of call documents and deletes them.

        Args:
            id: List of _ids for call documents
        """
        for call in calls:
            self.db.calls.delete_one({'_id': call})

    def _delete_files(self, files):
        """Iterates over a list of file documents and deletes them and their
        connected file chunks.

        Args:
            id: List of _ids for file documents
        """
        for file in files:
            self.db.fs.chunks.delete_many({'files_id': file})
            self.db.fs.files.delete_many({'_id': file})


class Archiver:
    """A simple object to wrap up the archiving steps and create the archive
    folders. """

    def __init__(self):
        if BINARIES_FOLDER.startswith('/'):
            self.binary_folder = BINARIES_FOLDER
        else:
            self.binary_folder = get_cwd(BINARIES_FOLDER)
        if REPORTS_FOLDER.startswith('/'):
            self.reports_folder = REPORTS_FOLDER
        else:
            self.reports_folder = get_cwd(REPORTS_FOLDER)
        try:
            if not os.path.exists(self.binary_folder):
                os.makedirs(self.binary_folder)
        except OSError:
            exit('Error creating binary archival folder')
        try:
            if not os.path.exists(self.reports_folder):
                os.makedirs(self.reports_folder)
        except OSError:
            exit('Error creating reports archival folder')

    def archive_files(self, id):
        """Follow the symlink and move the analyzed binary to an archive
        folder. Then compress the report.json file and move it to an archive
        folder.

        Args:
            id: The Task ID from the postgres cuckoo database
        """
        try:
            binary = os.readlink('{}/storage/analyses/{}/binary'.format(
                get_cwd(), id))
            shutil.copy(binary, self.binary_folder)
        except IOError:
            logging.warning('Failed to archive original binary')
        report = '{}/storage/analyses/{}/reports/report.json'.format(
            get_cwd(), id)
        compressed = '{}/report_{}.json.gz'.format(self.reports_folder, id)
        try:
            with open(report, 'rb') as json, gzip.open(compressed, 'wb') as gz:
                shutil.copyfileobj(json, gz)
        except IOError:
            logging.warning('Failed to archive analysis report file')


def purge_disk(id):
    """Delete the cuckoo analysis folder. If archiving is configured, archive
    the report.json file and the analyzed sample.

    Args:
        id: Task ID from the postgres cuckoo database
    """
    if ARCHIVE:
        archiver.archive_files(id)
    analysis_folder = '{}/storage/analyses/{}'.format(get_cwd(), id)
    try:
        shutil.rmtree(analysis_folder)
    except OSError:
        logging.warning('Error deleting analysis folder: {}'.format(
            analysis_folder))


def purge_db(ids):
    """Deletes a Task and its connected rows from the cuckoo database.

    Args:
        ids: Tuple of Task, Sample, and Submit ID from the cuckoo database
    """
    cuckoo_db.delete_bytable(Error, Error.task_id, ids[0])
    cuckoo_db.delete_bytable(Guest, Guest.task_id, ids[0])
    cuckoo_db.delete_bytable(Task, Task.id, ids[0])
    if cuckoo_db.isorphan(Task.submit_id, ids[0]):
        cuckoo_db.delete_bytable(Submit, Submit.id, ids[1])
    if cuckoo_db.isorphan(Task.sample_id, ids[0]):
        cuckoo_db.delete_bytable(Sample, Sample.id, ids[2])


def purge(ids):
    """Purges the data from each data store for one task
    (database, web, filesystem)."""
    logging.info('Purging task ID #{}'.format(ids[0]))
    purge_db(ids)
    cuckoo_web.deletes(ids[0])
    purge_disk(ids[0])


def purge_day():
    """Queries for a list of Task IDs from the oldest day and purges the data
    from each data store (postgres, mongo, filesystem)."""
    task = cuckoo_db.oldest_id()
    oldest_date = (task.added_on.date() + timedelta(days=1))
    ids = cuckoo_db.tasks_byday(oldest_date)
    for id in ids:
        purge(id)


def low_storage():
    """Queries the filesystem for available storage."""
    reserve = (THRESHOLD * 2 ** 30)
    stat = os.statvfs(get_cwd())
    available = (stat.f_bavail * stat.f_bsize)
    logging.info('Available space - {}GB'.format(available / 2 ** 30))
    if available < reserve:
        return True
    return False


def print_help():
    exit("""
There are two ways to configure the cuckoo purge script:
    (1) Configure the global variables within the purge.py script file.
    (2) Patch the cuckoo.common.config module to include the purge settings and
        define the purge configuration settings in the conf/cuckoo.conf file
    """)


def read_config():
    global THRESHOLD, DAEMON, ARCHIVE, BINARIES_FOLDER, REPORTS_FOLDER
    if config("cuckoo:purge:threshold"):
        THRESHOLD = config("cuckoo:purge:threshold")
        DAEMON = config("cuckoo:purge:daemon")
        ARCHIVE = config("cuckoo:purge:archive")
        BINARIES_FOLDER = config("cuckoo:purge:binaries_folder")
        REPORTS_FOLDER = config("cuckoo:purge:reports_folder")


@click.command()
@click.option("--cwd", required=True, help="Cuckoo Working Directory")
def main(cwd):
    decide_cwd(cwd)
    if config("cuckoo:database:connection") is None and \
        not os.path.exists(get_cwd("cuckoo.db")):
        exit('Invalid Cuckoo Working Directory provided.')
    read_config()
    if not isinstance(THRESHOLD, int):
        print_help()
        exit()
    try:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s, %(levelname)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            filename='{}/purge.log'.format(get_cwd("log")))
    except IOError:
        exit('Error writing to log file: {}/purge.log'.format(get_cwd("log")))
    global cuckoo_db, cuckoo_web, archiver
    cuckoo_db = CuckooDatabase()
    cuckoo_web = CuckooWeb()
    archiver = Archiver()
    if not DAEMON:
        while low_storage():
            purge_day()
        return True
    else:
        while True:
            if low_storage():
                task = cuckoo_db.oldest_id()
                purge((task.id, task.submit_id, task.sample_id))
            else:
                sleep(600)

if __name__ == "__main__":
    main()

