import json
import shutil
import hashlib
import logging
import argparse
from pathlib import Path
from collections import OrderedDict
from tempfile import NamedTemporaryFile

from vminspect.vtscan import VTScanner
# from vtscan import VTScanner
from vminspect.usnjrnl import usn_journal
from vminspect.winevtx import WinEventLog
from vminspect.vulnscan import VulnScanner
# from vulnscan import VulnScanner
from vminspect.comparator import DiskComparator
from vminspect.timeline import FSTimeline, NTFSTimeline
# from vminspect.winreg import RegistryHive, registry_root
from vminspect.filesystem import FileSystem, hash_filesystem, posix_path

from load_cve import dl_remote
from storescanresults import store_scan_results

def main():
    results = {}
    arguments = parse_arguments()

    logging.basicConfig(level=arguments.debug and logging.DEBUG or logging.INFO)
    logging.getLogger('requests').setLevel(logging.WARNING)

    results = COMMANDS[arguments.name](arguments)

    #if results is not None:
    #    print(json.dumps(results, indent=2))
    return (arguments, json.dumps(results, indent=2))

def list_files_command(arguments):
    return list_files(arguments.disk, identify=arguments.identify, size=arguments.size)


def list_files(disk, identify=False, size=False):
    logger = logging.getLogger('filesystem')

    with FileSystem(disk) as filesystem:
        logger.debug("Listing files.")

        files = hash_filesystem(filesystem)

        if identify:
            logger.debug("Gatering file types.")
            for file_meta in files:
                file_meta['type'] = filesystem.file(file_meta['path'])

        if size:
            logger.debug("Gatering file sizes.")
            for file_meta in files:
                file_meta['size'] = filesystem.stat(file_meta['path'])['size']

    return files


def compare_command(arguments):
    return compare_disks(arguments.disk1, arguments.disk2,
                         identify=arguments.identify, size=arguments.size,
                         extract=arguments.extract, path=arguments.path,
                         registry=arguments.registry,
                         concurrent=arguments.concurrent)


def compare_disks(disk1, disk2, identify=False, size=False, registry=False,
                  extract=False, path='.', concurrent=False):
    with DiskComparator(disk1, disk2) as comparator:
        results = comparator.compare(concurrent=concurrent,
                                     identify=identify,
                                     size=size)
        if extract:
            extract = results['created_files'] + results['modified_files']
            files = comparator.extract(1, extract, path=path)

            results.update(files)

        if registry:
            registry = comparator.compare_registry(concurrent=concurrent)

            results['registry'] = registry

    return results


def vtscan_command(arguments):
    with VTScanner(arguments.disk, arguments.apikey) as vtscanner:
        vtscanner.batchsize = arguments.batchsize
        filetypes = arguments.types and arguments.types.split(',') or None

        #vtscanner.scan(filetypes=filetypes)
        return [r._asdict() for r in vtscanner.scan(filetypes=filetypes)]


def vulnscan_command(arguments):
    with VulnScanner(arguments.disk, arguments.redisaddr) as vulnscanner:
        return [r._asdict() for r in vulnscanner.scan(arguments.concurrency)]


def usnjrnl_command(arguments):
    return parse_usnjrnl(arguments.usnjrnl, disk=arguments.disk)


def parse_usnjrnl(usnjrnl, disk=None):
    if disk is not None:
        with FileSystem(disk) as filesystem:
            return extract_usnjrnl(filesystem, usnjrnl)
    else:
        return [e._asdict() for e in usn_journal(usnjrnl)]


def extract_usnjrnl(filesystem, path):
    with NamedTemporaryFile(buffering=0) as tempfile:
        root = filesystem.inspect_get_roots()[0]
        inode = filesystem.stat(path)['ino']
        filesystem.download_inode(root, inode, tempfile.name)

        return [e._asdict() for e in usn_journal(tempfile.name)]


def timeline_command(arguments):
    logger = logging.getLogger('timeline')

    with FSTimeline(arguments.disk) as timeline:
        events = [e._asdict() for e in timeline.timeline()]

        if arguments.identify:
            logger.debug("Gatering file types.")
            events = identify_files(timeline, events)

        if arguments.hash:
            logger.debug("Gatering file hashes.")
            events = calculate_hashes(timeline, events)

    return events


def usnjrnl_timeline_command(arguments):
    logger = logging.getLogger('usnjrnl_timeline')

    with NTFSTimeline(arguments.disk) as timeline:
        events = [e._asdict() for e in timeline.usnjrnl_timeline()]

        if arguments.identify:
            logger.debug("Gatering file types.")
            events = identify_files(timeline, events)

        if arguments.hash:
            logger.debug("Gatering file hashes.")
            events = calculate_hashes(timeline, events)

        if arguments.extract:
            logger.debug("Extracting created files.")
            extract_created_files(timeline, arguments.extract, events)

        if arguments.recover:
            logger.debug("Recovering deleted files.")
            extract_deleted_files(timeline, arguments.recover, events)

    return events


def identify_files(timeline, events):
    for event in (e for e in events if e['allocated']):
        try:
            event['type'] = timeline.file(event['path'])
        except RuntimeError:
            pass

    return events


def calculate_hashes(timeline, events):
    for event in (e for e in events if e['allocated']):
        try:
            event['hash'] = timeline.checksum(event['path'])
        except RuntimeError:
            pass

    return events


def extract_created_files(timeline, path, events):
    path = Path(path)

    if not path.exists():
        path.mkdir(parents=True)

    for event in (e for e in events
                  if 'FILE_CREATE' in e['changes'] and e['allocated']):
        try:
            if 'hash' in event:
                sha_hash = event['hash']
            else:
                sha_hash = timeline.checksum(event['path'])
            source = event['path']
            name = Path(posix_path(event['path'])).name
            destination = Path(path, '_'.join((sha_hash, name)))

            if not destination.exists():
                timeline.download(source, str(destination))
        except RuntimeError:
            pass


def extract_deleted_files(timeline, path, events):
    path = Path(path)
    root = timeline.inspect_get_roots()[0]

    if not path.exists():
        path.mkdir(parents=True)

    for event in (e for e in events if 'FILE_DELETE' in e['changes']):
        inode = event['file_reference_number']

        try:
            with NamedTemporaryFile(buffering=0) as tempfile:
                timeline.download_inode(root, inode, tempfile.name)

                name = Path(posix_path(event['path'])).name
                sha_hash = hashlib.sha1(tempfile.read()).hexdigest()
                destination = Path(path, '_'.join((sha_hash, name)))

                shutil.copy(tempfile.name, str(destination))

                event['hash'] = sha_hash
                event['recovered'] = True
        except RuntimeError:
            event['recovered'] = False


def eventlog_command(arguments):
    with WinEventLog(arguments.disk) as eventlog:
        print('\n'.join(eventlog.eventlog(arguments.path)))


def parse_arguments():
    parser = argparse.ArgumentParser(description='Inspects VM disk images.')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='log in debug mode')

    subparsers = parser.add_subparsers(dest='name', title='subcommands',
                                       description='valid subcommands')

    list_parser = subparsers.add_parser('list',
                                        help='Lists the content of a disk.')
    list_parser.add_argument('disk', type=str, help='path to disk image')
    list_parser.add_argument('-i', '--identify', action='store_true',
                             default=False, help='report file types')
    list_parser.add_argument('-s', '--size', action='store_true',
                             default=False, help='report file sizes')

    compare_parser = subparsers.add_parser('compare',
                                           help='Compares two disks.')
    compare_parser.add_argument('disk1', type=str,
                                help='path to first disk image')
    compare_parser.add_argument('disk2', type=str,
                                help='path to second disk image')
    compare_parser.add_argument('-c', '--concurrent', action='store_true',
                                default=False, help='use concurrency')
    compare_parser.add_argument('-e', '--extract', action='store_true',
                                default=False, help='extract new files')
    compare_parser.add_argument('-p', '--path', type=str, default='.',
                                help='path where to extract files')
    compare_parser.add_argument('-i', '--identify', action='store_true',
                                default=False, help='report file types')
    compare_parser.add_argument('-s', '--size', action='store_true',
                                default=False, help='report file sizes')
    compare_parser.add_argument('-r', '--registry', action='store_true',
                                default=False, help='compare registry')

    registry_parser = subparsers.add_parser(
        'registry', help='Lists the content of a registry file.')
    registry_parser.add_argument('hive', type=str, help='path to hive file')
    registry_parser.add_argument('-s', '--sort', action='store_true',
                                 default=False,
                                 help='sort the keys by timestamp')
    registry_parser.add_argument('-d', '--disk', type=str, default=None,
                                 help='path to disk image')

    vtscan_parser = subparsers.add_parser(
        'vtscan', help='Scans a disk and queries VirusTotal.')
    vtscan_parser.add_argument('apikey', type=str, help='VirusTotal API key')
    vtscan_parser.add_argument('disk', type=str, help='path to disk image')
    vtscan_parser.add_argument('-b', '--batchsize', type=int, default=1,
                               help='VT requests batch size')
    vtscan_parser.add_argument(
        '-t', '--types', type=str, default='',
        help='comma separated list of file types (REGEX) to be scanned')

    # vulnscan arguments:
    # changes made here to download CVE db feed from NVD
    vulnscan_parser = subparsers.add_parser(
        'vulnscan', help='Scans a disk and queries VBE.')
    #vulnscan_parser.add_argument('url', type=str,
    #                             help='URL to vulnerabilities DB')
    vulnscan_parser.add_argument('redisaddr', type=str,
            help='the redis address to connect to retrieve CVE data')
    vulnscan_parser.add_argument('disk', type=str, help='path to disk image')
    vulnscan_parser.add_argument('-c', '--concurrency', type=int, default=1,
            help='amount of concurrent queries against DB')
    # options for downloading CVE database:
    vulnscan_parser.add_argument('-r', '--remote', action='store_true', default=False,
            help='download CVE data feed from NVD at https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')

    usnjrnl_parser = subparsers.add_parser(
        'usnjrnl', help='Parses the Update Sequence Number Journal file.')
    usnjrnl_parser.add_argument('-u', '--usnjrnl', type=str,
                                default='C:\\$Extend\\$UsnJrnl',
                                help='path to USN file')
    usnjrnl_parser.add_argument('-d', '--disk', type=str, default=None,
                                help='path to disk image')

    timeline_parser = subparsers.add_parser('timeline',
                                            help="""Parses the disk content
                                            to build a timeline of events.""")
    timeline_parser.add_argument('disk', type=str, help='path to disk image')
    timeline_parser.add_argument('-i', '--identify', default=False,
                                 action='store_true', help='report file types')
    timeline_parser.add_argument('-s', '--hash', action='store_true',
                                 default=False, help='report file hash (SHA1)')

    usnjrnl_timeline_parser = subparsers.add_parser(
        'usnjrnl_timeline', help="""Parses the NTFS Update Sequence Number
        Journal to build a timeline of events.""")
    usnjrnl_timeline_parser.add_argument('disk', type=str,
                                         help='path to disk image')
    usnjrnl_timeline_parser.add_argument('-i', '--identify', default=False,
                                         action='store_true',
                                         help='report file types')
    usnjrnl_timeline_parser.add_argument('-s', '--hash', action='store_true',
                                         default=False,
                                         help='report file hash (SHA1)')
    usnjrnl_timeline_parser.add_argument('-e', '--extract', type=str,
                                         default='',
                                         help='Extract created files into path')
    usnjrnl_timeline_parser.add_argument('-r', '--recover', type=str,
                                         default='',
                                         help='Try recovering deleted files')

    eventlog_parser = subparsers.add_parser(
        'eventlog', help="""Parses the given Windows Event Log.""")
    eventlog_parser.add_argument('disk', type=str, help='path to disk image')
    eventlog_parser.add_argument('path', type=str, help='path to event log')

    return parser.parse_args()


# list all the files contained within a disk image
# Compare two disk images
# Query Virustotal regarding the content of a disk.
# Query a CVE database for vulnerable applications.
# Extract event timelines of NTFS disks. Installation of 7Zip on Windows 7.
# Parse Windows Event Log files.
COMMANDS = {'list': list_files_command,
            'compare': compare_command,
            'vtscan': vtscan_command,
            'vulnscan': vulnscan_command,
            'usnjrnl': usnjrnl_command,
            'timeline': timeline_command,
            'usnjrnl_timeline': usnjrnl_timeline_command,
            'eventlog': eventlog_command}


if __name__ == '__main__':
    arguments, results = main()
    store_scan_results(arguments,results)
