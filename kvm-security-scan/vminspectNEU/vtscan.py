import re
import time
import logging
import requests
from collections import namedtuple
from itertools import chain, islice

from vminspect.filesystem import FileSystem


VTReport = namedtuple('VTReport', ('path', 'hash', 'detections'))


class VTScanner:

    def __init__(self, disk, apikey):
        self._disk = disk
        self._apikey = apikey
        self._filesystem = None
        self.batchsize = 1
        self.logger = logging.getLogger(
            "%s.%s" % (self.__module__, self.__class__.__name__))

    def __enter__(self):
        self._filesystem = FileSystem(self._disk)
        self._filesystem.mount()

        return self

    def __exit__(self, *_):
        self._filesystem.umount()

    def __getattr__(self, attr):
        return getattr(self._filesystem, attr)

    @property
    def apikey(self):
        return self._apikey

    def scan(self, filetypes=None):

        print("I'm here!1")

        self.logger.debug("Scanning FS content.")
        all_checksums = self._filesystem.checksums('/')

        print("I'm here!2")

        checksums = self.filetype_filter(all_checksums, filetypes=filetypes)
        print(len(list(checksums)))

        print("I'm here!3")
        # self.logger.debug("Querying %d objects to VTotal.", checksums)
#        print("checksum: " + checksums)

        aggregated_files = {}
        for files in chunks(checksums, size=self.batchsize):
            files = dict((reversed(e) for e in files))

            if len(aggregated_files) < 100:
                aggregated_files.update(files)
            else:
#            print("@@@@@@@@@@@@@@ files @@@@@@@@@@@@@")
#            for key in files.keys():
#                print(key + ", " + files[key])

                response = vtquery(self._apikey, aggregated_files.keys())

                yield from self.parse_response(aggregated_files, response)
                aggregated_files = {}

    def filetype_filter(self, files, filetypes=None):
#        print(len(list(files)))
        #for f in files:
        #    print(f)
#        print(type(filetypes))
#        print(filetypes)
        if filetypes is not None:
            #return [f for f in files
            #        if any((re.match(t, self._filesystem.file(f[0]))
            #                for t in filetypes))]
            matched_file_list = []
            for f in files:
                for t in filetypes:
                    if re.match(t, f[0]):
#                            print(self._filesystem.file(f[0]))
                            matched_file_list.append(f)
                            break
            return matched_file_list
        else:
            return files

    def parse_response(self, files, response):
        response = isinstance(response, list) and response or [response]

        for result in response:
            yield from self.parse_result(result, files)

    def parse_result(self, result, files):
        sha1 = result['resource']
        path = files[sha1]

        if result['response_code'] > 0:
            positives = result['positives']

            self.logger.debug("%s - %d positives.", path, positives)

            if positives > 0:
                detections = {engine: detection for engine, detection
                              in result['scans'].items()
                              if detection['detected']}

                yield VTReport(path, sha1, detections)
        else:
            self.logger.debug("%s - Unknown file.", path)

            yield VTReport(path, sha1, 'UNKNOWN')


def vtquery(apikey, checksums):
    request_url = VT_REPORT_URL + "?" + "apikey=" + apikey + "&resource=" + ",".join(checksums)

    while 1:
        #response = requests.post(VT_REPORT_URL, data=data)
        response = requests.get(request_url)
        response.raise_for_status()

        if response.status_code == 200:
            print(response.json())
            return response.json()
        elif response.status_code == 204:
            logging.debug("API key request rate limit reached, throttling.")
            print("API key request rate limit reached, throttling.")
            time.sleep(VT_THROTTLE)
        else:
            raise RuntimeError("Response status code %s" % response.status_code)


def chunks(iterable, size=1):
    """Splits iterator in chunks."""
    iterator = iter(iterable)

    for element in iterator:
        yield chain([element], islice(iterator, size - 1))


VT_THROTTLE = 5 
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
