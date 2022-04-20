import logging
import redis
import json
import sys
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

from filesystem import FileSystem


class VulnScanner:
    def __init__(self, disk, redis_addr):
        self._disk = disk
        self._filesystem = None
        if ":" in redis_addr:
            redis_IP, redis_port = redis_addr.split(":")
        else:
            redis_IP, redis_port = redis_addr, 6379
        self._cve_redis = redis.StrictRedis(host=redis_IP, port=redis_port, db=0, socket_timeout=2)
        self._app_redis = redis.StrictRedis(host=redis_IP, port=redis_port, db=1, socket_timeout=2)

    def __enter__(self):
        self._filesystem = FileSystem(self._disk)
        try:
            self._filesystem.mount()
        except:
            logging.warning("The disk cannot be mounted. Skip the scanning.")
            sys.exit(-1)

        return self

    def __exit__(self, *_):
        self._filesystem.umount()

    def __getattr__(self, attr):
        return getattr(self._filesystem, attr)

    def scan(self, concurrency=1):
        """
        VulnApp(name             -> application name
                version          -> application version
                vulnerabilities) -> list of Vulnerabilities

        Vulnerability(id       -> CVE Id
                      summary) -> brief description of the vulnerability
        """
        self.logger.debug("Scanning FS content.")

        #applications = self.applications()
        #print("#####application versions: ######")
        #for application in applications:
        #   print(application.name + " : " + application.version + " : " + application.publisher)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = executor.map(self.query_vulnerabilities,
                                   self.applications()) 
        for report in results:
            application, vulnerabilities = report
                
            if vulnerabilities:
                yield VulnApp(application.name,
                              application.version,
                              vulnerabilities)

    def query_vulnerabilities(self, application):
        self.logger.debug("Quering %s vulnerabilities.", application.name)

        name = application.name.lower()
        version = application.version
        results = []
        cve_set = self._app_redis.smembers(name)

        for cve_id in cve_set:
            cve = json.loads(self._cve_redis.get(cve_id).decode('utf-8'))
            vendor_list = cve['cve']['affects']['vendor']['vendor_data']
            for vendor in vendor_list:
                for product in vendor['product']['product_data']: 
                    if product['product_name'].lower() == name:
                        product_versions_list = product['version']['version_data']
                        if {'version_value': version} in product_versions_list:
                            results.append(cve)
        return application, results

    def query_cve_info(self, cve_id):
        # query local cve database
        result = [item['cve'] for item in self._cvefeed if item['cve']['CVE_data_meta']['ID'] == cve_id]
        return result

    def applications(self):
        return (Application(a['app2_name'], a['app2_version'], a['app2_publisher'])
                for a in self._filesystem.inspect_list_applications2(
                        self._filesystem._root))


def lookup_vulnerabilities(app_version, vulnerabilities):
    for vulnerability in vulnerabilities:
        for configuration in vulnerability['vulnerable_configuration']:
            try:
                vuln_version = configuration.split(':')[5]
            except IndexError:
                pass
            else:
                if app_version == vuln_version:
                    yield Vulnerability(vulnerability['id'],
                                        vulnerability['summary'])


VulnApp = namedtuple('VulnApp', ('name',
                                 'version',
                                 'vulnerabilities'))
Application = namedtuple('Application', ('name',
                                         'version',
                                         'publisher'))
Vulnerability = namedtuple('Vulnerability', ('id',
                                             'summary'))
FullVuln = namedtuple('FullVuln', ('id', 'summary', 'impact'))
