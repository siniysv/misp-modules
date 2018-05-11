import json
import os
import sys
import logging
import csv

log = logging.getLogger('vulnerable_hosts_csv')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'output': ['ip-src', 'ip-dst']}
moduleinfo = {'version': '0.1', 'author': 'Ivan Sinyansky',
              'description': 'Getting a list of internal IPs with a vulnerability',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['vuln_data_file', 'ip_column', 'cve_column']


def handler(q=False):
    log.debug('Module version: {}'.format(str(version())))
    if q is False:
        return False
    request = json.loads(q)

    if not request.get('vulnerability'):
        misperrors['error'] = 'Vulnerability ID missing for the module.'
        return misperrors
    vulnerability = request.get('vulnerability')
    log.debug('Using vulnerability: {}'.format(str(vulnerability)))

    if not request['config'].get('vuln_data_file'):
        misperrors['error'] = 'Filename not found in config.'
        return misperrors
    filename = request['config'].get('vuln_data_file')
    log.debug('Using file: {}'.format(str(filename)))

    if not request['config'].get('ip_column'):
        misperrors['error'] = 'ip_column not found in config.'
        return misperrors
    ip_column = request['config'].get('ip_column')
    log.debug('Using ip_column: {}'.format(str(ip_column)))

    if not request['config'].get('cve_column'):
        misperrors['error'] = 'cve_column not found in config.'
        return misperrors
    cve_column = request['config'].get('cve_column')
    log.debug('Using cve_column: {}'.format(str(cve_column)))

    ips = []
    try:
        log.debug('Opening file: {}'.format(str(filename)))
        with open(filename, 'r') as csv_file:
            csv_data = csv.reader(csv_file, delimiter=",")
            for row in csv_data:
                log.debug('Checking row: {}'.format(str(row)))
                try:
                    if vulnerability in row[int(cve_column)]:
                        ips.append(row[int(ip_column)].strip())
                except Exception as e:
                    log.error('Exception parsing csv row: {}'.format(str(e)))

    except:
        misperrors['error'] = 'Something went wrong while reading the file.'
        return misperrors

    results = {'results': [{'types': mispattributes['output'],
                      'values': ips}]}

    return results

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
