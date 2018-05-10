import json
import os
import sys
import logging

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

moduleconfig = ['vuln_data_file']


def handler(q=False):
    log.debug('Module version: {}'.format(str(version())))
    if q is False:
        return False
    request = json.loads(q)

    if not request.get('vulnerability'):
        misperrors['error'] = 'Vulnerability ID missing for the module.'
        return misperrors

    vulnerability = request.get('vulnerability')

    if not test_vuln_data_file(request):
        misperrors['error'] = 'Cannot read file with vulnerabilities.'
        return misperrors

    num_ip = get_ip_num_by_vuln(vulnerability)
    ips = get_ip_by_vuln(vulnerability)
    print_request(request)

    results = {'results': [{'types': mispattributes['output'],
                      'values': ips}]}

    return results

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

def test_vuln_data_file(request):
    if request.get('config'):
        config = request['config']
        if config.get('vuln_data_file'):
            filename = config['vuln_data_file']
            if os.path.isfile(filename):
                return True
            else:
                log.info('Cannot find specified file {}'.format(filename))
                return False
        else:
            log.info('Cannot open config section in request')
            return False
    else:
        return False

def get_ip_by_vuln(vuln):
    ips = ['127.0.0.1']
    return ips

def get_ip_num_by_vuln(vuln):
    num = 0
    return num

def print_request(request):
    log.debug('Request: {}'.format(str(request)))
    # print(request)
