import codecs
import csv
import hashlib
import json
import logging
import os
import pathlib
import shutil
import subprocess
from typing import Optional

import validators

GOSCANNER_DISSECTLS_CONF = "./goscanner/dissectls.conf"
GOSCANNER_JARM_CONF = "./goscanner/jarm.conf"
GOSCANNER_ATSF_CONF = "./goscanner/atsf.conf"


def tcpdump_start(port: Optional[int]):
    p_query = f'tcp port {port} and ' if port is not None else ''
    # Capture only Client Hellos
    cmd = ['tcpdump', '-i', 'any', '-w', '/dev/null ', #'--count',  #
           f'{p_query}(tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p


def tcpdump_stop(p: subprocess.Popen):
    p.terminate()
    try:
        outs, errs = p.communicate(timeout=15)
    except:
        p.kill()
        outs, errs = p.communicate(timeout=15)
    if 'packets captured' not in outs:
        logging.error(outs)
        return None, None
    else:
        try:
            lines = outs.splitlines()
            captured = lines[-3].split()[0]
            received = lines[-2].split()[0]
            return captured, received
        except Exception as e:
            logging.fatal(f'could not extract data from: {outs} {lines}', exc_info=e)


def goscanner_normal(goscanner_bin: str, input_file: str, output_dir: str):
    log_file = f'{output_dir}.log'
    new_input_file = f'{output_dir}.input'
    pathlib.Path(output_dir).parent.mkdir(exist_ok=True, parents=True)
    shutil.rmtree(output_dir, ignore_errors=True)
    subprocess.check_output(
        f'{goscanner_bin} create-ch-input --ch-dir ./goscanner/client-hellos -i {input_file} | shuf > {new_input_file}',
        shell=True)
    subprocess.check_output([goscanner_bin, '-C', GOSCANNER_ATSF_CONF, '-i', new_input_file, '-o', output_dir, '-l', log_file])


def generate_goscanner_fps(goscanner_bin: str, output_dir: str):
    temp_sorting_dir = f'{output_dir}.tmp'
    pathlib.Path(temp_sorting_dir).mkdir(exist_ok=True)
    subprocess.check_output(
        [goscanner_bin, 'generate-fingerprints', '--ch-dir', './goscanner/client-hellos', '--scanner-dir', output_dir, '--tmp-dir', temp_sorting_dir])
    shutil.rmtree(temp_sorting_dir, ignore_errors=True)


def goscanner_deep_tls(goscanner_bin: str, input_file: str, number_of_chs: int, output_dir: str):
    pathlib.Path(output_dir).parent.mkdir(exist_ok=True, parents=True)
    log_file = f'{output_dir}.log'
    shutil.rmtree(output_dir, ignore_errors=True)
    subprocess.check_output([goscanner_bin, '-C', GOSCANNER_DISSECTLS_CONF, '-i', input_file, '-o', output_dir,
                             '--deep-tls-max-chs', str(number_of_chs), '-l', log_file])


def goscanner_jarm(goscanner_bin: str, input_file: str, output_dir: str):
    pathlib.Path(output_dir).parent.mkdir(exist_ok=True, parents=True)
    log_file = f'{output_dir}.log'
    shutil.rmtree(output_dir, ignore_errors=True)
    subprocess.check_output(
        [goscanner_bin, '-C', GOSCANNER_JARM_CONF, '-i', input_file, '-o', output_dir, '-l', log_file])


def sslyze(input_file: str, output_dir: str):
    pathlib.Path(output_dir).mkdir(exist_ok=True, parents=True)
    output_file = os.path.join(output_dir, f'sslyze.json')
    new_input = f'{output_dir}.input'

    with pathlib.Path(new_input).open(mode='w') as f:
        with pathlib.Path(input_file).open() as f2:
            for row in csv.reader(f2):
                if len(row) > 1:
                    host = row[1]
                    ip = row[0]
                    if validators.ipv6(ip) and '[' not in ip:
                        ip = f'[{ip}]'
                    f.write(f'{host}{{{ip}}}' + os.linesep)
                else:
                    f.write(row[0] + os.linesep)
    # Need to extract "scan_result" and remove tls1_3 "public_bytes"
    subprocess.check_output(
        ['python3', '-m', 'sslyze', '--targets_in', new_input, f'--json_out={output_file}', '--sslv2', '--sslv3',
         '--tlsv1', '--tlsv1_1', '--tlsv1_2', '--tlsv1_3', '--elliptic_curves', '--compression', '--resum',
         '--fallback', '--reneg', '--early_data'], timeout=3600)


def generate_sslyze_fingerprints(output_dir: str):
    output_file = os.path.join(output_dir, f'sslyze.json')
    fp_file = os.path.join(output_dir, f'fingerprints.csv')

    with pathlib.Path(output_file).open() as f:
        json_result = json.load(f)

    with pathlib.Path(fp_file).open(mode='w') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'port', 'server_name', 'fingerprint', 'fingerprint_raw'])
        for server_scan_results in json_result.get('server_scan_results'):
            location = server_scan_results.get('server_location')

            scan_result: dict = server_scan_results.get('scan_result')
            if scan_result is not None:
                for sslyze_test, test_result in scan_result.items():
                    result = test_result.get('result')
                    if result is not None:
                        accepted_cipher_suites = result.get('accepted_cipher_suites')
                        if accepted_cipher_suites is not None:
                            for accepted_cipher_suite in accepted_cipher_suites:
                                del accepted_cipher_suite['ephemeral_key']
                                if accepted_cipher_suite.get('cipher_suite') is not None:
                                    del accepted_cipher_suite['cipher_suite']['openssl_name']
                        rejected_cipher_suites = result.get('rejected_cipher_suites')
                        if rejected_cipher_suites is not None:
                            for rejected_cipher_suite in rejected_cipher_suites:
                                del rejected_cipher_suite['error_message']
                                if rejected_cipher_suite.get('cipher_suite') is not None:
                                    del rejected_cipher_suite['cipher_suite']['openssl_name']

            fp = json.dumps(scan_result, sort_keys=True)
            fp_hashed = hashlib.sha256(fp.encode()).hexdigest()

            writer.writerow([location['ip_address'], location['port'], location['hostname'], fp_hashed, fp])


def testssl(testssl_bin: str, input_file: str, output_dir: str):
    new_input = f'{output_dir}.input'
    pathlib.Path(output_dir).mkdir(exist_ok=True, parents=True)
    output_file = os.path.join(output_dir, f'testssl.json')

    with pathlib.Path(new_input).open(mode='w') as f:
        with pathlib.Path(input_file).open() as f2:
            for row in csv.reader(f2):
                ip = row[0]
                port = 443
                # Currently not supporting ipv6 + port
                if not '[' in ip and not validators.ipv6(ip):
                    splits = row[0].split(':')
                    ip = splits[0]
                    if len(splits) > 1:
                        port = splits[1]
                server_name = 'example.com'
                if len(row) > 1:
                    server_name = row[1]
                add_6 = ''
                if validators.ipv6(ip):
                    add_6 = '-6'
                f.write(
                    f'-e -s -f -p -P -S -q -g --connect-timeout 15 --openssl-timeout 15 --nodns none {add_6} --ip {ip} {server_name}:{port}' + os.linesep)

    subprocess.check_output([testssl_bin, '--jsonfile', output_file, '--parallel', '--file', new_input], timeout=3600)


def is_bad_testssl_id(id: str) -> bool:
    if id in ['scanTime', 'optimal_proto', 'TLS_timestamp', 'TLS_session_ticket']:
        return True
    for skipped_field in ['DNS_', 'OCSP_', 'cert', 'intermediate_cert']:
        if id.startswith(skipped_field):
            return True
    if id.endswith('Problem') or id.endswith('problem'):
        return True
    return False


def generate_testssl_fingerprints(output_dir: str):
    output_file = os.path.join(output_dir, f'testssl.json')
    fp_file = os.path.join(output_dir, f'fingerprints.csv')

    result = dict()
    with codecs.open(output_file, errors='ignore') as f:
        testssl_data = json.load(f, strict=False)
        for entry in testssl_data:
            target = f'{entry.get("ip")}/{entry.get("port")}'
            id = entry.get('id')
            if is_bad_testssl_id(id):
                continue
            finding: str = entry.get('finding')
            r = result.get(target)
            if r is None:
                r = dict()
            r[id] = finding
            result[target] = r

    with pathlib.Path(fp_file).open(mode='w') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'port', 'server_name', 'fingerprint', 'fingerprint_raw'])
        for target, r in result.items():
            fp = json.dumps(r, sort_keys=True)
            fp_hash = hashlib.sha256(fp.encode()).hexdigest()
            server_name, ip, port = target.split('/')
            ip = ip.replace('[', '').replace(']', '')
            if ip != '':
                writer.writerow([ip, port, server_name, fp_hash, fp])
