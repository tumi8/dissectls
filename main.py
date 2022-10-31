#!/usr/bin/env python3

import itertools
import logging
import os
import pathlib
import shutil
import time
from functools import reduce
from multiprocessing import Pool
from typing import Iterator, Optional, Tuple, List

import click
import docker as docker_conn
from docker import DockerClient

import external.docker as docker
import external.subprocesses as subprocesses
import tls_configs.apache as apache
import tls_configs.nginx as nginx
from tls_configs.test_case import create_test_cases
from tls_configs.tls_config import generate_configs, TLSConfig


@click.group()
def main():
    pass


@main.command()
@click.option('--config-dir', type=click.Path(file_okay=False), required=True)
@click.option('--output-dir', type=click.Path(file_okay=False), required=True)
@click.option('--goscanner-bin', type=click.Path(dir_okay=False, exists=True), required=True)
@click.option('--testssl-bin', type=click.Path(dir_okay=False, exists=True), required=True)
@click.option('--debug-dir', type=click.Path(file_okay=False))
@click.option('--chunk-size', type=int, default=100)
@click.option('--capture-chs', type=bool, default=True)
def local_scan(config_dir: str, output_dir: str, debug_dir: Optional[str], goscanner_bin: str, testssl_bin: str,
         chunk_size: int, capture_chs: bool):
    logging.basicConfig(level=logging.WARNING)
    test_cases = create_test_cases(output_dir)
    for test_case in test_cases:
        # Create config Permutations (power set)
        configurations = generate_configs(test_case)
        for i, chunk in enumerate(chunker(configurations, chunk_size)):
            # Clear old configs
            shutil.rmtree(config_dir, ignore_errors=True)
            os.mkdir(config_dir)

            for webserver in ['nginx', 'apache']:
                # Save webserver configurations on disk
                config_names = list(create_webserver_configs(webserver, i, config_dir, chunk))

                containers = []

                output_dir = os.path.join(test_case.get_output_dir(), webserver)

                try:
                    # Start Webservers
                    containers, ports = start_webservers(config_names)

                    # Scan which each scanner
                    do_docker_scan(i, ports, output_dir, debug_dir, goscanner_bin, testssl_bin, capture_chs)
                finally:
                    # Stop webservers
                    stop_webservers(containers, config_names, debug_dir)

@main.command()
@click.option('--input-file', type=click.Path(file_okay=True, exists=True, dir_okay=False), required=True)
@click.option('--output-dir', type=click.Path(file_okay=False), required=True)
@click.option('--goscanner-bin', type=click.Path(dir_okay=False, exists=True), required=True)
@click.option('--testssl-bin', type=click.Path(dir_okay=False, exists=True), required=True)
@click.option('--capture-chs', type=bool, default=True)
def remote_scan(input_file: str, output_dir: str, goscanner_bin: str, testssl_bin: str, capture_chs: bool):
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
    with Pool() as p:
        async_jobs = []
        # Active TLS fingerprinting
        with CaptureClientHellos(capture_chs, [443], os.path.join(output_dir, 'atsf_chs.csv')):
            fixed_dir = os.path.join(output_dir, 'atsf')
            subprocesses.goscanner_normal(goscanner_bin, input_file, fixed_dir)
            async_jobs.append(p.apply_async(subprocesses.generate_goscanner_fps, (goscanner_bin, fixed_dir)))
        # 2x DeepTLS
        with CaptureClientHellos(capture_chs, [443], os.path.join(output_dir, 'dissectls_10_chs.csv')):
            subprocesses.goscanner_deep_tls(goscanner_bin, input_file, 10, os.path.join(output_dir, 'dissectls_10'))

        with CaptureClientHellos(capture_chs, [443], os.path.join(output_dir, 'dissectls_chs.csv')):
            subprocesses.goscanner_deep_tls(goscanner_bin, input_file, 100, os.path.join(output_dir, 'dissectls'))
        # JARM
        with CaptureClientHellos(capture_chs, [443], os.path.join(output_dir, 'jarm_chs.csv')):
            subprocesses.goscanner_jarm(goscanner_bin, input_file, os.path.join(output_dir, 'jarm'))

        # testssl.sh
        with pathlib.Path(input_file).open() as f:
            for i, chunk in enumerate(chunker(f, 200)):
                logging.info(f'Iteration {i} started')
                iteration_input = os.path.join(output_dir, f'iteration-{i}-input.csv')
                pathlib.Path(iteration_input).write_text(reduce(lambda x,y: x+y, chunk))

                with CaptureClientHellos(capture_chs, [443], os.path.join(output_dir, 'testssl_chs.csv')):
                    testssl_dir = os.path.join(output_dir, 'testssl', f'iteration={i}')
                    subprocesses.testssl(testssl_bin, iteration_input, testssl_dir)
                    async_jobs.append(p.apply_async(subprocesses.generate_testssl_fingerprints, [testssl_dir]))

                # SSLyze
                with CaptureClientHellos(capture_chs, [443], os.path.join(output_dir, 'sslyze_chs.csv')):
                    sslyze_dir = os.path.join(output_dir, 'sslyze', f'iteration={i}')
                    subprocesses.sslyze(iteration_input, sslyze_dir)

                    async_jobs.append(p.apply_async(subprocesses.generate_sslyze_fingerprints, [sslyze_dir]))

        for job in async_jobs:
            job.get()


@main.command()
@click.option('--output-dir', type=click.Path(file_okay=False), required=True)
def generate_fingerprints(output_dir: str):
    logging.basicConfig(level=logging.WARNING)
    for dirpath, dirnames, filenames in os.walk(output_dir):
        tool = os.path.basename(dirpath)
        if tool in ['sslyze', 'testssl']:
            for iteration in dirnames:
                iter_dir = pathlib.Path(os.path.join(dirpath, iteration))
                if iter_dir.is_dir():
                    try:
                        if tool == 'sslyze':
                            subprocesses.generate_sslyze_fingerprints(str(iter_dir))
                        elif tool == 'testssl':
                            subprocesses.generate_testssl_fingerprints(str(iter_dir))
                        else:
                            logging.fatal(f'Unknown option {tool}')
                    except Exception as e:
                        logging.error(f'Error during parsing {iter_dir}', exc_info=e)


def create_webserver_configs(webserver: str, iteration: int, config_dir, configurations: Iterator[TLSConfig]) -> Iterator[str]:
    if webserver == 'nginx':
        for i, config in enumerate(configurations):
            n_config = nginx.create_nginx_config(config)
            name = os.path.join(config_dir, f'nginx_{iteration}_{i}.conf')
            pathlib.Path(name).write_text(n_config)
            yield name
    elif webserver == 'apache':
        for i, config in enumerate(configurations):
            name = os.path.join(config_dir, f'apache_{iteration}_{i}.conf')
            a_config = apache.create_apache_config(config)
            pathlib.Path(name).write_text(a_config)
            yield name
    else:
        logging.fatal(f'Wrong webserver {webserver}')


def chunker(seq, size):
    chunk = []
    for s in seq:
        chunk.append(s)
        if len(chunk) == size:
            yield chunk
            chunk = []
    yield chunk


def start_webservers(config_names: List[str]) -> Tuple[list, list]:
    with Pool() as p:
        container_ports = p.starmap(docker.start_container, enumerate(config_names))
        containers, ports = zip(*container_ports)
        return containers, ports


def stop_webservers(containers: List[str], config_names, debug_dir: Optional[str]):
    with Pool() as p:
        if debug_dir is not None:
            # Debugging
            pathlib.Path(debug_dir).mkdir(exist_ok=True)
            p.starmap(docker.save_logs, zip(itertools.cycle([debug_dir]), config_names, containers))

        # 4. shutdown
        p.map(docker.stop_container, containers)

        client: DockerClient = docker_conn.from_env()
        client.containers.prune()


def do_docker_scan(iteration: int, ports: List[int], output_dir: str, debug_dir: Optional[str], goscanner_bin: str,
                   testssl_bin: str, capture_chs: bool):
    # Scan with scanners
    pathlib.Path(output_dir).mkdir(exist_ok=True, parents=True)
    input_file = os.path.join(output_dir, 'input.csv')

    pathlib.Path(input_file).write_text(os.linesep.join((f'127.0.0.1:{p}' for p in ports)))

    with Pool() as p:
        async_jobs = []

        # Active TLS fingerprinting
        with CaptureClientHellos(capture_chs, ports, os.path.join(output_dir, 'fixed_chs.csv')):
            fixed_dir = os.path.join(output_dir, 'dissectls', f'iteration={iteration}')
            subprocesses.goscanner_normal(goscanner_bin, input_file, fixed_dir)

            async_jobs.append(p.apply_async(subprocesses.generate_goscanner_fps, (goscanner_bin, fixed_dir)))
        # 2x DeepTLS
        with CaptureClientHellos(capture_chs, ports, os.path.join(output_dir, 'dissectls_10_chs.csv')):
            subprocesses.goscanner_deep_tls(goscanner_bin, input_file, 10,
                                      os.path.join(output_dir, 'dissectls_10', f'iteration={iteration}'))
        with CaptureClientHellos(capture_chs, ports, os.path.join(output_dir, 'dissectls_chs.csv')):
            subprocesses.goscanner_deep_tls(goscanner_bin, input_file, 100,
                                      os.path.join(output_dir, 'dissectls', f'iteration={iteration}'))
        # JARM
        with CaptureClientHellos(capture_chs, ports, os.path.join(output_dir, 'jarm_chs.csv')):
            subprocesses.goscanner_jarm(goscanner_bin, input_file, os.path.join(output_dir, 'jarm', f'iteration={iteration}'))

        # testssl.sh
        with CaptureClientHellos(capture_chs, ports, os.path.join(output_dir, 'testssl_chs.csv')):
            testssl_dir = os.path.join(output_dir, 'testssl', f'iteration={iteration}')
            subprocesses.testssl(testssl_bin, input_file, testssl_dir)
            async_jobs.append(p.apply_async(subprocesses.generate_testssl_fingerprints, [testssl_dir]))

        # SSLyze
        with CaptureClientHellos(capture_chs, ports, os.path.join(output_dir, 'sslyze_chs.csv')):
            sslyze_dir = os.path.join(output_dir, 'sslyze', f'iteration={iteration}')
            subprocesses.sslyze(input_file, sslyze_dir)
            async_jobs.append(p.apply_async(subprocesses.generate_sslyze_fingerprints, [sslyze_dir]))

        for job in async_jobs:
            job.get()


class CaptureClientHellos(object):
    def __init__(self, capture_chs: bool, ports: Optional[Iterator[int]], filename: str):
        self.ports = ports
        self.capture_chs = capture_chs
        self.subprocesses: list
        self.filename = filename

    def __enter__(self):
        if self.capture_chs:
            if self.ports is None:
                self.ports = [None]
            self.subprocesses = list(map(subprocesses.tcpdump_start, self.ports))
            time.sleep(2)

    def __exit__(self, type, value, traceback):
        if self.capture_chs:
            time.sleep(2)
            out = map(subprocesses.tcpdump_stop, self.subprocesses)
            with pathlib.Path(self.filename).open(mode='a') as f:
                f.writelines((','.join(line) + os.linesep for line in out if line[0] is not None))


if __name__ == "__main__":
    main()
