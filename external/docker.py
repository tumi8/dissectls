import logging
import os
import pathlib
from typing import Tuple

import docker
from docker.models.containers import Container
from docker.types import Mount

START_AT_PORT = 10000


def start_container(container: int, config_name: str) -> Tuple[str, int]:
    try:
        base_name = os.path.basename(config_name)
        if base_name.startswith('apache'):
            return start_container_apache(container, config_name)
        elif base_name.startswith('nginx'):
            return start_container_nginx(container, config_name)
        else:
            logging.fatal(f'Could not identify webserver for {config_name}')
    except Exception as e:
        logging.fatal(f'Could not start webserver {config_name}', exc_info=e)


def start_container_nginx(container: int, config_name: str) -> Tuple[str, int]:
    client = docker.from_env()
    port = START_AT_PORT + container

    config_path = os.path.abspath(config_name)
    certs_path = os.path.abspath('./certificates')
    index_path = os.path.abspath('./configs/index.html')

    mounts = [
        Mount(target='/etc/nginx/conf.d/custom.conf', read_only=True,
              source=config_path, type="bind"),
        Mount(target='/etc/certificates', read_only=True,
              source=certs_path, type="bind"),
        Mount(target='/etc/nginx/html/index.html"', read_only=True,
              source=index_path, type="bind")
    ]
    ports = {'443/tcp': port}
    container = client.containers.run("nginx:1.23", mounts=mounts, ports=ports,  detach=True)
    return container.id, port


def start_container_apache(container: int, config_name: str) -> Tuple[str, int]:
    client = docker.from_env()
    port = START_AT_PORT + container

    httpd_conf = os.path.abspath('./configs/httpd.conf')
    certs_path = os.path.abspath('./certificates')
    config_path = os.path.abspath(config_name)

    mounts = [
        Mount(target='/usr/local/apache2/conf/httpd.conf', read_only=True,
              source=httpd_conf, type="bind"),
        Mount(target='/usr/local/apache2/conf/extra/httpd-ssl.conf', read_only=True,
              source=config_path, type="bind"),
        Mount(target='/etc/certificates', read_only=True,
              source=certs_path, type="bind")
    ]
    ports = {'443/tcp': port}
    container: Container = client.containers.run("httpd:2.4", mounts=mounts, ports=ports,  detach=True)
    return container.id, port


def stop_container(container_id: str):
    client = docker.from_env()
    container = client.containers.get(container_id)
    container.stop()
    container.remove()


def save_logs(debug_dir, config_name, container_id: str):
    client = docker.from_env()
    container = client.containers.get(container_id)
    logs_std = container.logs(stderr=False)
    logs_err = container.logs(stdout=False)
    name = os.path.basename(config_name)
    if isinstance(logs_std, bytes):
        logs_std = logs_std.decode()
    if isinstance(logs_err, bytes):
        logs_err = logs_err.decode()
    try:
        pathlib.Path(os.path.join(debug_dir, f'{name}.stdout.txt')).write_text(logs_std)
        pathlib.Path(os.path.join(debug_dir, f'{name}.stderr.txt')).write_text(logs_err)
    except Exception as e:
        logging.error(f'Could not save logs for {name} in {debug_dir}', exc_info=e)
