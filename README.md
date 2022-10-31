# DissecTLS Experiment Setup

This repository describes the experiment we have conducted to compare the capabilities of different TLS scanners.
You need to provide the path to the DissecTLS fork from the TUM Goscanner that implements a JARM and DissecTLS scan and a local verison of testssl.sh.

To perform a local measurement using docker servers you can run

    ./main.py local_scan --config-dir ./tmp --output-dir ./test-output --goscanner-bin ~/goscanner --testssl-bin ~/testssl.sh/testssl.sh --capture-chs True --debug-dir ./server-logs

To scan external servers run, e.g.,

    ./main.py remote_scan --output-dir ./test-output-2 --goscanner-bin ~/goscanner --testssl-bin ~/testssl.sh/testssl.sh --capture-chs True --input-file ./example.input
