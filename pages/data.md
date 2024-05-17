---
layout: page
title: Data
permalink: /data/
order: 2
toc: Data
description: "This pages describes the data published for the PAM Paper \"DissecTLS: A Scalable Active Scanner for TLS Server Configurations, Capabilities, and TLS Fingerprinting\"."
---


The data set contains the raw measurement data from the section *Measurement Study on Top- and Blocklist Servers*.
The dataset consists of 9 measurements and the following files for each measurement:

* labels.csv (input list labels for each TLS handshake)
* atsf (the Active TLS Fingerprinting scan)
    * client-hellos (all client hellos used in the measurement)
    * scan
        * hosts.csv (main tls scan results)
        * http.csv (collected http data)
        * tls_verbose.csv (extended TLS data used for fingerprinting)
        * tls_fingerprints.csv (derived fingerprints for each [IP address, port, servername] target)
* dissectls
    * hosts.csv (main tls scan results)
    * dissectls.csv (the DissecTLS results)
    * http.csv (collected http data)
    * jarm.csv (the JARM fingerprints for each target)
    * tls_verbose.csv (extended TLS data)

Our measurements are based on multiple input lists and we have labeled each TLS handshake with the source where we have found the the domain or IP address.
Sources:

* Alexa Top 1 Million
* [Tranco](https://tranco-list.eu/)
* [Feodo](https://feodotracker.abuse.ch/)
* [SSLBL](https://sslbl.abuse.ch/)
                                                                    
