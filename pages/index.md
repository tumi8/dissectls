---
layout: page
toc: Home
permalink: /
order: 1
title: "DissecTLS"
description: "Additional material for the publication \"DissecTLS: A Scalable Active Scanner for TLS Server Configurations, Capabilities, and TLS Fingerprinting\" and acces to measruemnt data and code."
---

The paper was published at the [PAM 2023](https://pam2023.networks.imdea.org/).

Read the final version of our paper at Springer: **[[PDF]](https://link.springer.com/content/pdf/10.1007/978-3-031-28486-1_6.pdf)** **[[ONLINE]](https://link.springer.com/chapter/10.1007/978-3-031-28486-1_6)**

<div class="accordion-box">
  <div class="accordion-box__title">
    Abstract
  </div>
  <div class="accordion-box__content">
      <p>Collecting metadata from TLS servers on a large scale allows to draw conclusions about their capabilities and configuration.
This provides not only insights into the Internet but it enables use cases like detecting malicious C&C servers.
However, active scanners can only observe and interpret the behavior of TLS servers, the underlying configuration and implementation causing the behavior remains hidden.
Existing approaches struggle between resource intensive scans that can reconstruct this data and light-weight fingerprinting approaches that aim to differentiate servers without making any assumptions about their inner working.
With this work we propose DissecTLS, an active TLS scanner that is both light-weight enough to be used for Internet measurements and able to reconstruct the configuration and capabilities of the TLS stack.
This was achieved by modeling the parameters of the TLS stack and derive an active scan that dynamically creates scanning probes based on the model and the previous responses from the server.
We provide a comparison of five active TLS scanning and fingerprinting approaches in a local testbed and on toplist targets. 
We conducted a measurement study over nine weeks to fingerprint C&C servers and analyzed popular and deprecated TLS parameter usage.
Similar to related work, the fingerprinting achieved a maximum precision of 99% for a conservative detection threshold of 100%; and at the same time, we improved the recall by a factor of 2.8.</p>
  </div>
</div><br>

**Authors:**
{% for author in site.data.authors.list %}<a style="border-bottom: none" href="https://orcid.org/{{author.orcid}}">
<img src="assets/ORCIDiD_icon16x16.png" style="width: 1em; margin-inline-start: 0.5em;" alt="ORCID iD icon"/></a>
[{{author.name}}](https://orcid.org/{{author.orcid}}){% if author.name contains "Sgan" %}{% else %}, {% endif %}
{% endfor %}

## Data

We provide an extended [ranking]({{ site.baseurl }}{% link pages/ranking.md %}) of TLS patameters as introduces in the paper.

## Referencing our Work

If you are referring to our work or use the collected data in your publication, please refer to it with the following reference [[bib]]({{ site.baseurl }}{% link assets/dissectls.bib %})::

```bib
{% raw %}@inproceedings{10.1007/978-3-031-28486-1_6,
  author = {Sosnowski, Markus and Zirngibl, Johannes and Sattler, Patrick and Carle, Georg},
  editor = {Brunstrom, Anna and Flores, Marcel and Fiore, Marco},
  title = {{DissecTLS: A Scalable Active Scanner for TLS Server Configurations, Capabilities, and TLS Fingerprinting}},
  booktitle = {Proc. Passive and Active Measurement (PAM)},
  year = {2023},
  publisher = {Springer Nature Switzerland},
  pages = {110--126},
  isbn = {978-3-031-28486-1},
  doi = {10.1007/978-3-031-28486-1_6},
}{% endraw %}
```


## Experiment Setup and Scanner Software

For the paper we have used the open-source [TUM Goscanner](https://github.com/tumi8/goscanner) for our Internet measurements. We extended it with the DissecTLS functionality and [JARM](https://github.com/salesforce/jarm) fingerprinting.
The scammer is open-sourced in the official [repository](https://github.com/tumi8/goscanner).

The experiment setup used to compare the TLS scanner and fingerprinting tools can be found under: [experiment-setup](https://github.com/dissectls/experiment-setup)


## Reproducibility

Our data are published at [TUM University Library](https://mediatum.ub.tum.de/1695491) to enable reproducible analyses and to guarantee long-term availability.<br>
Dataset DOI: [10.14459/2023mp1695491](https://doi.org/10.14459/2023mp1695491)

Details of the data are described [here](/data/).
