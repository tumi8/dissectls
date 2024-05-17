---
layout: page
title: TLS Parameter Ranking
permalink: /ranking/
order: 3
toc: TLS Parameter Ranking
description: "The following tables show the complete TLS parameter popularity ranking from the paper together with the percentage of targets (IP address + domain name) supporting the specific value."
tables:
  - cipher_popularity_ranking
  - supported_groups_popularity_ranking
  - alpn_popularity_ranking
---


<style type="text/css">
    .tableContainer {
        height: 350px;
        overflow: scroll;
        margin: 20px;
    }

    .table {
        position: sticky;
        top: 0;
        width: 100%;
    }

</style>

Note that some lower ranks were observed very rarely, sometimes just once.

{% for type in page.tables %}

### {% cycle "Cipher suites", "Supported groups", "ALPNs" %} Popularity Ranking <font size=2>(<a href="https://raw.githubusercontent.com/pam2023-51-dissectls/pam2023-51-dissectls.github.io/main/_data/{{ type }}.csv">raw</a>)</font>

<div class="tableContainer">
    <table class="table">
        {% for row in site.data[type] %}
            {% if forloop.first %}
            <tr>
            {% for pair in row %}
                <th>{{ pair[0] }}</th>
            {% endfor %}
            </tr>
            {% endif %}

            {% tablerow pair in row %}
            {{ pair[1] }}
            {% endtablerow %}
        {% endfor %}
    </table>
</div>

{% endfor %}





