from functools import reduce

from docker import TLSConfig


def create_apache_config(config: TLSConfig):
    ssl_certificate = "/etc/certificates/cert.pem"
    ssl_certificate_key = "/etc/certificates/key.pem"

    ssl_protocols = ' '.join(map(lambda x: f'+{x}', config.ssl_protocols))
    h2 = 'h2' if config.http2 else ''
    ssl_prefer_server_ciphers = 'on' if config.ssl_prefer_server_ciphers else 'off'
    ssl_session_tickets = 'on' if config.ssl_session_tickets else 'off'
    ssl_stapling = 'on' if config.ssl_stapling else 'off'
    ssl_stapling_cache = 'SSLStaplingCache "shmcb:/usr/local/apache2/logs/ssl_stapling(32768)"\nSSLStaplingStandardCacheTimeout 3600' if config.ssl_stapling else ''

    ssl_ciphers = reduce(lambda x, y: f'{x}:{y}', config.ssl_ciphers)

    return f"""    
Listen 443

<VirtualHost *:443>
    SSLEngine on

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt >> /path/to/signed_cert_and_intermediate_certs_and_dhparams
    SSLCertificateFile     {ssl_certificate}
    SSLCertificateKeyFile   {ssl_certificate_key}

    # enable HTTP/2, if available
    Protocols {h2} http/1.1
    
    ServerName example.com:443
</VirtualHost>

# intermediate configuration
SSLProtocol             -all {ssl_protocols}
SSLCipherSuite          {ssl_ciphers}
SSLHonorCipherOrder      {ssl_prefer_server_ciphers}
SSLSessionTickets       {ssl_session_tickets}

SSLUseStapling {ssl_stapling}
{ssl_stapling_cache}

SSLSessionCache        "shmcb:/usr/local/apache2/logs/ssl_scache(512000)"
SSLSessionCacheTimeout  300
    """
