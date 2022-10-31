from docker import TLSConfig


def create_nginx_config(config: TLSConfig):
    ssl_certificate = "/etc/certificates/cert.pem"
    ssl_certificate_key = "/etc/certificates/key.pem"

    ssl_protocols = ' '.join(config.ssl_protocols)
    h2 = 'http2' if config.http2 else ''
    ssl_prefer_server_ciphers = 'on' if config.ssl_prefer_server_ciphers else 'off'
    ssl_session_tickets = 'on' if config.ssl_session_tickets else 'off'
    ssl_stapling = 'on' if config.ssl_stapling else 'off'
    ssl_ciphers = ':'.join(config.ssl_ciphers)

    return f"""
server {{
    listen 443 ssl {h2};
    listen [::]:443 ssl {h2};

    ssl_certificate {ssl_certificate};
    ssl_certificate_key {ssl_certificate_key};
    
    # General TLS configuration
    ssl_protocols {ssl_protocols};
    ssl_ciphers  {ssl_ciphers};
    ssl_prefer_server_ciphers {ssl_prefer_server_ciphers};
    
    ssl_session_tickets {ssl_session_tickets};
    
    # OCSP stapling
    ssl_stapling {ssl_stapling};
}} 
    """
