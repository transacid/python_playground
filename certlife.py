#!/usr/bin/env python3
import ssl
import OpenSSL
import datetime
import socket
import smtplib
from termcolor import colored


def get_smtp_tls_certificate(hostname, port):
    connection = smtplib.SMTP(hostname, port)
    connection.starttls()
    cert = connection.sock.getpeercert(binary_form=True)
    return cert


def get_ssl_certificate(hostname, port):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(binary_form=True)
    return cert


def get_xmpp_tls_certificate(hostname, port):
    xmpp_open_stream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'" \
                       " xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{}'>"
    xmpp_starttls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

    sock = socket.create_connection((hostname, port))
    sock.send(xmpp_open_stream.format(hostname).encode())
    sock.recv(2048)
    sock.send(xmpp_starttls.encode())
    sock.recv(2048)
    with ssl.wrap_socket(sock) as ssock:
        cert = ssock.getpeercert(binary_form=True)
    return cert


def openssl(cert):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    raw_date = x509.get_notAfter().decode("ascii")
    date = datetime.datetime.strptime(raw_date, "%Y%m%d%H%M%SZ")
    formated_date = datetime.datetime.strftime(date, "%d. %B %Y, %H:%M")
    return formated_date


def output(func, hostname, port):
    print("The Certificate for {} on port {} expires on\n\t{}.\n".format(colored(hostname, "green"),
                                                                         colored(port, "green"),
                                                                         colored(openssl(func(hostname, port)), "red")))


output(get_ssl_certificate, "transacid.de", 443)
output(get_ssl_certificate, "transacid.de", 993)
output(get_ssl_certificate, "transacid.de", 6697)
output(get_smtp_tls_certificate, "transacid.de", 25)
output(get_ssl_certificate, "0x7fffffff.net", 443)
output(get_xmpp_tls_certificate, "0x7fffffff.net", 5222)
