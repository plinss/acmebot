.. _bindtool: https://github.com/plinss/bindtool

*******
acmebot
*******

ACME protocol automatic certitificate manager.

This tool acquires and maintains certificates from a certificate authority using the ACME protocol, similar to EFF's Certbot.
While developed and tested using Let's Encrypt, the tool should work with any certificate authority using the ACME protocol.


Features
========

This tool is not intended as a replacement for Certbot and does not attempt to replicate all of Certbot's functionality,
notably it does not modify configuration files of other services,
or provide a server to perform stand-alone domain validation.
It does however, do a few things that Certbot does not,
simplifying certificate management in more advanced environments.
In addition to automatically issuing and maintaining certificates,
the tool can also maintain associated HPKP headers and TLSA (DANE) records.


Master/Follower Mode
--------------------

This tool separates the authorization (domain validation) and certificate issuance processes allowing one machine to maintain authorizations (the master),
while another machine issues certificates (the follower).
This is useful for situations where an isolated server is providing a service, such as XMPP,
behind a firewall and does not have the ability to perform authorizations over http or configure DNS records,
but still needs to obtain and periodically renew one or more certificates.


Sharing of Private Keys Between Certificates
--------------------------------------------

This tool allows multiple certificates to be defined using the same public/private key pair.

When deploying Hypertext Puplic Key Pinning (HPKP), you can optionally use the same pins to secure subdomains.
This increases security of the site because a visitor to a root domain will have previously obtained pins for subdomains,
reducing the possibility of a man-in-the-middle attacker installing a false pin on first visit.

This practice obviously requires the use of the same public/private key pair for the domain and all subdomains.
However, it may not be desirable to use the same certificate for all subdomains, for example,
exposing the full list of subdomains in the alternative names of the root domain's certificate,
or reissuing the root domain's certificate every time a subdomain is added or removed.


Hypertext Public Key Pin (HPKP) Support
---------------------------------------

This tool automatically generates and maintains HPKP header information suitable to be directly included in server configuraton files.
Support for Apache and Nginx are provided by default, other servers may be added by the user.


Automatic Management of Backup Private Keys
-------------------------------------------

Using HPKP requires a second public key to provide a backup when private keys are changed.
This tool automatically generates backup keys and switches to the pre-generated backup key when rolling over private keys.
Rolling over private keys can be done automatically and is scheduled independently of certificate expiration.
Private key rollover is prevented in cases where insufficient time has passed to distribute backup HPKP pins.


Parallel RSA and ECDSA Certificates
-----------------------------------

This tool can generate both RSA and ECDSA certificates.
By default it will generate and maintain both types of certificates in parallel.


Certificate Transparency / Signed Certificate Timestamp Support
---------------------------------------------------------------

This tool can automatically register your certificates with multiple certificate transparency logs and retrieve Signed Certificate Timestamps (SCTs) for each.
The retrieved SCTs are suitable to be deilvered via a TLS extension,
SCT TLS extension modules are available for `Apache <https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html>`_ and `Nginx <https://github.com/grahamedgecombe/nginx-ct>`_.


OCSP Response File Support
--------------------------

This tool automatically obtains and maintains OCSP response files for each configured certificate.
These files may be used to serve stapled OCSP responses from your server without relying on the server's OCSP stapling mechanisms.
Some servers, such as Nginx, obtain stapled OCSP responses lazily and cache the response in memory.
When using the OCSP Must-Staple extension this can result in your server being unreachable until the OCSP response is refreshed,
during OCSP responder outages, this can be a significant interval.
Using OCSP responses from disk will alleviate this issue.
Only OCSP responses with a "good" status will be stored.


Encrypted Private Keys
----------------------

Primary and backup private keys can optionally be encrypted using a passphrase and cipher of your choice.


Mixed Use of DNS and HTTP Authorization
---------------------------------------

By default this tool performs dns-01 authorizartions for domain validation.
It is possible to configure overrides for specific domains names to use http-01 authorization instead.
This is useful for situations where a domain outside your immediate control has provided an alias to your web site.


Automatic Local or Remote DNS Updates
-------------------------------------

This tool can automatically add and remove DNS records for dns-01 authorizations as well as TLSA records.
Updates to a local server can be made via an external zone file processor, such as `bindtool`_,
or to a remote DNS server via RFC 2136 dynamic DNS updates using ``nsupdate``.
The choice between local and remote DNS updates can be made on a zone by zone basis.


Configurable Output File Names
------------------------------

Server administrators often develop their own file naming conventions or need to match naming conventions of other tools.
The names and output directories of all certificate, key, and related files are fully configurable.
The defaults are intended for standard Debian installations.


Configurable Deployment Hooks
-----------------------------

Each operation that writes key, certificate, or related files have optional hooks that can call user-specified programs to
assist in deploying resources to remote servers or coordinating with other tooling.


Certificate Installation Verification
-------------------------------------

This tool can automatically connect to configured servers and verify that the generated certificates are properly served via TLS.
Additional checks are made for OSCP staples and optionally HPKP headers can be verified as well.


ACME Protocol V1 and V2 Support
-------------------------------

This tool supports services running both ACME V1 and ACME V2 APIs.
Wildcard certrificates may be issued when using the V2 API.


Installation
============

Requires Python 3.7+ and the OpenSSL support.

On Debian Stretch and later::

    sudo apt-get install python3-pip libssl-dev libffi-dev
    sudo pip3 install acmebot

You may want to create a virtual environment and install acmebot there.
Copy either the ``acmebot.example.json`` file or the ``acmebot.example.yaml`` file to ``acmebot.json`` (or ``acmebot.yaml``) and edit the configuration options.
The configuration file can be placed in the current directory that the tool is run from,
the /etc/acmebot directory,
or the same directory that the acmebot tool is installed in.

By default, debug level output will be written to a log file.
A configuration file for logrotate is provided in the logrotate.d directory,
you may want to copy, or create a link to this file in /etc/logrotate.d.

Note that when using dns-01 authorizations via a local DNS server,
this tool needs to be able to add, remove, and update DNS records.
This can be achieved by installing it on your master DNS server and using `bindtool`_ to manage the zone file,
or you can use a custom shell script to update the DNS records.

When using dns-01 authorizations via a remote server,
an update key allowing the creation and deletion of TXT and optionally TLSA record types is required.

Optional: some services require a full certificate chain including the root (OSCP stapling on Nginx, for example).
In order to generate these files,
place a copy of the root certificates from your certificate authority of choice in the same directory as the configuration file with the file names ``root_cert.rsa.pem`` and ``root_cert.ecdsa.pem`` for RSA and ECDSA certificate roots respectively.
Note that the root certificates are the those used to sign RSA and ECDSA client certificates,
and may not necessarily be of the same type,
e.g. Let's Encrypt currently signs ECDSA certificates with an RSA root.
If your certificate authority uses RSA certificate to sign ECDSA certificates types, place that RSA root certificate in ``root_cert.ecdsa.pem``.
The root certificate for Let's Encrypt can be obtained `here <https://letsencrypt.org/certificates/>`_.


Upgrade
=======

Starting with version 2.0.0 of this tool, the Let's Encrypt ACME V2 API is used by default.
When upgrading to version 2.0.0+, or otherwise changing API endpoints,
the client key is regenerated and a new registration is performed.
If running in master/follower mode, be sure to run the tool on the master first,
then copy the new client key and registration files to the followers before running on the followers.
Existing private keys and certificates may continue to be used.


Quick Start
===========


Basic Configuration
-------------------

While the example configuration file may appear complicated,
it is meant to show all possible configuration options and their defaults,
rather than demonstrate a basic simple configuration.

The only items that must be present in the configuration file to create and maintain a certificate are your account email address,
and the file name for the certificate.
By default, the common name of the certificate will be the same as the certificate file name.

For example::

    {
        "account": {
            "email": "admin@example.com"
        },
        "certificates": {
            "example.com": {
                "alt_names": {
                    "example.com": ["@", "www"]
                }
            }
        }
    }

will create a certificate named ``example.com``,
with the common name of ``example.com``,
and the subject alternative names of ``example.com`` and ``www.example.com``.

As many certificates as desired may be configured.
The number of alternative names is limited by the certificate authority (Let's Encrypt currently allows 100).
Alternative names are specified on a DNS zone basis,
multiple zones may be specified per certificate.
The host name ``"@"`` is used for the name of the zone itself.


Authorization Setup
-------------------

By default, the tool will attempt dns-01 domain authorizations for every alternative name specified,
using local DNS updates.
See the later sections on configuring `local <#configuring-local-dns-updates>`_ or `remote <#configuring-remote-dns-updates>`_ DNS updates.

To use http-01 authorizations instead,
configure the ``http_challenges`` section of the configuration file specifying a challenge directory for each fully qualified host name.

For example::

    {
        ...
        "http_challenges": {
            "example.com": "/var/www/htdocs/.well-known/acme-challenge",
            "www.example.com": "/var/www/htdocs/.well-known/acme-challenge"
        }
    }

See the `HTTP Challenges <#http-challenges>`_ section for more information.


First Run
---------

Once the configuration file is in place,
simply execute the tool.
For the first run you may wish to select detailed output to see exactly what the tool is doing::

    acmebot --detail

If all goes well,
the tool will generate a public/private key pair used for client authentication to the certificate authority,
register an account with the certificate authority,
prompt to accept the certificate authority's terms of service,
obtain authorizations for each configured domain name,
generate primary private keys as needed for the configured certificates,
issue certificates,
generate backup private keys,
generate custom Diffie-Hellman parameters,
retrieve Signed Certificate Timestamps from certificate transparency logs,
retrieve an OCSP response from the certificate authority,
and install the certificates and private keys into /etc/ssl/certs and /etc/ssl/private.

If desired, you can test the tool using Let's Encrypt's staging server.
To do this, specify the staging server's directory URL in the ``acme_directory_url`` setting.
See `Staging Environment <https://letsencrypt.org/docs/staging-environment/>`_ for details.
When switching from the staging to production servers,
you should delete the client key and registration files (/var/local/acmebot/\*.json) to ensure a fresh registration in the production environment.


File Location
=============

After a successful certificate issuance,
up to twenty one files will be created per certificate.

The locations for these files can be controlled via the ``directories`` section of the configuration file.
The default locations are used here for brevity.

Output files will be written as a single transaction,
either all files will be written,
or no files will be written.
This is designed to prevent a mismatch between certificates and private keys should an error happen during file creation.


Private Keys
------------

Two private key files will be created in /etc/ssl/private for each key type.
The primary: ``<private-key-name>.<key-type>.key``; and a backup key: ``<private-key-name>_backup.<key-type>.key``.

The private key files will be written in PEM format and will be readable by owner and group.


Certificate Files
-----------------

Two certificate files will be created for each key type,
one in /etc/ssl/certs, named ``<certificate-name>.<key-type>.pem``,
containing the certificate,
followed by any intermediate certificates sent by the certificate authority,
followed by custom Diffie-Hellman and elliptic curve paramaters;
the second file will be created in /etc/ssl/private, named ``<certificate-name>_full.<key-type>.key``,
and will contain the private key,
followed by the certificate,
followed by any intermediate certificates sent by the certificate authority,
followed by custom Diffie-Hellman and elliptic curve paramaters.

The ``<certificate-name>_full.<key-type>.key`` file is useful for services that require both the private key and certificate to be in the same file,
such as ZNC.


Intermediate Certificate Chain File
-----------------------------------

If the certificate authority uses intermediate certificates to sign your certificates,
a file will be created in /etc/ssl/certs, named ``<certificate-name>_chain.<key-type>.pem`` for each key type,
containing the intermediate certificates sent by the certificate authority.

This file will not be created if the ``chain`` directory is set to ``null``.

Note that the certificate authority may use a different type of certificate as intermediates,
e.g. an ECDSA client certificate may be signed by an RSA intermediate,
and therefore the intermediate certificate key type may not match the file name (or certificate type).


Full Chain Certificate File
---------------------------

If the ``root_cert.<key-type>.pem`` file is present (see `Installation <#installation>`_),
then an additional certificate file will be generated in /etc/ssl/certs,
named ``<certificate-name>+root.<key-type>.pem`` for each key type.
This file will contain the certificate,
followed by any intermediate certificates sent by the certificate authority,
followed by the root certificate,
followed by custom Diffie-Hellman and elliptic curve paramaters.

If the ``root_cert.<key-type>.pem`` file is not found in the same directory as the configuration file,
this certificate file will not be created.

This file is useful for configuring OSCP stapling on Nginx servers.


Diffie-Hellman Parameter File
-----------------------------

If custom Diffie-Hellman parameters or a custom elliptical curve are configured,
a file will be created in /etc/ssl/params, named ``<certificate-name>_param.pem``,
containing the Diffie-Hellman parameters and elliptical curve paramaters.

This file will not be created if the ``param`` directory is set to ``null``.


Hypertext Public Key Pin (HPKP) Files
-------------------------------------

Two additional files will be created in /etc/ssl/hpkp, named ``<private-key-name>.apache`` and ``<private-key-name>.nginx``.
These files contain HTTP header directives setting HPKP for both the primary and backup private keys for each key type.

Each file is suitable to be included in the server configuration for either Apache or Nginx respectively.

Thess files will not be created if the ``hpkp`` directory is set to ``null``.


Signed Certificate Timestamp (SCT) Files
----------------------------------------

One additional file will be created for each key type and configured certificate transparency log in ``/etc/ssl/scts/<certificate-name>/<key-type>/<log-name>.sct``.
These files contain SCT information in binary form suitable to be included in a TLS extension.
By default, SCTs will be retrieved from the Google Icarus and Google Pilot certificate transparency logs.
The Google Test Tube certificate transparency log can be used with the Let's Encrypt staging environment for testing.


OCSP Response Files
-------------------
One OCSP response file will be created for each key type,
in /etc/ssl/ocsp, named ``<certificate-name>.<key_type>.ocsp``.
These files contain OCSP responses in binary form suitable to be used as stapled OCSP responses.


Archive Directory
-----------------

Whenever exsiting files are replaced by subsequent runs of the tool,
for example during certificate renewal or private key rollover,
all existing files are preserved in the archive directory, /etc/ssl/archive.

Within the archive directory,
a directory will be created with the name of the private key,
containing a datestamped directory with the time of the file transaction (YYYY_MM_DD_HHMMSS).
All existing files will be moved into the datestamped directory should they need to be recovered.


Server Configuration
====================

Because certificate files will be periodically replaced as certificates need to be renewed,
it is best to have your server configurations simply refer to the certificate and key files in the locations they are created.
This will prevent server configurations from having to be updated as certificate files are replaced.

If the server requires the certificate or key file to be in a particular location or have a different file name,
it is best to simply create a soft link to the certificate or key file rather than rename or copy the files.

Another good practice it to isolate the configuration for each certificate into a snippet file,
for example using Apache,
create the file /etc/apache2/snippets/ssl/example.com containing::

    SSLCertificateFile    /etc/ssl/certs/example.com.rsa.pem
    SSLCertificateKeyFile /etc/ssl/private/example.com.rsa.key
    CTStaticSCTs          /etc/ssl/certs/example.com.rsa.pem /etc/ssl/scts/example.com/rsa        # requires mod_ssl_ct to be installed

    SSLCertificateFile    /etc/ssl/certs/example.com.ecdsa.pem
    SSLCertificateKeyFile /etc/ssl/private/example.com.ecdsa.key
    CTStaticSCTs          /etc/ssl/certs/example.com.ecdsa.pem /etc/ssl/scts/example.com/ecdsa    # requires mod_ssl_ct to be installed

    Header always set Strict-Transport-Security "max-age=63072000"
    Include /etc/ssl/hpkp/example.com.apache

and then in each host configuration using that certificate, simply add::

    Include snippets/ssl/example.com

For Nginx the /etc/nginx/snippets/ssl/example.com file would contain::

    ssl_ct on;                                                          # requires nginx-ct module to be installed

    ssl_certificate         /etc/ssl/certs/example.com.rsa.pem;
    ssl_certificate_key     /etc/ssl/private/example.com.rsa.key;
    ssl_ct_static_scts      /etc/ssl/scts/example.com/rsa;              # requires nginx-ct module to be installed
    ssl_stapling_file       /etc/ssl/ocsp/example.com.rsa.ocsp;

    ssl_certificate         /etc/ssl/certs/example.com.ecdsa.pem;       # requires nginx 1.11.0+ to use multiple certificates
    ssl_certificate_key     /etc/ssl/private/example.com.ecdsa.key;
    ssl_ct_static_scts      /etc/ssl/scts/example.com/ecdsa;            # requires nginx-ct module to be installed
    ssl_stapling_file       /etc/ssl/ocsp/example.com.ecdsa.ocsp;       # requires nginx 1.13.3+ to use with multiple certificates

    ssl_trusted_certificate /etc/ssl/certs/example.com+root.rsa.pem;    # not required if using ssl_stapling_file

    ssl_dhparam             /etc/ssl/params/example.com_param.pem;
    ssl_ecdh_curve secp384r1;

    add_header Strict-Transport-Security "max-age=63072000" always;
    include /etc/ssl/hpkp/example.com.nginx;

and can be used via::

    include snippets/ssl/example.com;


Configuration
=============

The configuration file ``acmebot.json`` or ``acmebot.yaml`` may be placed in the current working directory,
in /etc/acmebot,
or in the same directory as the acmebot tool is installed in.
A different configuration file name may be specified on the command line.
If the specified file name is not an absolute path,
it will be searched for in the same locations,
e.g. ``acmebot --config config.json`` will load ``./config.json``, ``/etc/acmebot/config.json``, or ``<install-dir>/config.json``.
If the file extension is omitted, the tool will search for a file with the extensions: ``.json``, ``.yaml``, and ``.yml`` in each location.
If the speficied file is an absolute path,
only that location will be searched.

Additional configuration files may be placed in a subdirectory named ``conf.d`` in the same directory as the configuration file.
All files with the extensions: ``.json``, ``.yaml``, or ``.yml`` in that subdirectory will be loaded and merged into the configuration,
overriding any settings in the main configuration file.
For example,
the configurtaion for each certificate may be placed in a separate file,
while the common settings remain in the main configuration file.

The configuration file must adhere to standard JSON or YAML formats.
The examples given in this document are in JSON format, however, the equivalent structures may be expressed in YAML.

The files ``acmebot.example.json`` and ``acmebot.example.yaml`` provide a template of all configuration options and their default values.
Entries inside angle brackets ``"<example>"`` must be replaced (without the angle brackets),
all other values may be removed unless you want to override the default values.


Account
-------

Enter the email address you wish to associate with your account on the certificate authority.
This email address may be useful in recovering your account should you lose access to your client key.

Example::

    {
        "account": {
            "email": "admin@example.com"
        },
        ...
    }


Settings
--------

Various settings for the tool.
All of these need only be present when the desired value is different from the default.

* ``follower_mode`` specifies if the tool should run in master or follower mode.
  The defalt value is ``false`` (master mode).
  The master will obtain authorizations and issue certificates,
  a follower will not attempt to obtain authorizations but can issue certificates.
* ``log_level`` specifies the amount of information written into the log file.
  Possible values are ``null``, ``"normal"``, ``"verbose"``, ``"debug"``, and ``"detail"``.
  ``"verbose"``, ``"debug"``, and ``"detail"`` settings correlate to the ``--verbose``, ``--debug`` and ``--detail`` command-line options.
* ``color_output`` specifies if the output should be colorized.
  Colorized output will be suppressed on non-tty devices.
  This option may be overridden via command line options.
  The default value is ``true``.
* ``key_types`` specifies the types of private keys to generate by default.
  The default value is ``['rsa', 'ecdsa']``.
* ``key_size`` specifies the size (in bits) for RSA private keys.
  The default value is ``4096``.
  RSA certificates can be turned off by setting this value to ``0`` or ``null``.
* ``key_curve`` specifies the curve to use for ECDSA private keys.
  The default value is ``"secp384r1"``.
  Available curves are ``"secp256r1"``, ``"secp384r1"``, and ``"secp521r1"``.
  ECDSA certificates can be turned off by setting this value to ``null``.
* ``key_cipher`` specifies the cipher algorithm used to encrypt private keys.
  The default value is ``"blowfish"``.
  Available ciphers are those accepted by your version of OpenSSL's EVP_get_cipherbyname().
* ``key_passphrase`` specifies the passphrase used to encrypt private keys.
  The default value is ``null``.
  A value of ``null`` or ``false`` will result in private keys being written unencrypted.
  A value of ``true`` will cause the password to be read from the command line, the environment, a prompt, or stdin.
  A string value will be used as the passphrase without further input.
* ``key_provided`` specifies that the private keys are provided from an external source and the tool should not modify them.
  The default value is ``false``.
* ``dhparam_size`` specifies the size (in bits) for custom Diffie-Hellman parameters.
  The default value is ``2048``.
  Custom Diffie-Hellman parameters can be turned off by setting this value to ``0`` or ``null``.
  This value should be at least be equal to half the ``key_size``.
* ``ecparam_curve`` speficies the curve or list of curves to use for ECDHE negotiation.
  This value may be a string or a list of strings.
  The default value is ``["secp521r1", "secp384r1", "secp256k1"]``.
  Custom EC parameters can be turned off by setting this value to ``null``.
  You can run ``openssl ecparam -list_curves`` to find a list of available curves.
* ``file_user`` specifies the name of the user that will own certificate and private key files.
  The default value is ``"root"``.
  Note that this tool must run as root, or another user that has rights to set the file ownership to this user.
* ``file_group`` speficies the name of the group that will own certificate and private key files.
  The default value is ``"ssl-cert"``.
  Note that this tool must run as root, or another user that has rights to set the file ownership to this group.
* ``log_user`` specifies the name of the user that will own log files.
  The default value is ``"root"``.
  Note that this tool must run as root, or another user that has rights to set the file ownership to this user.
* ``log_group`` speficies the name of the group that will own log files.
  The default value is ``"adm"``.
  Note that this tool must run as root, or another user that has rights to set the file ownership to this group.
* ``warning_exit_code`` specifies if warnings will produce a non-zero exit code.
  The default value is ``false``.
* ``hpkp_days`` specifies the number of days that HPKP pins should be cached for.
  The default value is ``60``.
  HPKP pin files can be turned off by setting this value to ``0`` or ``null``.
* ``pin_subdomains`` specifies whether the ``includeSubdomains`` directive should be included in the HPKP headers.
  The default value is ``true``.
* ``hpkp_report_uri`` specifies the uri to report HPKP failures to.
  The default value is ``null``.
  If not null, the ``report-uri`` directive will be included in the HPKP headers.
* ``ocsp_must_staple`` specifies if the OCSP Must-Staple extension is added to certificates.
  The default value is ``false``.
* ``ocsp_responder_urls`` specifies the list of OCSP responders to use if a certificate doesn't provide them.
  The default value is ``["http://ocsp.int-x3.letsencrypt.org"]``.
* ``ct_submit_logs`` specifies the list of certificate transparency logs to submit certificates to.
  The default value is ``["google_icarus", "google_pilot"]``.
  The value ``["google_testtube"]`` can be used with the Let's Encrypt staging environment for testing.
* ``renewal_days`` specifies the number of days before expiration when the tool will attempt to renew a certificate.
  The default value is ``30``.
* ``expiration_days`` specifies the number of days that private keys should be used for.
  The dafault value is ``730`` (two years).
  When the backup key reaches this age,
  the tool will notify the user that a key rollover should be performed,
  or automatically rollover the private key if ``auto_rollover`` is set to ``true``.
  Automatic rollover and expiration notices can be disabled by setting this to ``0`` or ``null``.
* ``auto_rollover`` specifies if the tool should automatically rollover private keys that have expired.
  The default value is ``false``.
  Note that when running in a master/follower configuration and sharing private keys between the master and follower,
  key rollovers must be performed on the master and manually transferred to the follower,
  therefore automatic rollovers should not be used unless running stand-alone.
* ``max_dns_lookup_attempts`` specifies the number of times to check for deployed DNS records before attempting authorizations.
  The default value is ``60``.
* ``dns_lookup_delay`` specifies the number of seconds to wait between DNS lookups.
  The default value is ``10``.
* ``max_domains_per_order`` specifies the maximum number of domains allowed per authorization order.
  The default value is ``100``, which is the limit set by Let's Encrypt.
* ``max_authorization_attempts`` specifies the number of times to check for completed authorizations.
  The default value is ``30``.
* ``authorization_delay`` specifies the number of seconds to wait between authorization checks.
  The default value is ``10``.
* ``cert_poll_time`` specifies the number of seconds to wait for a certificate to be issued.
  The default value is ``30``.
* ``max_ocsp_verify_attempts`` specifies the number of times to check for OCSP staples during verification.
  Retries will only happen when the certificate has the OCSP Must-Staple extension.
  The default value is ``10``.
* ``ocsp_verify_retry_delay`` specifies the number of seconds to wait between OCSP staple verification attempts.
  The default value is ``5``.
* ``min_run_delay`` specifies the minimum number of seconds to wait if the ``--randomwait`` command line option is present.
  The default value is ``300``.
* ``max_run_delay`` specifies the maximum number of seconds to wait if the ``--randomwait`` command line option is present.
  The default value is ``3600``.
* ``acme_directory_url`` specifies the primary URL for the ACME service.
  The default value is ``"https://acme-v02.api.letsencrypt.org/directory"``, the Let's Encrypt production API.
  You can substitute the URL for Let's Encrypt's staging environment or another certificate authority.
* ``acme_directory_verify_ssl`` specifies whether or not to verify the certificate of the ACME service.
  The default value is ``True``.
  Setting this to ``False`` is not recommneded, but may be necessary in environments using a private ACME server.
* ``reload_zone_command`` specifies the command to execute to reload local DNS zone information.
  When using `bindtool`_ the ``"reload-zone.sh"`` script provides this service.
  If not using local DNS updates, you may set this to ``null`` to avoid warnings.
* ``nsupdate_command`` specifies the command to perform DNS updates.
  The default value is ``"/usr/bin/nsupdate"``.
* ``verify`` specifies the default ports to perform installation verification on.
  The default value is ``null``.
* ``services`` specifies the default services to associate with certificates.
  The default value is ``null``.

Example::

    {
        ...
        "settings": {
            "follower_mode": false,
            "log_level": "debug",
            "key_size": 4096,
            "key_curve": "secp384r1",
            "key_cipher": "blowfish",
            "key_passphrase": null,
            "key_provided": false,
            "dhparam_size": 2048,
            "ecparam_curve": ["secp521r1", "secp384r1", "secp256k1"],
            "file_user": "root",
            "file_group": "ssl-cert",
            "hpkp_days": 60,
            "pin_subdomains": true,
            "hpkp_report_uri": null,
            "ocsp_must_staple": false,
            "ocsp_responder_urls": ["http://ocsp.int-x3.letsencrypt.org"],
            "ct_submit_logs": ["google_icarus", "google_pilot"],
            "renewal_days": 30,
            "expiration_days": 730,
            "auto_rollover": false,
            "max_dns_lookup_attempts": 60,
            "dns_lookup_delay": 10,
            "max_authorization_attempts": 30,
            "authorization_delay": 10,
            "min_run_delay": 300,
            "max_run_delay": 3600,
            "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
            "reload_zone_command": "/etc/bind/reload-zone.sh",
            "nsupdate_command": "/usr/bin/nsupdate",
            "verify": [443]
        },
        ...
    }


Directories
-----------

Directories used to store the input and output files of the tool.
Relative paths will be considered relative to the directory of configuration file.
All of these need only be present when the desired value is different from the default.

* ``pid`` specifies the directory to store a process ID file.
  The default value is ``"/var/run"``.
* ``log`` specifies the directory to store the log file.
  The default value is ``"/var/log/acmebot"``.
* ``resource`` specifies the directory to store the client key and registration files for the ACME account.
  The default value is ``"/var/local/acmebot"``.
* ``private_key`` specifies the directory to store primary private key files.
  The default value is ``"/etc/ssl/private"``.
* ``backup_key`` specifies the directory to store backup private key files.
  The default value is ``"/etc/ssl/private"``.
* ``previous_key`` specifies the directory to store previously used private key files after key rollover.
  The default value is ``null``.
* ``full_key`` specifies the directory to store primary private key files that include the certificate chain.
  The default value is ``"/etc/ssl/private"``.
  Full key files may be omitted by setting this to ``null``.
* ``certificate`` specifies the directory to store certificate files.
  The default value is ``"/etc/ssl/certs"``.
* ``full_certificate`` specifies the directory to store full chain certificate files that include the root certificate.
  The default value is ``"/etc/ssl/certs"``.
  Full certificate files may be omitted by setting this to ``null``.
* ``chain`` specifies the directory to store certificate intermediate chain files.
  The default value is ``"/etc/ssl/certs"``.
  Chain files may be omitted by setting this to ``null``.
* ``param`` specifies the directory to store Diffie-Hellman parameter files.
  The default value is ``"/etc/ssl/params"``.
  Paramater files may be omitted by setting this to ``null``.
* ``challenge`` specifies the directory to store ACME dns-01 challenge files.
  The default value is ``"/etc/ssl/challenge"``.
* ``http_challenge`` specifies the directory to store ACME http-01 challenge files.
  The default value is ``null``.
* ``hpkp`` specifies the directory to store HPKP header files.
  The default value is ``"/etc/ssl/hpkp"``.
  HPKP header files may be turned off by setting this to ``null``.
* ``sct`` specifies the directory to store Signed Certificate Timestamp files.
  The default value is ``"/etc/ssl/scts/<certificate-name>/<key-type>"``.
  SCT files may be turned off by setting this to ``null``.
* ``ocsp`` specifies the directory to store OCSP response files.
  The default value is ``"/etc/ssl/ocsp"``.
  OCSP response files may be turned off by setting this to ``null``.
* ``update_key`` specifies the directory to search for DNS update key files.
  The default value is ``"/etc/ssl/update_keys"``.
* ``archive`` specifies the directory to store older versions of files that are replaced by this tool.
  The default value is ``"/etc/ssl/archive"``.
* ``temp`` specifies the directory to write temporary files to.
  A value of ``null`` results in using the system defined temp directory.
  The temp directory must be on the same file system as the output file directories.
  The default value is ``null``.

Example::

    {
        ...
        "directories": {
            "pid": "/var/run",
            "log": "/var/log/acmebot",
            "resource": "/var/local/acmebot",
            "private_key": "/etc/ssl/private",
            "backup_key": "/etc/ssl/private",
            "full_key": "/etc/ssl/private",
            "certificate": "/etc/ssl/certs",
            "full_certificate": "/etc/ssl/certs",
            "chain": "/etc/ssl/certs",
            "param": "/etc/ssl/params",
            "challenge": "/etc/ssl/challenges",
            "http_challenge": "/var/www/{zone}/{host}/.well-known/acme-challenge",
            "hpkp": "/etc/ssl/hpkp",
            "ocsp": "/etc/ssl/ocsp/",
            "sct": "/etc/ssl/scts/{name}/{key_type}",
            "update_key": "/etc/ssl/update_keys",
            "archive": "/etc/ssl/archive"
        },
        ...
    }

Directory values are treated as Python format strings,
fields available for directories are: ``name``, ``key_type``, ``suffix``, ``server``.
The ``name`` field is the name of the private key or certificate.
The ``"http_challenge"`` directory uses the fields: ``zone``, ``host``, and ``fqdn``,
for the zone name, host name (without the zone), and the fully qualified domain name respectively.
The ``host`` value will be ``"."`` if the fqdn is the same as the zone name.


Services
--------

This specifies a list of services that are used by issued certificates and the commands necessary to restart or reload the service when a certificate is issued or changed.
You may add or remove services as needed.
The list of services is arbritrary and they are referenced from individual certificate definitions.

Example::

    {
        ...
        "services": {
            "apache": "systemctl reload apache2",
            "coturn": "systemctl restart coturn",
            "dovecot": "systemctl restart dovecot",
            "etherpad": "systemctl restart etherpad",
            "mysql": "systemctl reload mysql",
            "nginx": "systemctl reload nginx",
            "postfix": "systemctl reload postfix",
            "postgresql": "systemctl reload postgresql",
            "prosody": "systemctl restart prosody",
            "slapd": "systemctl restart slapd",
            "synapse": "systemctl restart matrix-synapse",
            "znc": "systemctl restart znc"
        },
        ...
    }

To specify one or more services used by a certificate,
add a ``services`` section to the certificate definition listing the services using that certificate.

For example::

    {
        "certificates": {
            "example.com": {
                "alt_names": {
                    "example.com": ["@", "www"]
                },
                "services": ["nginx"]
            }
        }
    }

This will cause the command ``"systemctl reload nginx"`` to be executed any time the certificate ``example.com`` is issued, renewed, or updated.


Certificates
------------

This section defines the set of certificates to issue and maintain.
The name of each certificate is used as the name of the certificate files.

* ``common_name`` specifies the common name for the certificate.
  If omitted, the name of the certificate will be used.
* ``alt_names`` specifies the set of subject alternative names for the certificate.
  If specified, the common name of the certificate must be included as one of the alternative names.
  The alternative names are specified as a list of host names per DNS zone,
  so that associated DNS updates happen in the correct zone.
  The zone name may be used directly by specifying ``"@"`` for the host name.
  Multiple zones may be specified.
  The default value is the common name of the certificate in the zone of the first registered domain name according to the `Public Suffix List <https://publicsuffix.org/>`_.
  For example, if the common name is "example.com", the default ``alt_names`` will be: ``{"example.com": ["@"] }``;
  if the common name is "foo.bar.example.com", the default ``alt_names`` will be: ``{ "example.com": ["foo.bar"] }``.
* ``services`` specifies the list of services to be reloaded when the certificate is issued, renewed, or modified.
  This may be omitted.
  The default value is the value specified in the ``settings`` section.
* ``dhparam_size`` specifies the number of bits to use for custom Diffie-Hellman paramaters for the certificate.
  The default value is the value specified in the ``settings`` section.
  Custom Diffie-Hellman paramaters may be ommitted from the certificate by setting this to ``0`` or ``null``.
  The value should be at least equal to half the number of bits used for the private key.
* ``ecparam_curve`` specified the curve or curves used for elliptical curve paramaters.
  The default value is the value specified in the ``settings`` section.
  Custom elliptical curve paramaters may be ommitted from the certificate by setting this to ``null``.
* ``key_types`` specifies the types of keys to create for this certificate.
  The default value is all available key types.
  Provide a list of key types to restrict the certificate to only those types.
  Available types are ``"rsa"`` and ``"ecdsa"``.
* ``key_size`` specifies the number of bits to use for the certificate's RSA private key.
  The default value is the value specified in the ``settings`` section.
  RSA certificates can be turned off by setting this value to ``0`` or ``null``.
* ``key_curve`` specifies the curve to use for ECDSA private keys.
  The default value is the value specified in the ``settings`` section.
  Available curves are ``"secp256r1"``, ``"secp384r1"``, and ``"secp521r1"``.
  ECDSA certificates can be turned off by setting this value to ``null``.
* ``key_cipher`` specifies the cipher algorithm used to encrypt the private keys.
  The default value is the value specified in the ``settings`` section.
  Available ciphers those accepted by your version of OpenSSL's EVP_get_cipherbyname().
* ``key_passphrase`` specifies the passphrase used to encrypt private keys.
  The default value is the value specified in the ``settings`` section.
  A value of ``null`` or ``false`` will result in private keys being written unencrypted.
  A value of ``true`` will cause the password to be read from the command line, the environment, a prompt, or stdin.
  A string value will be used as the passphrase without further input.
* ``key_provided`` specifies that the private keys are provided from an external source and the tool should not modify them.
  The default value is the value specified in the ``settings`` section.
  This is useful when the same private keys are shared between multiple instances of the tool, e.g. for HPKP purposes.
* ``expiration_days`` specifies the number of days that the backup private key should be considered valid.
  The default value is the value specified in the ``settings`` section.
  When the backup key reaches this age,
  the tool will notify the user that a key rollover should be performed,
  or automatically rollover the private key if ``auto_rollover`` is set to ``true``.
  Automatic rollover and expiration notices can be disabled by setting this to ``0`` or ``null``.
* ``auto_rollover`` specifies if the tool should automatically rollover the private key when it expires.
  The default value is the value specified in the ``settings`` section.
* ``hpkp_days`` specifies the number of days that HPKP pins should be cached by clients.
  The default value is the value specified in the ``settings`` section.
  HPKP pin files can be turned off by setting this value to ``0`` or ``null``.
* ``pin_subdomains`` specifies whether the ``includeSubdomains`` directive should be included in the HPKP headers.
  The default value is the value specified in the ``settings`` section.
* ``hpkp_report_uri`` specifies the uri to report HPKP errors to.
  The default value is the value specified in the ``settings`` section.
  If not null, the ``report-uri`` directive will be included in the HPKP headers.
* ``ocsp_must_staple`` specifies if the OCSP Must-Staple extension is added to certificates.
  The default value is the value specified in the ``settings`` section.
* ``ocsp_responder_urls`` specifies the list of OCSP responders to use if a certificate doesn't provide them.
  The default value is the value specified in the ``settings`` section.
* ``ct_submit_logs`` specifies the list of certificate transparency logs to submit the certificate to.
  The default value is the value specified in the ``settings`` section.
  The value ``["google_testtube"]`` can be used with the Let's Encrypt staging environment for testing.
* ``verify`` specifies the list of ports to perform certificate installation verification on.
  The default value is the value specified in the ``settings`` section.

Example::

    {
        ...
        "certificates": {
            "example.com": {
                "common_name": "example.com",
                "alt_names": {
                    "example.com": ["@", "www"]
                },
                "services": ["nginx"],
                "dhparam_size": 2048,
                "ecparam_curve": ["secp521r1", "secp384r1", "secp256k1"],
                "key_types": ["rsa", "ecdsa"],
                "key_size": 4096,
                "key_curve": "secp384r1",
                "key_cipher": "blowfish",
                "key_passphrase": null,
                "key_provided": false,
                "expiration_days": 730,
                "auto_rollover": false,
                "hpkp_days": 60,
                "pin_subdomains": true,
                "hpkp_report_uri": null,
                "ocsp_must_staple": false,
                "ocsp_responder_urls": ["http://ocsp.int-x3.letsencrypt.org"],
                "ct_submit_logs": ["google_icarus", "google_pilot"],
                "verify": [443]
            }
        }
    }


Private Keys
------------

This section defines the set of private keys generated and their associated certificates.
Multiple certificates may share a single private key.
This is useful when it is desired to use different certificates for certain subdomains,
while specifying HPKP headers for a root domain that also apply to subdomains.

The name of each private key is used as the file name for the private key files.

Note that a certificate configured in the ``certificates`` section is equivalent to a private key configured in this section with a single certificate using the same name as the private key.
As such, it is an error to specify a certificate using the same name in both the ``certificates`` and ``private_keys`` sections.

The private key and certificate settings are identical to those specified in the ``certificates`` section,
except settings relevant to the private key: ``key_size``, ``key_curve``, ``key_cipher``, ``key_passphrase``, ``key_provided``, ``expiration_days``, ``auto_rollover``, ``hpkp_days``, ``pin_subdomains``, and ``hpkp_report_uri`` are specified in the private key object rather than the certificate object.
The ``key_types`` setting may be specified in the certificate, private key, or both.

Example::

    {
        ...
        "private_keys": {
            "example.com": {
                "certificates": {
                    "example.com": {
                        "common_name": "example.com",
                        "alt_names": {
                            "example.com": ["@", "www"]
                        },
                        "services": ["nginx"],
                        "key_types": ["rsa"],
                        "dhparam_size": 2048,
                        "ecparam_curve": ["secp521r1", "secp384r1", "secp256k1"],
                        "ocsp_must_staple": true,
                        "ct_submit_logs": ["google_icarus", "google_pilot"],
                        "verify": [443]
                    },
                    "mail.example.com": {
                        "alt_names": {
                            "example.com": ["mail", "smtp"]
                        },
                        "services": ["dovecot", "postfix"],
                        "key_types": ["rsa", "ecdsa"]
                    }
                },
                "key_types": ["rsa", "ecdsa"],
                "key_size": 4096,
                "key_curve": "secp384r1",
                "key_cipher": "blowfish",
                "key_passphrase": null,
                "key_provided": false,
                "expiration_days": 730,
                "auto_rollover": false,
                "hpkp_days": 60,
                "pin_subdomains": true,
                "hpkp_report_uri": null
            }
        },
        ...
    }

The above example will generate a single primary/backup private key set and two certificates, ``example.com`` and ``mail.example.com`` both using the same private keys.
An ECDSA certicicate will only be generated for ``mail.example.com``.


TLSA Records
------------

When using remote DNS updates,
it is possible to have the tool automatically maintain TLSA records for each certificate.
Note that this requires configuring zone update keys for each zone containing a TLSA record.

When using local DNS updates, the ``reload_zone`` command will be called after certificates are issued, renewed, or modified to allow TLSA records to be updated by a tool such as `bindtool`_.
The ``reload_zone`` command will not be called in follower mode.

To specify TLSA records, add a ``tlsa_records`` name/object pair to each certificate definition, either in the ``certificates`` or ``private_keys`` section.
TLSA records are specified per DNS zone, similar to ``alt_names``,
to specify which zone should be updated for each TLSA record.

For each zone in the TLSA record object,
specify a list of either host name strings or objects.
Using a host name string is equivalent to::

    {
        "host": "<host-name>"
    }

The values for the objects are:

* ``host`` specifies the host name for the TLSA record.
  The default value is ``"@"``.
  The host name ``"@"`` is used for the name of the zone itself.
* ``port`` specifies the port number for the TLSA record.
  The default value is ``443``.
* ``usage`` is one of the following: ``"pkix-ta"``, ``"pkix-ee"``, ``"dane-ta"``, or ``"dane-ee"``.
  The default value is ``"pkix-ee"``.
  When specifying an end effector TLSA record (``"pkix-ee"`` or ``"dane-ee"``),
  the hash generated will be of the certificate or public key itself.
  When specifying a trust anchor TLSA record (``"pkix-ta"`` or ``"dane-ta"``),
  records will be generated for each of the intermediate and root certificates.
* ``selector`` is one of the following: ``"cert"``, or ``"spki"``.
  The default value is ``"spki"``.
  When specifying a value of ``"spki"`` and an end effector usage,
  records will be generated for both the primary and backup public keys.
* ``protocol`` specifies the protocol for the TLSA record.
  The default value is ``"tcp"``.
* ``ttl`` specifies the TTL value for the TLSA records.
  The default value is ``300``.

Example::

    {
        ...
        "private_keys": {
            "example.com": {
                "certificates": {
                    "example.com": {
                        "alt_names": {
                            "example.com": ["@", "www"]
                        },
                        "services": ["nginx"],
                        "tlsa_records": {
                            "example.com": [
                                "@",
                                {
                                    "host": "www",
                                    "port": 443,
                                    "usage": "pkix-ee",
                                    "selector": "spki",
                                    "protocol": "tcp",
                                    "ttl": 300
                                }
                            ]
                        }
                    },
                    "mail.example.com": {
                        "alt_names": {
                            "example.com": ["mail", "smtp"]
                        },
                        "services": ["dovecot", "postfix"],
                        "tlsa_records": {
                            "example.com": [
                                {
                                    "host": "mail",
                                    "port": 993
                                },
                                {
                                    "host": "smtp",
                                    "port": 25,
                                    "usage": "dane-ee"
                                },
                                {
                                    "host": "smtp",
                                    "port": 587
                                }
                            }
                        }
                    }
                }
            }
        },
        ...
    }


Authorizations
--------------

This section specifies a set of host name authorizations to obtain without issuing certificates.

This is used when running in a master/follower configuration,
the master, having access to local or remote DNS updates or an HTTP server,
obtains authorizations,
while the follower issues the certificates.

It is not necessary to specify host name authorizations for any host names used by configured certificates,
but it is not an error to have overlap.

Authorizations are specified per DNS zone so that associated DNS updates happen in the correct zone.

Simplar to ``alt-names``, a host name of ``"@"`` may be used to specify the zone name.

Example::

    {
        ...
        "authorizations": {
            "example.com": ["@", "www"]
        },
        ...
    }


HTTP Challenges
---------------

By default, the tool will attempt dns-01 domain authorizations for every alternative name specified,
using local or remote DNS updates.

To use http-01 authorizations instead,
configure the ``http_challenges`` section of the configuration file specifying a challenge directory for each fully qualified domain name,
or configure a ``http_challenge`` directory.

It is possible to mix usage of dns-01 and http-01 domain authorizations on a host by host basis,
simply specify a http challenge directory only for those hosts requiring http-01 authentication.

Example::

    {
        ...
        "http_challenges": {
            "example.com": "/var/www/htdocs/.well-known/acme-challenge"
            "www.example.com": "/var/www/htdocs/.well-known/acme-challenge"
        },
        ...
    }

The ``http_challenges`` must specify a directory on the local file system such that files placed there will be served via an already running http server for each given domain name.
In the above example,
files placed in ``/var/www/htdocs/.well-known/acme-challenge`` must be publicly available at:
``http://example.com/.well-known/acme-challenge/file-name``
and
``http://www.example.com/.well-known/acme-challenge/file-name``

Alternatively, if your are primarily using http-01 authorizations and all challenge directories have a similar path,
you may configure a single ``http_challenge`` directory using a python format string with the fields ``zone``, ``host``, and ``fqdn``.

Example::

    {
        ...
        "directories": {
            "http_challenge": "/var/www/{zone}/{host}/.well-known/acme-challenge"
        },
        ...
    }

If an ``http_challenge`` directory is configured,
all domain authorizations will default to http-01.
To use dns-01 authorizations for selected domain names,
add an ``http_challenges`` entry configured with a ``null`` value.


Zone Update Keys
----------------

When using remote DNS updates,
it is necessary to specify a TSIG key used to sign the update requests.

For each zone using remote DNS udpates,
specify either a string containing the file name of the TSIG key,
or an object with further options.

The TSIG file name may an absolute path or a path relative to the ``update_key`` directory setting.
Both the ``<key-file>.key`` file and the ``<key-file>.private`` files must be present.

Any zone referred to in a certificate, private key, or authorization that does not have a corresponding zone update key will use local DNS updates unless an HTTP challenge directory has been specified for every host in that zone.

* ``file`` specifies the name of the TSIG key file.
* ``server`` specifies the name of the DNS server to send update requests to.
  If omitted, the primary name server from the zone's SOA record will be used.
* ``port`` specifies the port to send update requests to.
  The default value is ``53``.

Example::

    {
        ...
        "zone_update_keys": {
            "example1.com": "update.example1.com.key",
            "example2.com": {
                "file": "update.example2.com.key",
                "server": "ns1.example2.com",
                "port": 53
            }
        },
        ...
    }


Key Type Suffix
---------------

Each certificate and key file will have a suffix, just before the file extension,
indicating the type of key the file is for.

The default suffix used for each key type can be overridden in the ``key_type_suffixes`` section.
If you are only using a single key type, or want to omit the suffix from one key type,
set it to an empty string.
Note that if using multiple key types the suffix must be unique or files will be overridden.

Example::

    {
        ...
        "key_type_suffixes": {
            "rsa": ".rsa",
            "ecdsa": ".ecdsa"
        },
        ...
    }


File Name Patterns
------------------

All output file names can be overridden using standard Python format strings.
Fields available for file names are: ``name``, ``key_type``, ``suffix``, ``server``.
The ``name`` field is the name of the private key or certificate.

* ``log`` specifies the name of the log file.
* ``private_key`` specifies the name of primary private key files.
* ``backup_key`` specifies the name of backup private key files.
* ``full_key`` specifies the name of primary private key files that include the certificate chain.
* ``certificate`` specifies the name of certificate files.
* ``full_certificate`` specifies the name of certificate files that include the root certificate.
* ``chain`` specifies the name of intemediate certificate files.
* ``param`` specifies the name of Diffie-Hellman parameter files.
* ``challenge`` specifies the name of ACME challenge files used for local DNS updates.
* ``hpkp`` specifies the name of HPKP header files.
* ``ocsp`` specifies the name of OCSP response files.
* ``sct`` specifies the name of SCT files.

Example::

    {   ...
        "file_names": {
            "log": "acmebot.log",
            "private_key": "{name}{suffix}.key",
            "backup_key": "{name}_backup{suffix}.key",
            "full_key": "{name}_full{suffix}.key",
            "certificate": "{name}{suffix}.pem",
            "full_certificate": "{name}+root{suffix}.pem",
            "chain": "{name}_chain{suffix}.pem",
            "param": "{name}_param.pem",
            "challenge": "{name}",
            "hpkp": "{name}.{server}",
            "ocsp": "{name}{suffix}.ocsp",
            "sct": "{ct_log_name}.sct"
        },
        ...
    }


HPKP Headers
------------

This section defines the set of HPKP header files that will be generated and their contents.
Header files for additional servers can be added at will,
one file will be generated for each server.
Using standard Python format strings, the ``{header}`` field will be replaced with the HPKP header,
the ``{key_name}`` field will be replaced with the name of the private key,
and ``{server}`` will be replaced with the server name.
The default servers can be omitted by setting the header to ``null``.

Example::

    {
        ...
        "hpkp_headers": {
            "apache": "Header always set Public-Key-Pins \"{header}\"\n",
            "nginx": "add_header Public-Key-Pins \"{header}\" always;\n"
        },
        ...
    }


Certificate Transparency Logs
-----------------------------

This section defines the set of certificate transparency logs available to submit certificates to and retrieve SCTs from.
Additional logs can be aded at will.
Each log definition requires the primary API URL of the log, and the log's ID in base64 format.
A list of currently active logs and their IDs can be found at `certificate-transparency.org <https://www.certificate-transparency.org/known-logs>`_.

Example::

    {
        ...,
        "ct_logs": {
            "google_pilot": {
                "url": "https://ct.googleapis.com/pilot",
                "id": "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA="
            },
            "google_icarus": {
                "url": "https://ct.googleapis.com/icarus",
                "id": "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg="
            }
        },
        ...
    }


Deployment Hooks
----------------

This section defines the set of hooks that can be called via the shell when given actions happen.
Paramaters to hooks are specified using Python format strings.
Fields available for each hook are described below.
Output from the hooks will be captured in the log.
Hooks returing a non-zero status code will generate warnings,
but will not otherwise affect the operation of this tool.

* ``set_dns_challenge`` is called for each DNS challenge record that is set.
  Available fields are ``domain``, ``zone``, and ``challenge``.
* ``clear_dns_challenge`` is called for each DNS challenge record that is removed.
  Available fields are ``domain``, ``zone``, and ``challenge``.
* ``dns_zone_update`` is called when a DNS zone is updated via either local or remote updates.
  Available field is ``zone``.
* ``set_http_challenge`` is called for each HTTP challenge file that is installed.
  Available fields are ``domain``, and ``challenge_file``.
* ``clear_http_challenge`` is called for each HTTP challenge file that is removed.
  Available fields are ``domain``, and ``challenge_file``.
* ``private_key_rollover`` is called when a private key is replaced by a backup private key.
  Available fields are ``key_name``, ``key_type``, ``backup_key_file``, ``private_key_file``, ``previous_key_file``, and ``passphrase``.
* ``private_key_installed`` is called when a private key is installed.
  Available fields are ``key_name``, ``key_type``, ``private_key_file``, and ``passphrase``.
* ``backup_key_installed`` is called when a backup private key is installed.
  Available fields are ``key_name``, ``key_type``, ``backup_key_file``, and ``passphrase``.
* ``previous_key_installed`` is called when a previous private key is installed after key rollover.
  Available fields are ``key_name``, ``key_type``, ``previous_key_file``, and ``passphrase``.
* ``hpkp_header_installed`` is called when a HPKP header file is installed.
  Available fields are ``key_name``, ``server``, ``header``, and ``hpkp_file``.
* ``certificate_installed`` is called when a certificate file is installed.
  Available fields are ``key_name``, ``key_type``, ``certificate_name``, and ``certificate_file``.
* ``full_certificate_installed`` is called when a certificate file that includes the root is installed.
  Available fields are ``key_name``, ``key_type``, ``certificate_name``, and ``full_certificate_file``.
* ``chain_installed`` is called when a certificate intermediate chain file is installed.
  Available fields are ``key_name``, ``key_type``, ``certificate_name``, and ``chain_file``.
* ``full_key_installed`` is called when a private key including the full certificate chain file is installed.
  Available fields are ``key_name``, ``key_type``, ``certificate_name``, and ``full_key_file``.
* ``params_installed`` is called when a params file is installed.
  Available fields are ``key_name``, ``certificate_name``, and ``params_file``.
* ``sct_installed`` is called when a SCT file is installed.
  Available fields are ``key_name``, ``key_type``, ``certificate_name``, ``ct_log_name``, and ``sct_file``.
* ``ocsp_installed`` is called when an OSCP file is installed.
  Available fields are ``key_name``, ``key_type``, ``certificate_name``, and ``ocsp_file``.

Example::

    {
        ...
        "hooks": {
            certificate_installed": "scp {certificate_file} remote-server:/etc/ssl/certs/"
        },
        ...
    }


Certificate Installation Verification
-------------------------------------

The tool may be configured to perform installation verification of certificates.
When verifying installation, the tool will connect to every subject alternative host name for each certificate on all avaialable IP addresses,
per each configured port,
perform a TLS handshake,
and compare the served certificate chain to the specified certificate.

Each configured port may be an integer port number,
or an object specifying connection details.

When using an object, the avaialable fields are:

* ``port`` specifies the port number to connect to.
  Required.
* ``starttls`` specifies the STARTTLS mechanism that should be used to initiate a TLS session.
  Allowed values are: ``null``, ``smtp``, ``pop3``, ``imap``, ``sieve``, ``ftp``, ``ldap``, and ``xmpp``.
  The default value is ``null``.
* ``protocol`` specifies the protocol used to obtain additional information to verify.
  Currently this can retrieve Public-Key-Pins http headers to ensure that they are properly set.
  Allowed values are: ``null``, and ``http``.
  The default value is ``null``.
* ``hosts`` specifies a list of fully qualified domain names to test.
  This allows testing only a subset of the alternative names specified for the certificate.
  Each host name must be present as an alternative name for the certificate.
  The default value is all alternative names.
* ``key_types`` specifies a list of key types to test.
  This allows testing only a subset of the avaialable key types.
  The default value is all avaialable key types.

Example::

    {
        ...
        "verify": [
            {
                "port": 443,
                "protocol": "http"
            },
            {
                "port": 25,
                "starttls": "smtp",
                "hosts": "smtp.example.com",
                "key_types": "rsa"
            },
            993
        ]
        ...
    }


Configuring Local DNS Updates
=============================

In order to perform dns-01 authorizations,
and to keep TLSA records up to date,
the tool will need to be able to add, remove, and update various DNS records.

For updating DNS on a local server,
this tool was designed to use a bind zone file pre-processor,
such as `bindtool`_,
but may be used with another tool instead.

When using `bindtool`_, be sure to configure bindtool's ``acme_path`` to be equal to the value of the ``challenge`` directory, so that it can find the ACME challenge files.

When the tool needs to update a DNS zone, it will call the configured ``reload_zone`` command with the name of the zone as its argument.
When _acme-challenge records need to be set, a file will be placed in the ``challenge`` directory with the name of the zone in question, e.g. ``/etc/ssl/challenges/example.com``.
The challenge file is a JSON format file containing a single object.
The name/value pairs of that object are the fully qualified domain names of the records needing to be set, and the values of the records, e.g.::

    {
        "www.example.com": "gfj9Xq...Rg85nM"
    }

Which should result in the following DNS record created in the zone::

    _acme-challenge.www.example.com. 300 IN TXT "gfj9Xq...Rg85nM"

Note that domain names containing wildcards must have the wildcard component removed in the corresponding TXT record, e.g.::

    {
        "example.com": "jc87sd...kO89hG"
        "*.example.com": "gfj9Xq...Rg85nM"
    }

Must result in the following DNS records created in the zone::

    _acme-challenge.example.com. 300 IN TXT "jc87sd...kO89hG"
    _acme-challenge.example.com. 300 IN TXT "gfj9Xq...Rg85nM"

If there is no file in the ``challenge`` directory with the same name as the zone, all _acme-challenge records should be removed.

Any time the ``reload_zone`` is called, it should also update any TLSA records asscoiated with the zone based on the certificates or private keys present.

All of these functions are provided automatically by `bindtool`_ via the use of ``{{acme:}}`` and ``{{tlsa:}}`` commands in the zone file.
For example, the zone file::

    {{soa:ns1.example.com:admin@example.com}}

    {{ip4=192.0.2.0}}

    @   NS  ns1
    @   NS  ns2

    @   A   {{ip4}}
    www A   {{ip4}}

    {{tlsa:443}}
    {{tlsa:443:www}}

    {{acme:}}

    {{caa:letsencrypt.org}}

Will define the zone ``example.com`` using the nameservers ``ns1.example.com`` and ``ns1.example.com``, providing the hosts ``example.com`` and ``www.example.com``, with TLSA records pinning the primary and backup keys.


Configuring Remote DNS Updates
==============================

If the tool is not run on a machine also hosting a DNS server, then http-01 authorizations or remote DNS updates must be used.

The use remote DNS udpates via RFC 2136 dynamic updates,
configure a zone update key for each zone.
See the `Zone Update Keys <#zone-update-keys>`_ section for more information.

It is also necesary to have the ``nsupdate`` tool installed and the ``nsupdate_command`` configured in the ``settings`` configuration section.

Zone update keys may be generated via the ``dnssec-keygen`` tool.

For example::

    dnssec-keygen -r /dev/urandom -a HMAC-MD5 -b 512 -n HOST update.example.com

will generate two files, named Kupdate.example.com.+157+NNNNN.key and Kupdate.example.com.+157+NNNNN.private.
Specify the .key file as the zone update key.

To configure bind to allow remote DNS updates, add an entry to named.conf.keys for the update key containg the key value from the private key file, e.g.::

    key update.example.com. {
        algorithm hmac-md5;
        secret "sSeWrBDen...9WESlnEwQ==";
    };

and then add an ``allow-update`` entry to the zone configuration, e.g.::

    zone "example.com" {
        type master;
        allow-update { key update.example.com.; };
        ...
    };


Running the Tool
================

On first run, the tool will generate a client key,
register that key with the certificate authority,
accept the certificate authority's terms and conditions,
perform all needed domain authorizations,
generate primary private keys,
issue certificates,
generate backup private keys,
generate custom Diffie-Hellman parameters,
install certificate and key files,
update TLSA records,
retrieve current Signed Certificate Timestamps (SCTs) from configured certificate transparency logs,
retrieve OCSP staples,
reload services associated to the certificates,
and perform configured certificate installation verification.

Each subsequent run will ensure that all authorizations remain valid,
check if any backup private keys have passed their expiration date,
check if any certificate's expiration dates are within the renewal window,
or have changes to the configured common name, or subject alternative names,
or no longer match their associated private key files.

If a backup private key has passed its expiration date,
the tool will rollover the private key or emit a warning recommending that the private key be rolled over,
see the `Private Key Rollover <#private-key-rollover>`_ section for more information.

If a certificate needs to be renewed or has been modified,
the certificate will be re-issued and reinstalled.

When certificates are issued or re-issued,
local DNS updates will be attempted (to update TLSA records) and associated services will be reloaded.

When using remote DNS updates,
all configured TLSA records will be verified and updated as needed on each run.

Configured certificate transparency logs will be queried and SCT files will be updated as necessary.

All certificates and private keys will normally be processed on each run,
to restrict processing to specific private keys (and their certificates),
you can list the names of the private keys to process on the command line.


Daily Run Via cron
------------------

In order to ensure that certificates in use do not expire,
it is recommended that the tool be run at least once per day via a cron job.

By default, the tool only generates output when actions are taken making it cron friendly.
Normal output can be supressed via the ``--quiet`` command line option.

To prevent multiple instances running at the same time,
a random wait can be introduced via the ``--randomwait`` command line option.
The minimum and maximum wait times can be controlled via the ``min_run_delay`` and ``max_run_delay`` settings.

Example cron entry, in file /etc/cron.d/acmebot::

    MAILTO=admin@example.com

    20 0 * * * root /usr/local/bin/acmebot --randomwait

This will run the tool as root every day at 20 minutes past midnight plus a random delay of five minutes to an hour.
Any output will be mailed to admin@example.com.

If using OCSP response files, it may be desirable to refresh OCSP responses at a shorter interval.
(Currently Let's Encrypt updates OCSP responses every three days.)
To refresh OCSP responses every six hours, add the line:

    20 6,12,18 * * * root /usr/local/bin/acmebot --ocsp --randomwait


Output Options
--------------

Normally the tool will only generate output to stdout when certificates are issued or private keys need to be rolled over.
More detailed output can be obtained by using any of the ``--verbose``, ``--debug``, or ``--detail`` options on the command line.

Normal output may be supressed by using the ``--quiet`` option.

Error and warning output will be sent to stderr and cannot be supressed.

The output can be colorized by type by adding the ``--color`` option,
or colorized output can be suppressed via the ``--no-color`` option.


Private Key Rollover
--------------------

During normal operations the private keys for certificates will not be modified,
this allows renewing or modifying certificates without the need to update associated pinning information,
such as HPKP headers or TLSA records using spki selectors.

However, it is a good security practice to replace the private keys at regular intervals,
or immediately if it is believed that the primary private key may have been compromised.
This tool maintains a backup private key for each primary private key and generates pinning information including the backup key as appropriate to allow smooth transitions to the backup key.

When the backup private key reaches the age specified via the ``expiration_days`` setting,
the tool will notify you that it is time to rollover the private key,
unless the ``auto_rollover`` setting has been set to ``true``,
in which case it will automatically perform the rollover.

The rollover process will archive the current primary private key,
re-issue certificates using the existing backup key as the new primary key,
generate a new backup private key,
generate new custom Diffie-Hellman parameters,
and reset HPKP headers and TLSA records as appropriate.

If the ``previous_key`` directory is specified,
the current primary private key will be stored in that directory as a previous private key.
While previous private key files are present,
their key signatures will be added to HPKP pins and TLSA records.
This can assist in key rollover when keys are pinned for subdomains and private keys are shared between multiple servers.
Once the new primary and backup keys have been distributed to the other servers,
the previous private key file may be safely removed.

To manually rollover private keys, simply run the tool with the ``--rollover`` option.
You can specify the names of individual private keys on the command line to rollover,
otherwise all private keys will be rolled over.

Note that the tool will refuse to rollover a private key if the current backup key is younger than the HPKP duration.
A private key rollover during this interval may cause a web site to become inaccessable to clients that have previously cached HPKP headers but not yet retrieved the current backup key pin.
If it is necessary to rollover the private key anyway,
for example if it is believed that the backup key has been compromised as well,
add the ``--force`` option on the command line to force the private key rollover.


Forced Certificate Renewal
--------------------------

Normally certificates will be automatically renewed when the tool is run within the certificate renewal window,
e.g. within ``renewal_days`` of the certificate's expiration date.
To cause certificates to be renewed before this time,
run the tool with the ``--renew`` option on the command line.


Revoking Certificates
---------------------

Should it become necessary to revoke a certificate,
for example if it is believed that the private key has been compromised,
run the tool with the ``--revoke`` option on the command line.

When revoking certificates, as a safety measure,
it is necessary to also specify the name of the private key (or keys) that should be revoked.
All certificates using that private key will be revoked,
the certificate files and the primary private key file will be moved to the archive,
and remote DNS TLSA records will be removed.

The next time the tool is run after a revocation,
any revoked certificates that are still configured will automatically perform a private key rollover.


Authorization Only
------------------

Use of the ``--auth`` option on the command line will limit the tool to only performing domain authorizations.


Certificates Only
-----------------

Use of the ``--certs`` option on the command line will limit the tool to only issuing and renewing certificates and keys,
and updating related files such as Diffie-Hellman paramaters and HPKP headers.


Remote TLSA Updates
-------------------

Use of the ``--tlsa`` option on the command line will limit the tool to only verifying and updating configured TLSA records via remote DNS updates.


Signed Certificate Timestamp Updates
------------------------------------

Use of the ``--sct`` option on the command line will limit the tool to only verifying and updating configured Signed Certificate Timestamp files.


OCSP Response Updates
---------------------

Use of the ``--ocsp`` option on the command line will limit the tool to only updating configured OCSP response files.


Certificate Installation Verification
-------------------------------------

Use of the ``--verify`` option on the command line will limit the tool to only performing certificate installation verification.


Multiple Operations
-------------------

The ``--auth``, ``--certs``, ``--tlsa``, ``--sct``, ``-ocsp``, and ``--verify`` options may be combined to perform a combinations of operations.
If none of these options are specified, all operations will be performed as necessary and configured.
The order of the operations will not be affected by the order of the command line options.


Private Key Encryption
----------------------

When encrypting private keys, a passphrase must be provided.
There are several options for providing the key.

Passphrases may be specified directly in the configuration file,
both as a default passphrase applying to all keys,
or specific passphrases for each key.
Storing passphrases in cleartext in the configuration file obviously does little to protect the private keys if the configuration file is stored on the same machine.
Either protect the configuration file or use an alternate method of providing passphrases.

Alternatively, by setting the passphrase to ``true`` in the configuration file (the binary value, not the string ``"true"``),
the tool will attempt to obtain the passphrases at runtime.

Runtime passphrases may be provided on the command line, via an environment variable, via a text prompt, or via an input file.

A command line passphrase is passed via the ``--pass`` option, e.g.::

    acmebot --pass "passphrase"

To use an environment variable, set the passphrase in ``ACMEBOT_PASSPHRASE``.

A passphrase passed at the command line or an environment variable will be used for every private key that has it's ``key_passphrase`` set to ``true``.
If different passphrases are desired for different keys,
run the tool for each key specifying the private key name on the command line to restrict processing to that key.

If the passphrase is not provided on the command line or an environment variable,
and the tool is run via a TTY device (e.g. manually in a terminal),
it will prompt the user for each passphrase as needed.
Different passphrases may be provided for each private key (the same passphrase will be used for all key types of that key).

Finally, the passphrases may be stored in a file, one per line, and input redirected from that file, e.g.::

    acmebot < passphrase_file.txt

Passphrases passed via an input file will be used in the order that the private keys are defined in the configuration file.
If both certificates and private key sections are defined, the private keys will be processed first, then the certificates.
You may wish to run the tool without the input file first to verify the private key order.



Master/Follower Setup
=====================

In some circumstances, it is useful to run the tool in a master/follower configuration.
In this setup, the master performs domain authorizations
while the follower issues and maintains certificates.

This setup is useful when the follower machine does not have the ability to perform domain authorizations,
for example, an XMPP server behind a firewall that does not have port 80 open or access to a DNS server.

To create a master/follower setup,
first install and configure the tool on the master server as normal.
The master server may also issue certificates, but it is not necessary.

Configure any required domain authorizations (see the `Authorizations <#authorizations>`_ section) on the master and run the tool.

Then install the tool on the follower server.
It is not necessary to configure HTTP challenges or remote DNS update keys on the follower.

Before running the tool on the follower server,
copy the client key and registration files from the master server.
These files are normally found in ``/var/local/acmebot`` but an alternate location can be configured in the ``resource`` directory setting.

If the master server also issues certificates for the same domain names or parent domain names as the follower,
you may want to copy the primary and backup private keys for those certificates to the follower.
This will cause the follower certificates to use the same keys allowing HPKP headers to safey include subdomains.

Set the follower ``follower_mode`` setting to ``true`` and configure desired certificates on the follower.

Run the tool on the follower server.

When setting up cron jobs for the master and follower,
be sure the follower runs several minutes after the master so that all authorizations will be complete.
The master can theoretically take (``max_dns_lookup_attempts`` x ``dns_lookup_delay``) + (``max_authorization_attempts`` x ``authorization_delay``) seconds to obtain domain authorizations (15 minutes at the default settings).

It is possible to run several follower servers for each master,
the follower cron jobs should not all run at the same time.

The follower server may maintain TLSA records if remote DNS updates are configured on the follower,
otherwise it is recommended to use spki selectors for TLSA records so that certificate renewals on the follower will not invalidate TLSA records.

If private keys are shared between a master and follower,
be sure to turn off ``auto_rollover`` and only perform private key rollovers on the master.
It is also useful to specify the ``previous_key`` directory to preserve previous key pins during the key rollover process.
After a private key rollover, copy the new primary and backup private key files to the followers.
The follower will automatically detect the new private key and re-issue certificates on the next run.
Once all the followers have updated their certificates to the new keys,
you can safely delete the previous private key file.
