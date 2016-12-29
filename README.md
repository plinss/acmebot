[bindtool]: https://github.com/plinss/bindtool

# acmebot

ACME protocol automatic certitificate manager.

This tool acquires and maintains certificates from a certificate authority using the ACME protocol, similar to EFF's Certbot.
While developed and tested using Let's Encrypt, the tool should work with any certificate authority using the ACME protocol.


## Features

This tool is not intended as a replacement for Certbot and does not attempt to replicate all of Certbot's functionality,
notably it does not modify configuration files of other services,
or provide a server to perform stand-alone domain validation.
It does however, do a few things that Certbot does not,
simplifying certificate manangement in more advanced environments.
In addition to automatically issuing and maintaining certificates,
the tool can also maintain associated HPKP headers and TLSA (DANE) records.


### Master/Slave Mode

This tool separates the authorization (domain validation) and certificate issuance processes allowing one machine to maintain authorizations (the master),
while another machine issues certificates (the slave).
This is useful for situations where an isolated server is providing a service, such as XMPP,
behind a firewall and does not have the ability to perform authorizations over http or configure DNS records,
but still needs to obtain and periodically renew one or more certificates.


### Simple Sharing of Private Keys Between Certificates

This tool allows multiple certificates to be defined using the same public/private key pair.

When deploying Hypertext Puplic Key Pinning (HPKP), you can optionally use the same pins to secure subdomains.
This increases security of the site because a visitor to a root domain will have previously obtained pins for subdomains,
reducing the possibility of a man-in-the-middle attacker installing a false pin on first visit.

This practice obviously requires the use of the same public/private key pair for the domain and all subdomains.
However, it may not be desirable to use the same certificate for all subdomains, for example,
exposing the full list of subdomains in the alternative names of the root domain's certificate,
or reissuing the root domain's certificate every time a subdomain is added or removed.


### Automatic Management of Backup Private Keys

Using HPKP requires a second public key to provide a backup when private keys are changed.
This tool automatically generates backup keys and switches to the pre-generated backup key when rolling over private keys.
The tool also automatically maintains proper HPKP header information.


### Mixed Use of DNS and HTTP Authorization

By default this tool performs DNS-01 authorizartions for domain validation.
It is possible to configure overrides for specific domains names to use HTTP-01 authorization instead.
This is useful for situations where a domain outside your immediate control has provided an alias to your web site.


### Automatic Local or Remote DNS Updates

This tool can automatically add and remove DNS records for DNS-01 authorizations as well as TLSA records.
Updates to a local server can be made via an external zone file processor, such as [bindtool],
or to a remote DNS server via RFC 2136 dynamic DNS updates using nsupdate.
The choice between local and remote DNS updates can be made on a zone by zone basis.


## Installation

Requires Python 3.4+ and the acme and py3dns packages.

On Debian, these can be installed via:

    apt-get install build-essential libssl-dev libffi-dev python3-dev python3-pip
    pip3 install acme py3dns

Clone this repository or download the 'acmebot' file and install it on your server.
Copy the 'acmebot.example.json' file to 'acmebot.json' and edit the configuration options.
The configuration file can be placed in the current directory that the tool is run from,
the /etc/acmebot directory,
or the same directory that the acmebot tool is installed in.

Note that when using DNS-01 authorizations via a local DNS server,
this tool needs to be able to add, remove, update DNS records.
This can be achieved by installing it on your master DNS server and using [bindtool] to manage the zone file,
or you can use a custom shell script to update the DNS records.

When using DNS-01 authorizations via a remote server,
an update key allowing the creation and deletion of TXT and optionally TLSA record types is required.

Optional: some services require a full certificate chain including the root (OSCP stapling on Nginx, for example).
In order to generate these files,
place a copy of the root certificate from your CA of choice in the same directory as the configuration file with the file name 'root_cert.pem'.
The root certificate for Let's Encrypt can be obtained [here](https://letsencrypt.org/certificates/).


## Quick Start


### Basic Configuration

While the example configuration file may appear complicated,
it is meant to show all possible configuration options,
rather than demonstrate a basic simple configuration.

The only items that must be present in the configuration file to create and maintain a certificate are your account email address,
the file name, and subject alternative names for the certificate.
By default, the common name of the certificate will be the same as the certificate file name.

For example:

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

will create a certificate named 'example.com',
with the common name of 'example.com',
and the subject alternative names of 'example.com' and 'www.example.com'.

As many certificates as desired may be configured.
The number of alternative names is limited by the certificate authority (Let's Encrypt currently allows 100).
Alternative names are specified on a DNS zone basis,
multiple zones may be specified per certificate.
The host name '@' is used for the name of the zone itself.


### Authorization Setup

By default, the tool will attempt DNS-01 domain authorizations for every alternative name specified,
using local DNS updates.
See the later sections on configuring local or remote DNS updates.

To use HTTP-01 authorizations instead,
configure the 'http_challenges' section of the configuration file specifying a challenge directory for each fully qualified host name.

For example:

    {
        ...
        "http_challenges": {
            "example.com": "/var/www/htdocs/.well-known/acme-challenge",
            "www.example.com": "/var/www/htdocs/.well-known/acme-challenge"
        }
    }

See the HTTP Challenges section for more information.

### First Run

Once the configuration file is in place,
simply execute the tool.
For the first run you may wish to select verbose output to see exactly what the tool is doing:

    acmebot --verbose

If all goes well,
the tool will generate a public/private key pair used for client authentication to the certificate authority,
register an account with the certificate authority,
automatically accept the certificate authority's terms of service,
obtain authorizations for each configured domain name,
generate primary and backup private keys as needed for the configured certificates,
issue certificates,
and install the certificates and private keys into /etc/ssl/certs and /etc/ssl/private.

If desired, you can test the tool using Let's Encrypt's staging server.
To do this, specify the staging server's directory URL in the 'acme_directory_url' setting.
See [Staging Environment](https://letsencrypt.org/docs/staging-environment/) for details.
When switching from the staging to production servers,
you should delete the client key and registration files (/var/local/acmebot/*.json) to ensure a fresh registration in the production environment.

## File Locations

After a successful certificate issuance,
up to eight files will be created per certificate.

The locations for these files can be controlled via the 'directories' section of the configuration file.
The default locations are used here for brevity.

Output files will be written as a single transaction,
either all files will be written,
or no files will be written.
This is designed to prevent a mismatch between certificates and private keys should an error happen during file creation.


### Private Keys

Two private key files will be created in /etc/ssl/private.
The primary: &lt;filename&gt;.key; and a backup key: &lt;filename&gt;_backup.key.

The private key files will be written in PEM format and will be readable by owner and group.


### Certificate Files

Two certificate files will be created,
one in /etc/ssl/certs, named &lt;filename&gt;.pem,
containing the certificate,
followed by any intermediate certificates sent by the certificate authority,
followed by custom Diffie-Hellman paramaters;
the second file will be created in /etc/ssl/private, named &lt;filename&gt;_full.key,
and will contain the private key,
followed by the certificate,
followed by any intermediate certificates sent by the certificate authority,
followed by custom Diffie-Hellman paramaters.

The &lt;filename&gt;_full.key file is useful for services that require both the private key and certificate to be in the same file,
such as ZNC.


### Full Chain Certificate File

If the 'root_cert.pem' file was created (see Installation),
then an additional certificate file will be generated in /etc/ssl/certs,
named &lt;filename&gt;+root.pem.
This file will contain the certificate,
followed by any intermediate certificates sent by the certificate authority,
followed by the root certificate,
followed by custom Diffie-Hellman paramaters.

If the 'root_cert.pem' file is not found in the same directory as the configuration file,
this certificate file will not be created.

This file is useful for configuring OSCP stapling on Nginx servers.


### Diffie-Hellman Parameter File

If custom Diffie-Hellman parameters or a custom elliptical curve are configured,
a file will be created in /etc/ssl/private, named &lt;filename&gt;.param,
containing the Diffie-Hellman parameters and elliptical curve paramaters.


### Hypertext Public Key Pin (HPKP) Files

Two additional files will be created in /etc/ssl/hpkp, named  &lt;filename&gt;.apache and &lt;filename&gt;.nginx.
These files contain HTTP header directives setting HPKP for both the primary and backup private keys.

Each file is suitable to be included in the server configuration for either Apache or Nginx respectively.


### Archive Directory

Whenever exsiting files are replaced by subsequent runs of the tool,
for example during certificate renewal or private key rollover,
all existing files are preserved in the archive directory, /etc/ssl/archive.

Within the archive directory,
a directory will be created with the name of the private key,
containing a datestamped directory with the time of the file transaction (YYYY_MM_DD_HHMMSS).
All existing files will be moved into the datestamped directory should they need to be recovered.


## Server Configuration

Because certificate files will be periodically replaced as certificates need to be renewed,
it is best to have your server configurations simply refer to the certificate and key files in the locations they are created.
This will prevent server configurations from having to be updated as certificate files are replaced.

If the server requires the certificate or key file to be in a particular location or have a different file name,
it is best to simply create a soft link to the certificate or key file rather than rename or copy the files.

Another good practice it to isolate the configuration for each certificate into a snippet file,
for example using Apache,
create the file /etc/apache2/snippets/ssl/example.com containing:

    SSLCertificateFile    /etc/ssl/certs/example.com.pem
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
    Header set Strict-Transport-Security "max-age=31536000"
    Include /etc/ssl/hpkp/example.com.apache

and then in each host configuration using that certificate, simply add:

    Include snippets/ssl/example.com

For Nginx the /etc/nginx/snippets/ssl/example.com file would contain:

    ssl_certificate         /etc/ssl/certs/example.com.pem;
    ssl_certificate_key     /etc/ssl/private/example.com.key;
    ssl_trusted_certificate /etc/ssl/certs/example.com+root.pem;
    ssl_dhparam             /etc/ssl/certs/example.com.pem;
    ssl_ecdh_curve secp384r1;
    add_header Strict-Transport-Security "max-age=31536000";
    include /etc/ssl/hpkp/example.com.nginx;

and can be used via:

    include snippets/ssl/example.com;


## Configuration

The configuration file 'acmebot.json' may be placed in the current working directory,
in /etc/acmebot,
or in the same directory as the acmebot tool is installed in.
A different configuration file name may be specified on the command line.
If the specified file name is not an absolute path,
it will be searched for in the same locations,
e.g. 'acmebot --config config.json' will load ./config.json, /etc/acmebot/config.json, or &lt;install-dir&gt;/config.json
The file must adhere to standard JSON format.

The file 'acmebot.example.json' provides a template of all configuration options and their default values.
Entries inside angle brackets '&lt;example&gt;' must be replaced (without the angle brackets),
all other values except referenced services may be removed unless you want to override the default values.

### Account

Enter the email address you wish to associate with your account on the certificate authority.
This email address may be useful in recovering your account should you lose access to your client key.

Example:

    {
        "account": {
            "email": "admin@example.com"
        },
        ...
    }


### Settings

Various settings for the tool.
All of these need only be present when the desired value is different from the default.

* 'slave_mode' specifies if the tool should run in master or slave mode.
The defalt value is 'false' (master mode).
The master will obtain authorizations and issue certificates,
a slave will not attempt to obtain authorizations but can issue certificates.
* 'key_size' specifies the size (in bits) for private keys.
The default value is '4096'.
* 'dhparam_size' specifies the size (in bits) for custom Diffie-Hellman parameters.
The default value is '2048'.
Custom Diffie-Hellman parameters can be turned off by setting this value to '0'.
This value should at least be equal to half the 'key_size'.
* 'ecparam_curve' speficies the curve to use for ECDHE negotiation.
The default value is 'secp384r1'.
Custom EC parameters can be turned off by setting this value to null.
You can run 'openssl ecparam -list_curves' to find a list of available curves.
* 'file_user' specifies the name of the user that will own certificate and private key files.
The default value is 'root'.
Note that this tool must run as root, or another user that has rights to set the file ownership.
* 'file_group' speficies the name of the group that will own certificate and private key files.
The default value is 'ssl-cert'.
Note that this tool must run as root, or another user that has rights to set the file ownership.
* 'hpkp_days' specifies the number of days that HPKP pins should be cached for.
The default value is '30'.
HPKP pin files can be turned off by setting this value to '0'.
* 'pin_subdomains' specifies whether the 'includeSubdomains' directive should be included in the HPKP headers.
The default value is 'true'.
* 'renewal_days' specifies the number of days before expiration when the tool will attempt to renew a certificate.
The default value is '30'.
* 'expiration_days' specifies the number of days that private keys should be used for.
The dafault value is '730' (two years).
When the backup key reaches this age, the tool will notify the user that a key rollover should be performed.
Note that key rollovers must be coordinated between the master and slaves and will therefore not be automatically performed.
* 'max_dns_lookup_attempts' specifies the number of times to check for deployed DNS records before attempting authorizations.
The default value is '60'.
* 'dns_lookup_delay' specifies the number of seconds to wait between DNS lookups.
The default value is '10'.
* 'max_authorization_attempts' specifies the number of times to check for completed authorizations.
The default value is '30'.
* 'authorization_delay' specifies the number of seconds to wait between authorization checks.
The default value is '10'.
* 'acme_directory_url' specifies the primary URL for the ACME service.
The default value is 'https://acme-v01.api.letsencrypt.org/directory', the Let's Encrypt production API.
You can substitute the URL for Let's Encrypt's staging environment or another certificate authority.
* 'reload_zone_command' specifies the command to execute to reload local DNS zone information.
When using [bindtool] the 'reload-zone.sh' script provides this service.
* 'nsupdate_command' specifies the command to perform DNS updates.
The default value is '/usr/bin/nsupdate'.

Example:

    {
        ...
        "settings": {
            "slave_mode": false,
            "key_size": 4096,
            "dhparam_size": 2048,
            "ecparam_curve": "secp384r1",
            "file_user": "root",
            "file_group": "ssl-cert",
            "hpkp_days": 30,
            "pin_subdomains": true,
            "renewal_days": 30,
            "expiration_days": 730,
            "max_dns_lookup_attempts": 60,
            "dns_lookup_delay": 10,
            "max_authorization_attempts": 30,
            "authorization_delay": 10,
            "acme_directory_url": "https://acme-v01.api.letsencrypt.org/directory",
            "reload_zone_command": "/etc/bind/reload-zone.sh",
            "nsupdate_command": "/usr/bin/nsupdate"
        },
        ...
    }


### Directories

Directories used to store the input and output files of the tool.
All of these need only be present when the desired value is different from the default.

* 'pid' specifies the directory to store a process ID file.
The default value is '/var/run'.
* 'resource' specifies the directory to store the client key and registration files for the ACME account.
The default value is '/var/local/acmebot'.
* 'private_key' specifies the directory to store private key and backup private key files.
The default value is '/etc/ssl/private'.
* 'certificate' specifies the directory to store certificate files.
The default value is '/etc/ssl/certs'.
* 'dhparam' specifies the directory to store Diffie-Hellman parameter files.
The default value is '/etc/ssl/private'.
* 'challenge' specifies the directory to store ACME DNS-01 challenge files.
The default value is '/etc/ssl/challenge'.
* 'hpkp' specifies the directory to store HPKP header files.
The default value is '/etc/ssl/hpkp'.
* 'archive' specifies the directory to store older versions of files that are replaced by this tool.
The default value is '/etc/ssl/archive'.
* 'update_key' specifies the directory to search for DNS update key files.
The default value is '/etc/ssl/update_keys'.

Example:

    {
        ...
        "directories": {
            "pid": "/var/run",
            "resource": "/var/local/acmebot",
            "private_key": "/etc/ssl/private",
            "certificate": "/etc/ssl/certs",
            "dhparam": "/etc/ssl/private",
            "challenge": "/etc/ssl/challenges",
            "hpkp": "/etc/ssl/hpkp",
            "archive": "/etc/ssl/archive",
            "update_key": "/etc/ssl/update_keys"
        },
        ...
    }


### Services

This specifies a list of services that are used by issued certificates and the commands necessary to restart or reload the service when a certificate is issued or changed.
You may add or remove services as needed.
The list of services is arbritrary and they are referenced from individual certificate definitions.

Example:

    {
        ...
        "services": {
            "apache": "systemctl reload apache2",
            "coturn": "systemctl restart coturn",
            "dovecot": "systemctl restart dovecot",
            "etherpad": "systemctl restart etherpad",
            "nginx": "systemctl reload nginx",
            "postfix": "systemctl reload postfix",
            "prosody": "systemctl restart prosody",
            "synapse": "systemctl restart matrix-synapse",
            "znc": "systemctl restart znc"
        },
        ...
    }

To specify one or more services used by a certificate,
add a 'services' section to the certificate definition listing the services using that certificate.

For example:

    {
        "certificates": {
            "example.com": {
                "alt_names": {
                    "example.com": ["@", "www"]
                }
            },
            "services": ["nginx"]
        }
    }

This will cause the command 'systemctl reload nginx' to be executed any time the certificate 'example.com' is issued, renewed, or updated.


### Certificates

This section defines the set of certificates to issue and maintain.
The name of each certificate is used as the name of the certificate files.

* 'common_name' specifies the common name for the certificate.
If omitted, the name of the certificate will be used.
* 'alt_names' specifies the set of subject alternative names for the certificate.
This must be specified and the common name of the certificate must be included as one of the alternative names.
The alternateive names are specified as a list of host names per DNS zone,
so that associated DNS updates happen in the correct zone.
The zone name may be used directly by specifying '@'.
Multiple zones may be specified.
* 'services' specifies the list of services to be reloaded when the certificate is issued, renewed, or modified.
This may be omitted.
* 'dhparam_size' specifies the number of bits to use for custom Diffie-Hellman paramaters for the certificate.
The default value is the value specified in the 'settings' section.
Custom Diffie-Hellman paramaters may be ommitted from the certificate by setting this to '0'.
The value should be at least equal to half the number of bits used for the private key.
* 'ecparam_curve' specified the curve used for elliptical curve paramaters.
The default value is the value specified in the 'settings' section.
Custom elliptical curve paramaters may be ommitted from the certificate by setting this to an empty string or 'null'.
* 'key_size' specifies the number of bits to use for the certificate's private key.
The default value is the value specified in the 'settings' section.
* 'expiration_days' specifies the number of days that the backup private key should be considered valid.
The default value is the value specified in the 'settings' section.
After this period, the tool will recommend rolling over the private key.
* 'hpkp_days' specifies the number of days that HPKP pins should be cached by clients.
The default value is the value specified in the 'settings' section.
* 'pin_subdomains' specifies whether the 'includeSubdomains' directive should be included in the HPKP headers.
The default value is the value specified in the 'settings' section.

Example:

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
                "ecparam_curve": "secp384r1",
                "key_size": 4096,
                "expiration_days": 730,
                "hpkp_days": 30,
                "pin_subdomains": true
            }
        }
    }


### Private Keys

This section defines the set of private keys generated and their associated certificates.
Multiple certificates may share a single private key.
This is useful when it is desired to use different certificates for certain subdomains,
while specifying HPKP headers for a root domain that also apply to subdomains.

The name of each private key is used as the file name for the private key files.

Note that a certificate configured in the 'certificates' section is equivalent to a private key configured in this section with a single certificate using the same name as the private key.
As such, it is an error to specify a certificate using the same name in both the 'certificates' and 'private_keys' sections.

The private key and certificate settings are identical to those specified in the 'certificates' section,
except settings relevant to the private key: 'key_size', 'expiration_days', 'hpkp_days', and 'pin_subdomains' are specified in the private key object rather than the certificate object.

Example:

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
                        "services": ["nginx"]
                        "dhparam_size": 2048,
                        "ecparam_curve": "secp384r1"
                    },
                    "mail.example.com": {
                        "alt_names": {
                            "example.com": ["mail", "smtp"]
                        },
                        "services": ["dovecot", "postfix"],
                    }
                },
                "key_size": 4096,
                "expiration_days": 730,
                "hpkp_days": 30,
                "pin_subdomains": true
            }
        },
        ...
    }

The above example will generate a single primary/backup private key set and two certificates, 'example.com' and 'mail.example.com' both using the same private key.


### TLSA Records

When using remote DNS updates,
it is possible to have the tool automatically maintain TLSA records for each certificate.
Note that this requires configuring zone update keys for each zone containing a TLSA record.

When using local DNS updates, the 'reload_zone' command will be called after certificates are issued, renewed, or modified to allow TLSA records to be updated by a tool such as [bindtool].
The 'reload_zone' command will not be called in slave mode.

To specify TLSA records, add a 'tlsa_records' name/object pair to each certificate definition, either in the 'certificates' or 'private_keys' section.
TLSA records are specified per DNS zone, similar to 'alt_names',
to specify which zone should be updated for each TLSA record.

Each TLSA record maye be a simple pair of host name and a list of ports,
or a host name and an object specifying further options.

* 'ports' specifies the port number for the TLSA record.
The default value is '443'.
The port for each record may be a single integer or a list of integers to create records for multiple ports.
* 'usage' is one of the following: 'pkix-ta', 'pkix-ee', 'dane-ta', or 'dane-ee'.
The default value is 'pkix-ee'.
When specifying an end effector TLSA record ('pkix-ee' or 'dane-ee'),
the hash generated will be of the certificate or public key itself.
When specifying a trust anchor TLSA record ('pkix-ta' or 'dane-ta'),
records will be generated for each of the intermediate and root certificates.
* 'selector' is one of the following: 'cert', or 'spki'.
The default value is 'spki'.
When specifying a value of 'spki' and an end effector usage,
records will be generated for both the primary and backup public keys.
* 'protocol' specifies the protocol for the TLSA record.
The default value is 'tcp'.
* 'ttl' specifies the TTL value for the TLSA records.
The default value is '300'.

Example:

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
                            "example.com": {
                                "@": 443,
                                "www": {
                                    "ports": 443,
                                    "usage": "pkix-ee",
                                    "selector": "spki",
                                    "protocol": "tcp",
                                    "ttl": 300
                                }
                            }
                        }
                    },
                    "mail.example.com": {
                        "alt_names": {
                            "example.com": ["mail", "smtp"]
                        },
                        "services": ["dovecot", "postfix"],
                        "tlsa_records": {
                            "example.com": {
                                "mail": 993,
                                "smtp": {
                                    "ports": [25, 465, 587],
                                    "usage": "dane-ee"
                                }
                            }
                        }
                    }
                }
            }
        },
        ...
    }


### Authorizations

This section specifies a set of host name authorizations to obtain without issuing certificates.

This is used when running in a master/slave configuration,
the master having access to local or remote DNS updates or an HTTP server,
obtains authorizations,
while the slave issues the certificates.

It is not necessary to specify host name authorizations for any host names used by configured certificates,
but it is not an error to have overlap.

Authorizations are specified per DNS zone so that associated DNS updates happen in the correct zone.

Simplar to 'alt-names', a host name of '@' may be used to specify the zone name.

Example:

    {
        "example.com": ["@", "www"]
    }


### HTTP Challenges

By default, the tool will attempt DNS-01 domain authorizations for every alternative name specified,
using local or remote DNS updates.

To use HTTP-01 authorizations instead,
configure the 'http_challenges' section of the configuration file specifying a challenge directory for each fully qualified domain name.

It is possible to mix usage of DNS-01 and HTTP-01 domain authorizations on a host by host basis,
simply specify a http challenge directory only for those hosts requiring HTTP-01 authentication.

Example:

    {
        ...
        "http_challenges": {
            "example.com": "/var/www/htdocs/.well-known/acme-challenge"
            "www.example.com": "/var/www/htdocs/.well-known/acme-challenge"
        }
    }

The 'http_challenges' must specify a directory on the local file system such that files placed there will be served via an already running http server for each given domain name.
In the above example,
files placed in '/var/www/htdocs/.well-known/acme-challenge' must be publicly available at:
http://example.com/.well-known/acme-challenge/file-name
and
http://www.example.com/.well-known/acme-challenge/file-name


### Zone Update Keys

When using remote DNS updates,
it is necessary to specify a TSIG key used to sign the update requests.

For each zone using remote DNS udpates,
specify either a string containing the file name of the TSIG key,
or an object with further options.

The TSIG file name may an absolute path or a path relative to the 'update_key' directory setting.
Both the &lt;key-name&gt;.key file and the &lt;key-name&gt;.private files must be present.

Any zone referred to in a certificate, private key, or authorization that does not have a corresponding zone update will use local DNS updates unless an HTTP challenge directory has been specified for every host in that zone.

* 'file' specifies the name of the TSIG key file.
* 'server' specified the name of the DNS server to send update requests to.
If omitted, the primary name server from the zone's SOA record will be used.
* 'port' specifies the port to send update requests to.
The default value is '53'.

Example:

    "zone_update_keys": {
        "example1.com": "update.example1.com.key",
        "example2.com": {
            "file": "update.example2.com.key",
            "server": "ns1.example2.com",
            "port": 53
        }
    }


## Configuring Local DNS Updates

In order to perform DNS-01 authorizations,
and to keep TLSA records up to date,
the tool will need to be able to add, remove, and update various DNS records.

For updating DNS on a local server,
this tool was designed to use a bind zone file pre-processor,
such as [bindtool],
but may be used with another tool instead.

When using [bindtool], be sure to configure bindtool's 'acme_path' to be equal to the value of the 'challenge' directory, so that it can find the ACME challenge files.

When the tool needs to update a DNS zone, it will call the configured 'reload_zone' command with the name of the zone as its argument.
When _acme-challenge records need to be set, a file will be placed in the 'challenge' directory with the name of the zone in question, e.g. '/etc/ssl/challenges/example.com'.
The challenge file is a JSON format file containing a single object.
The name/value pairs of that object are the fully qualified domain names of the records needing to be set, and the values of the records, e.g.:

    {
        "www.example.com": "gfj9Xq...Rg85nM"
    }

Which should result in the following DNS record created in the zone:

    _acme-challenge.www.example.com. 300 IN TXT "gfj9Xq...Rg85nM"

If there is no file in the 'challenge' directory with the same name as the zone, all _acme-challenge records should be removed.

Any time the 'reload_zone' is called, it should also update any TLSA records asscoiated with the zone based on the certificates or private keys present.

All of these functions are provided automatically by [bindtool] via the use of '{{acme:}}' and '{{tlsa:}}' commands in the zone file.
For example, the zone file:

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

Will define the zone 'example.com' using the nameservers 'ns1.example.com' and 'ns1.example.com', providing the hosts 'example.com' and 'www.example.com', with TLSA records pinning the primary and backup keys.


## Configuring Remote DNS Updates

If the tool is not run on a machine also hosting a DNS server, then HTTP-01 authorizations or remote DNS updates must be used.

The use remote DNS udpates via RFC 2136 dynamic updates,
configure a zone update key for each zone.
See the Zone Update Keys section for more information.

It is also necesary to have the 'nsupdate' tool installed and the 'nsupdate_command' configured in the 'settings' configuration section.

Zone update keys may be generated via the 'dnssec-keygen' tool.

For example:

    dnssec-keygen -r /dev/urandom -a HMAC-MD5 -b 512 -n HOST update.example.com

will generate two files, named Kupdate.example.com.+157+NNNNN.key and Kupdate.example.com.+157+NNNNN.private.
Specify the .key file as the zone update key.

To configure bind to allow remote DNS updates, add an entry to named.conf.keys for the update key containg the key value from the private key file, e.g.

    key update.example.com. {
        algorithm hmac-md5;
        secret "sSeWrBDen...9WESlnEwQ==";
    };

and then add an 'allow-update' entry to the zone configuration, e.g.:

    zone "example.com" {
        type master;
        allow-update { key update.example.com.; };
        ...
    };


## Running the Tool

On first run, the tool will generate a client key,
register that key with the certificate authority,
accept the certificate authority's terms and conditions,
perform all needed domain authorizations,
generate private keys,
issue certificates,
install certificate and key files,
update TLSA records,
and reload services associated to the certificates.

Each subsequent run will ensure that all authorizations remain valid,
check if any backup private keys are past their expiration date,
check if any certificate's expiration dates are within the renewal window,
or have changes to the configured common name, or subject alternative names,
or no longer match their associated private key files.

If a backup private key has passed its expiration date,
the tool will emit a warning recommending that the private key be rolled over,
see the Private Key Rollover section for more information.

If a certificate needs to be renewed or has been modified,
the certificate will be re-issued and reinstalled.

When certificates are issued or re-issued,
TLSA record updates will be attempted and associated services will be reloaded.

All certificates and private keys will normally be processed on each run,
to restrict processing to specific private keys (and their certificates),
you can list the names of the private keys to process on the command line.


### Daily Run Via cron

In order to ensure that certificates in use do not expire,
it is recommended that the tool be run at least once per day via a cron job.

By default, the tool only generates output when actions are taken making it cron friendly.
Normal output can be supressed via the '--quiet' command line option.

Example cron entry, in file /etc/cron.d/acmebot:

    MAILTO=admin@example.com

    20 0 * * * root /etc/ssl/acmebot

This will run the tool as root every day at 20 minutes past midnight.
Any output will be mailed to admin@example.com


### Output Options

Normally the tool will only generate output to stdout when certificates are issued or private keys need to be rolled over.
More detailed output can be obtained by using either '--debug' or '--verbose' options on the command line.

Normal output may be supressed by using the '--quiet' option.

Error and warning output will be sent to stderr and cannot be supressed.


### Private Key Rollover

During normal operations the private keys for certificates will not be modified,
this allows renewing or modifying certificates without the need to update associated pinning information,
such as HPKP headers or TLSA records using spki selectors.

However, it is a good security practice to replace the private keys at regular intervals,
or immediately if it is believed that the primary private key may have been compromised.
This tool maintains a backup private key for each primary private key and generates pinning information including the backup key as appropriate to allow smooth transitions to the backup key.

When the backup private key reaches the age specified via the 'expiration_days' setting,
the tool will notify you that it is time to rollover the private key.

The rollover process will archive the current primary private key,
re-issue certificates using the existing backup key as the new primary key,
generate a new backup private key,
and reset HPKP headers and TLSA records as appropriate.

To rollover private keys, simply run the tool with the '--rollover' option.
You can specify the names of individual private keys on the command line to rollover,
otherwise all private keys will be rolled over.

Note that the tool will refuse to rollover a private key if the current backup key is younger than the HPKP duration.
A private key rollover during this interval may cause a web site to become inaccessable to clients that have previously cached HPKP headers but not yet retrieved the current backup key pin.
If it is necessary to rollover the private key anyway,
for example if it is believed that the backup key has been compromised as well,
add the '--force' option on the command line to force the private key rollover.


### Forced Certificate Renewal

Normally certificates will be automatically renewed when the tool is run within the certificate renewal window,
e.g. within 'renewal_days' of the certificate's expiration date.
To cause certificates to be renewed before this time,
run the tool with the '--renew' option on the command line.


### Revoking Certificates

Should it become necessary to revoke a certificate,
for example if it is believed that the private key has been compromised,
run the tool with the '--revoke' option on the command line.

When revoking certificates, as a safety measure,
it is necessary to also specify the name of the private key (or keys) that should be revoked.
All certificates using that private key will be revoked,
and the certificate files and the primary private key file will be moved to the archive.

The next time the tool is run after a revocation,
any revoked certificates will automatically perform a private key rollover.


## Master/Slave Setup

In some circumstances, it is useful to run the tool in a master/slave configuration.
In this setup, the master performs domain authorizations,
while the slave issues and maintains certificates.

This setup is useful when the slave machine doesn not have the ability to perform domain authorizations,
for example, an XMPP server behind a firewall that does not have port 80 open or access to a DNS server.

To create a master/slave setup,
first install and configure the tool on the master server as normal.
The master server may also issue certificates, but it is not necessary.

Configure any required domain authorizations (see the Authorizations section) on the master and run the tool.

Then install the tool on the slave server.
It is not necessary to configure HTTP challenges or remote DNS update keys on the slave.

Before running the tool on the slave server,
copy the client key and registration files from the master server.
These files are normally found in '/var/local/acmebot' but an alternate location can be configured in the 'resource' directory setting.

If the master server also issues certificates for the same domain names or parent domain names as the slave,
you may want to copy the primary and backup private keys for those certificates to the slave.
This will cause the slave certificates to use the same keys allowing HPKP headers to safey include subdomains.

Set the slave 'slave_mode' setting to 'true' and configure desired certifiacates on the slave.

Run the tool on the slave server.

When setting up cron jobs for the master and slave, be sure the slave runs several minutes after the master.
The master can theoretically take 'max_dns_lookup_attempts' x 'dns_lookup_delay' + 'max_authorization_attempts' x 'authorization_delay' seconds to obtain domain authorizations (15 minutes at the default settings).

It is possible to run several slave servers for each master,
the slave cron jobs should not all run at the same time.

The slave server may maintain TLSA records if remote DNS updates are configured on the slave,
otherwise it is recommended to use 'spki' selectors for TLSA records so that certificate renewals on the slave will not invalidate TLSA records.

If private keys are shared between a master and slave,
be sure to only perform private key rollovers on the master and copy new private key files to the slaves after the rollover.

The slave will automatically detect the new private key and re-issue certificates on the next run.



