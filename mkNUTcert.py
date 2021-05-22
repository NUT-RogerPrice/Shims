#!/usr/bin/python3 -u
# mkNUTcert Make a self-signed TLS private key and public key for NUT.
# RFC5280 chap 3.2 :
# Starting with the public key of a CA in a user's own domain has certain
# advantages.  In some environments, the local domain is the most trusted.
# Copyright (C) 2020 Roger Price. GPL v3 or later at your choice.
'''mkNUTcert: Make a self-signed TLS private key and public key for NUT'''
mkNUTcert_version = '1.0'

# Changes
# 2020-11-27 RP OS ID improvement
# 2021-05-11 RP monitor -> client

# We need some library stuff
import argparse, OpenSSL, re, socket, ssl, sys, subprocess

# Known to work for Python 3.4
if sys.version_info[0] >= 3 and sys.version_info[1] >= 4 : pass
else :
  msg = '\tMessage 50: This program requires Python version 3.4 or later.\n'\
        '\tYou are using version {}.'\
        .format(sys.version.replace('\n',''))
  print(msg, file=sys.stderr, flush=True)
  exit(1)

#############################################################################################
#                                   Functions
#############################################################################################
#############################################################################################
# Function do_command takes a command and its options in a list of strings,
# and returns stdout, stderr as iterable list of lines of utf-8 text.
# The command may be specified as a list of strings or as a single string.
# E.g. stdout, stderr = do_command(['/bin/bash', '-s', 'ls', '-alF'])
#      stdout, stderr = do_command('ls -l .')
#      if not stdout == None :
#        for line in stdout :
# If error, displays message before returning stdout and stderr.
# It would be better to use shlex.split(command_line_string)
def do_command (arglist, use_shell=False) :
  try :
    # Execute the command
    RC = subprocess.Popen(arglist, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=use_shell)
    bstdout, bstderr = RC.communicate()
    if bstdout == None : stdout = None
    else : stdout = re.split('\n',bstdout.decode("utf-8"))     # Convert bytes to iterable lines of text
    if bstderr == None : stderr = None
    # Convert bytes to iterable lines of text and remove '' elements from list
    else : stderr = [x for x in re.split('\n',bstderr.decode("utf-8")) if x != '']
    # Handle error output from command
    if stderr != [] :
      msg = (('Error 585: do_command receives error message when calling\n'\
              '\t {}\n'\
              '\t stderr = {}\n'\
              '\t Continuing ...')\
             .format(string_list_to_string(arglist), stderr))
      print(msg, file=sys.stderr, flush=True)
    return stdout, stderr                 # Official exit from this function
  # Subprocess problems
  except Exception as ex :
    msg = ('Error 590: do_command error: Unable to execute command\n'\
           '\t {}\n'\
           '\t Reason: {}\n'\
           '\t Continuing ...')\
           .format(arglist, ex)
    print(msg, file=sys.stderr, flush=True)
    return None, None

#############################################################################################
# Try to find an identifier for the Linux OS
# Returns opensuse, fedora, debian, ... or None
# See http://0pointer.de/blog/projects/os-release for background
def get_OS_id () :
  stdout_list, stderr_list = do_command(['uname', '-a'])  # -a needed for synology
  if stdout_list == None : return None    # uname failed
  if stderr_list == None : return None
  if stderr_list != [] : return None
  line = stdout_list[0].lower()
  if re.match(r'(?i).*aix.*',  line)        : return 'aix'
  if re.match(r'(?i).*darwin.*',  line)     : return 'darwin'
  if re.match(r'(?i).*freebsd.*', line)     : return 'freebsd'
  if re.match(r'(?i).*hp-ux.*',  line)      : return 'hpux'
  if re.match(r'(?i).*ipfire.*',  line)     : return 'ipfire'
  if re.match(r'(?i).*mac.*',  line)        : return 'mac'
  if re.match(r'(?i).*netbsd.*',  line)     : return 'netbsd'
  if re.match(r'(?i).*openbsd.*', line)     : return 'openbsd'
  if re.match(r'(?i).*openindiana.*', line) : return 'openindiana'
  if re.match(r'(?i).*synology.*',  line)   : return 'synology'
  if re.match(r'(?i).*linux.*', line) :
    try :
      with open('/etc/os-release', 'r') as fd :
        lines = fd.readlines()            # A list of lines, each ending with \n
        for line in lines :
          m = re.match(r'ID=(.*)$', line)
          if m : return m.group(1).lower() # E.g. debian
        return None                       # No ID in os-release
    except Exception :
      try :
        with open('/etc/gentoo-release', 'r') as fd :
          return 'gentoo'
      except Exception : return None      # No *-release
  msg = ('Error 620: get_OS_id error: I do not recognize uname result {}\n'\
         '\t Continuing ...').format(stdout_list[0])
  print(msg, file=sys.stderr, flush=True)
  return None                             # Unknown uname

# Try to find out which non-root user runs the upsd daemon, and
# where the NUT configuration files are placed.
# Returns (user, directory)
def get_NUT_install_params () :
  OS_id = get_OS_id()                     # E.g. debian or None
  try :
    ud = {'aix':         ('nut',   '/etc/nut/'), # IBM AIX
          'amzn':        ('nut',   '/etc/ups/'), # Amazon Linux
          'arch':        ('nut',   '/etc/nut/'),
          'centos':      ('nut',   '/etc/ups/'),
          'darwin':      ('nut',   '/etc/nut/'),
          'debian':      ('nut',   '/etc/nut/'),
          'fedora':      ('nut',   '/etc/ups/'), # Includes Scientific Linux
          'freebsd':     ('uucp',  '/usr/local/etc/nut/'), # Includes FreeNAS
          'gentoo':      ('nut',   '/etc/nut/'),
          'hpux':        ('nut',   '/etc/nut/'), # HP-UX ? ?
          'ipfire':      ('nutmon','/etc/nut/'), # IPFire
          'kali':        ('nut',   '/etc/nut/'), # Similar to Debian
          'linuxmint':   ('nut',   '/etc/nut/'), # Close to Ubuntu
          'mac':         ('nut',   '/etc/nut/'),
          'mageia':      ('nut',   '/etc/nut/'), # Similar to Fedora
          'manjaro':     ('nut',   '/etc/nut/'),
          'netbsd':      ('nut',   '/etc/nut/'),
          'ol':          ('nut',   '/etc/ups/'), # Oracle Linux
          'openbsd':     ('ups',   '/etc/nut/'),
          'openindiana': ('nut',   '/etc/nut/'),
          'opensuse':    ('upsd',  '/etc/ups/'),
          'raspbian':    ('nut',   '/etc/nut/'),
          'rhel':        ('nut',   '/etc/ups/'),
          'slackware':   ('nut',   '/etc/nut/'),
          'sles':        ('upsd',  '/etc/ups/'), # SuSE Enterprise Linux
          'sles_sap':    ('upsd',  '/etc/ups/'), # SuSE Enterprise Linux
          'synology':    ('root',  '/usr/syno/etc/ups/'),
          'ubuntu':      ('nut',   '/etc/nut/'),
          None:          ('nut',   '/etc/nut/')}[OS_id]
    return ud
  except Exception : return ('nut', '/etc/nut/')  # Most likely configuration

#############################################################################################
#                                   Main program
#############################################################################################
# Assume that this program is being run in the system running upsd.
# Who are we ?
try : hostname = socket.gethostname()     # PEP8 look away
except Exception : hostname = 'upsd'
bhostname = bytes(hostname, 'utf-8')      # X509 likes bytes

# Try to guess where things go in this system
default_user, etc_dir = get_NUT_install_params()

argparser = argparse.ArgumentParser(
  description = 'mkNUTcert.py is a Python3 script to build TLS private key, self-signed CA'
                '  certificate and certificates for the clients that will access upsd.'
                '  Status: "experimental".  Intended for demonstration and experiment.',
  epilog = 'License: GPL v3 or later at your choice.\n'
           'Support: nut-upsuser mailing list.\n'
           'Documentation: http://rogerprice.org/NUT/ConfigExamples.A5.pdf')
# CN commonName not used
argparser.add_argument('-SAN', '--subjectAltName',        nargs=1,
                       default=hostname+' localhost 10.218.0.19 '+hostname+'.example.com',
                       help='Space separated list of names of the upsd server, default "%(default)s".',
                       metavar='<list of server names>')
argparser.add_argument('-C', '--countryName',             nargs=1,
                       default='FR',
                       help='2 digit country code, default "%(default)s".',
                       metavar='<ISO 3166 two letters>')
# ST stateOrProvinceName not used
# L  localityName not used
argparser.add_argument('-O', '--organisationName',        nargs=1,
                       default='Network UPS Tools',
                       help='Organisation name, default "%(default)s".',
                       metavar='<name>')
argparser.add_argument('-OU', '--organisationUnitName',   nargs=1,
                       default='mkNUTcert.py version '+mkNUTcert_version,
                       help='Organisation unit name, default "%(default)s".',
                       metavar='<unit name>')
argparser.add_argument('--serialNumber',                  nargs=1,
                       default=1,
                       help='Serial number, default "%(default)s".',
                       metavar='<integer>')
argparser.add_argument('--notBefore',                     nargs=1,
                       default=0,
                       help='Validity start time, default %(default)s, i.e. now.',
                       metavar='<integer>')
argparser.add_argument('--notAfter',                      nargs=1,
                       default=0,  # For 10 years, set 10 * 366 * 24 * 60 * 60
                       help='Validity end time in seconds from now, default %(default)s, i.e. indefinite validity.',
                       metavar='<integer>')
argparser.add_argument('-s', '--servercertfile',          nargs=1,
                       default=etc_dir+'mkNUTcert/'+hostname+'.cert.pem',
                       help='File path and name for the server\'s certificate.  Default %(default)s',
                       metavar='<filename>')
argparser.add_argument('-c', '--clientcertfile',          nargs=1,
                       default=etc_dir+'mkNUTcert/'+hostname+'-client.cert.pem',
                       help='File path and name for the client\'s certificate.  Default %(default)s'\
                            ' All the clients of the upsd server use this certificate.',
                       metavar='<filename>')
argparser.add_argument('-v', '--version', action='version',
                       help='Show program, Python and SSL/TLS versions, then exit.',
                       version='%(prog)s {}, with SSL/TLS support: {}, '\
                               'running on Python {}'
                       .format(mkNUTcert_version, ssl.OPENSSL_VERSION,\
                               sys.version.replace('\n','')))
args = argparser.parse_args()

# Provide the default values if arguments were omitted.  This is made coplex because
# args.xxxxx has form [('127.0.0.1', 401)] if specified, ('127.0.0.1', 401) if default
subjectAltName   = args.subjectAltName[0]   if isinstance(args.subjectAltName, list)   else args.subjectAltName
countryName      = args.countryName[0]      if isinstance(args.countryName, list)      else args.countryName
organisationName = args.organisationName[0] if isinstance(args.organisationName, list) else args.organisationName
organisationUnitName = args.organisationUnitName[0] if isinstance(args.organisationUnitName, list) else args.organisationUnitName
serialNumber     = args.serialNumber[0]     if isinstance(args.serialNumber, list)     else args.serialNumber
notBefore        = args.notBefore[0]        if isinstance(args.notBefore, list)        else args.notBefore
notAfter         = args.notAfter[0]         if isinstance(args.notAfter, list)         else args.notAfter
servercertfile   = args.servercertfile[0]   if isinstance(args.servercertfile, list)   else args.servercertfile
clientcertfile   = args.clientcertfile[0]   if isinstance(args.clientcertfile, list)   else args.clientcertfile

print('\n          mkNUTcert\n\n'\
      '  This script builds private and public X509 keys, to be used in\n'\
      '  a PKI (Public Key Infrastructure) customised for NUT.  It\n'\
      '  provides self signed certificates for use on a upsd server and\n'\
      '  on clients which monitor the server.\n')

# Hint: You can look at generated file using openssl:
# openssl x509 -inform pem -in selfsigned.cert -noout -text

########################################################################
# Create a private key and CA certificate
key = OpenSSL.crypto.PKey()
key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

# Create a self-signed Certifying Authority certificate
CAcert = OpenSSL.crypto.X509()
CAcert.set_version(2)                       # X509 version 3 1996
CAcert.get_subject().C = countryName
CAcert.get_subject().O = organisationName
CAcert.get_subject().OU = organisationUnitName
CAcert.set_serial_number(int(serialNumber))
CAcert.gmtime_adj_notBefore(int(notBefore))
if int(notAfter) == 0 :
  CAcert.set_notAfter(b'99991231235959Z')     # Permanent, as per RFC 5820 4.1.2.5
else :
  CAcert.gmtime_adj_notAfter(int(notAfter))   # 10 years: 10 * 366 * 24 * 60 * 60
# Use the Subject as the Issuer
CAcert.set_issuer(CAcert.get_subject())

# Extensions to X509 https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html
# See also RFC 5820 section 4.2
# Build subjectAltName declaration from subjectAltName space seperated list.
# If the DNS: are missing, you'll get a missing value error.  Documented?  You must be joking.
SAN = 'DNS:'+', DNS:'.join(subjectAltName.split())
bSAN = bytes(SAN, 'utf-8')

# OpenSSL.crypto.X509Extension(type_name, critical, value, subject=None, issuer=None)
# Only one instance of each extension allowed.
CAcert.add_extensions(
  [OpenSSL.crypto.X509Extension(b"basicConstraints", True, b'CA:TRUE'),
   OpenSSL.crypto.X509Extension(b"subjectAltName", False, bSAN),
   OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=CAcert)])

CAcert.set_pubkey(key)                      # Identify private key used in CA certificate ?
CAcert.sign(key, 'sha512')

# PEM encoding of key and CA cert
key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key).decode("utf-8")
CAcert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, CAcert).decode("utf-8")

########################################################################
# Wtite key and certificates to disk

# Announce the files to be created
msg = ('   I am about to create the following files.\n'\
       '   These files will overwrite any previous files.\n'\
       ' * Private key with self-signed certificate for server in file {}\n'\
       ' * Certificate for the client in file {}\n')\
       .format(servercertfile, clientcertfile)
print(msg)
# Ask for confirmation before overwriting any previous files
confirm = input('Enter yes to proceed, anything else to exit: ').lower()
if confirm != 'yes' : exit(1)

# Write server private key and certificate in that orer to disk
print('\nWriting key with self-signed certificate for server to file {} ...'.format(servercertfile))
try :
  with open(servercertfile, "wt") as fd :
    fd.write(key_pem)
  with open(servercertfile, "at") as fd :
    fd.write(CAcert_pem)
except Exception as ex:
  msg = ('Error 30: I cannot write into private key file {}\n'\
         '          Reason: {}\n'\
         '          Have you declared the directory?')\
         .format(servercertfile, ex)
  print(msg) ; exit(1)
print('This file must be protected.  E.g. do not make it world readable.')
print('Suggested owner is {}:root with permissions 660.'.format(default_user))

# Write user certificate for client to disk
print('\nWriting user certificate for client to file {} ...'.format(clientcertfile))
try :
  with open(clientcertfile, "wt") as fd :
    fd.write(CAcert_pem)
except Exception as ex :
  msg = ('Error 40: I cannot write into public key file {}\n'\
         '          Reason: {}\n'\
         '          Have you declared the directory?')\
         .format(clientcertfile, ex)
  print(msg) ; exit(1)
print('The user (i.e. client) certificate should be installed in all monitors.')
print('Suggested owner is {}:root with permissions 644.\n'.format(default_user))

exit(0)

# Adieu


