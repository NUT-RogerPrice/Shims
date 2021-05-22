#!/usr/local/bin/python3.8 -u
# upsmonTLS.py A shim daemon which is placed in front of upsmon to provide up to date TLS support.
# Copyright (C) 2020 Roger Price. GPL v3 or later at your choice.
'''upsmonTLS: Shim daemon provides up to date TLS access to upsd'''
Version='1.0'

# Version 1.1 Changes:
# 2021-02-07 RP Added function isempty to clarify Pythonism
# 2021-05-08 RP recv_response becomes protocol aware
# 2021-05-11 RP monitor -> client

# We need some library stuff
import argparse, datetime, getpass, inspect, os, pathlib, pwd
import re, signal, select, socket, ssl, subprocess, sys, syslog, time
if sys.version_info[0] >= 3 and sys.version_info[1] >= 5 : pass
else :
  msg='\tMessage 200: This program requires Python version 3.5 or later.\n'\
      '\tYou are using version {}.'\
      .format(sys.version.replace('\n',' '))
  print(msg, file=sys.stderr, flush=True)
  exit(1)

#############################################################################################
# Functions Functions Functions Functions Functions Functions Functions Functions Functions #
#############################################################################################
# Function isempty returns True if a string, list or dictionary is empty. None = empty.
# Makes use of Python wierdness.
def isempty (enumerable) :
  if enumerable : return False
  else :          return True
def isnotempty (enumerable) :
  if enumerable : return True
  else :          return False
def boolean (b) :
  if b : return True
  else : return False

#############################################################################################
# Function printer calls print to send string to stdout
# If stdout has been disconnected, do nothing
def printer (line) :
  if stderr_redirect : return 0
  print(line)

#############################################################################################
# Function eprinter calls print to send string to stderr
# If stderr has been disconnected, do nothing
def eprinter (line) :
  if stderr_redirect : return 0
  print(line, file=sys.stderr, flush=True)

#############################################################################################
# Function fnl () returns a string with a list of file names and line
# numbers of the point in the main program where it was called.
def fnl () :
  line_nums = []
  # https://docs.python.org/3/library/inspect.html
  current_frame = inspect.currentframe()
  all_frames = inspect.getouterframes(current_frame)
  for f in all_frames[1:] :
    top_frame = all_frames[-1]
    dir_file_name, lineno = f[1], f[2]
    file_name = re.split('/',dir_file_name)[-1]     # Remove directory.  Not used
    line_nums.append('{}'.format(lineno))
  del current_frame, all_frames, f, top_frame       # GC needs help with frames
  nums = line_nums[1:][::-1]                        # Avoid tracing fnl, reverse list
  return prog_name + '[' + DownArrow.join(nums) + ']'

# Function fnl_short () returns a string with the file name and line
# number of the point in the main program where it was called.
def fnl_short () :
  # https://docs.python.org/3/library/inspect.html
  current_frame = inspect.currentframe()
  all_frames = inspect.getouterframes(current_frame)
  top_frame = all_frames[-1]
  dir_file_name, lineno = top_frame[1], top_frame[2]
  del current_frame, all_frames, top_frame          # GC needs help with frames
  file_name = re.split('/',dir_file_name)[-1]       # Remove directory
  return '{}[{}]'.format(file_name, lineno)

#############################################################################################
# date_time_µsec Local time in ISO format       2019-09-09 17:35:53.968428
# Experience shows that one must test m.  I don't know what causes this.
def date_time_µsec () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\.([0-9][0-9][0-9]).*',datetime.datetime.now().isoformat())
  if m : return '{} {}.{}'.format(m.group(1), m.group(2), m.group(3))
  else : return '{} {}.{}'.format(None, None, None)

# date_time      Local time in ISO format       2019-09-09 17:35:53
def date_time () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\..*',datetime.datetime.now().isoformat())
  if m : return '{} {}'.format(m.group(1), m.group(2))
  else : return '{} {}'.format(None, None)

# date           Local day in ISO format        2019-09-09
def date () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\..*',datetime.datetime.now().isoformat())
  if m : return '{}'.format(m.group(1))
  else : return '{}'.format(None)

# System time including microseconds            2019-09-09.968428
def time_µsec () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\.([0-9][0-9][0-9]).*',datetime.datetime.now().isoformat())
  if m : return '{}.{}'.format(m.group(2), m.group(3))
  else : return '{}.{}'.format(None, None)

# System time in microseconds                    968428
def µsec () :
  m = re.match(r'([0-9-]+)[A-Z]([0-9:]+)\.([0-9][0-9][0-9]).*',datetime.datetime.now().isoformat())
  if m : return '{}'.format(m.group(3))
  else : return '{}'.format(None)

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
  if re.match(r'(?i).*aix.*', line)         : return 'aix'     # (?i) = ignore case
  if re.match(r'(?i).*darwin.*', line)      : return 'darwin'
  if re.match(r'(?i).*freebsd.*', line)     : return 'freebsd'
  if re.match(r'(?i).*hp-ux.*', line)       : return 'hpux'
  if re.match(r'(?i).*ipfire.*', line)      : return 'ipfire'
  if re.match(r'(?i).*mac.*', line)         : return 'mac'
  if re.match(r'(?i).*netbsd.*', line)      : return 'netbsd'
  if re.match(r'(?i).*openbsd.*', line)     : return 'openbsd'
  if re.match(r'(?i).*openindiana.*', line) : return 'openindiana'
  if re.match(r'(?i).*synology.*', line)    : return 'synology'
  if re.match(r'(?i).*linux,*', line) :
    try :
      with open('/etc/os-release', 'r') as fd :
        lines = fd.readlines()            # A list of lines, each ending with \n
        for line in lines :
          m = re.match(r'ID=(.*)$', line) # E.g. ID=Raspbian
          if m : return m.group(1).lower() # E.g. raspbian
        return None                       # No ID in os-release
    except Exception :
      try :
        with open('/etc/gentoo-release', 'r') as fd :
          return 'gentoo'
      except Exception : return None      # No *-release
  msg = ('Error 200: get_OS_id error: I do not recognize uname result {}\n'\
         '\t Continuing ...').format(stdout_list[0])
  eprinter(msg) ; logger(msg)
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
# Utility function logger appends line l to the log file
# provided that the current debug level is greater than or equal
# to d.  If d is omitted everything is logged.
# Function logger behaves like function print and automatically adds a \n
# at the end of the line.
# Log file log is kept permanently open in append mode.
# Messages are instantly flushed so log is safely wriiten to disk
#  even if we use kill to stop the daemon.
def logger (l, d=0) :
  global log, log_inode                   # pylint: disable=global-statement
  # Before we start, a sanity check
  if isinstance(d, int) : pass
  else:
    msg = ('{} Error 210: Internal error\n'\
          +tab+'Type error in call to function logger("{}",{})\n'\
          +tab+'type({}) = {}\n'\
          +tab+'This may be due to writing ",format" instead of ".format"\n'\
          +tab+'Exiting ...').format(blob, l, d, d, type(d))
    eprinter(msg); cleanup(); exit(1)

  # Is the log file available?
  if not log_file_open : return 0

  # Has logrotate changed the inode of the log file ?
  if os.stat(log_file).st_ino == log_inode :  new_inode_flag = '' # Marker for new file handle
  else :
    log.close()                           # Old file handle dead
    # Reopen a file for logging as the user who will run the server
    log, log_inode = open_log_file(log_file, os.getuid(), os.getgid())   # Opened for current user
    new_inode_flag = 'New inode {}. '.format(os.stat(log_file).st_ino)

  # And now, the logging action
  if debug >= d :
    # Friendly prefix for messages to the log file
    msg = '{} {} {}\n'.format(time_µsec(), fnl(), new_inode_flag+l)
    try :
      rc = log.write(msg)                 # Ensure data recorded on disk in case we use kill
      log.flush()                         # to stop the daemon.
    except Exception : rc = -1            # File may have been closed by unexpected exit
    return rc  # Returns number of characters written
  else : return 0
def Dlogger (l) : logger(l,1)
def DDlogger (l) : logger(l,2)

#############################################################################################
# Function open_log_file opens a file for logging
# The file owner will be uid, with group gid, e.g. upsd:daemon
# Returns tuple (log,log_inode)
# log_file  is the name of the file, e,g, /var/log/NUT.log
# log       is a Python class providing log.write(...)
# log_inode is the inode of the log file
# global tells the logger when logging is possible.
def open_log_file (log_file, uid, gid) :
  global log_file_open                    # pylint: disable=global-statement
  try :
    log = open(log_file, 'a')             # Opened for current user, re-open if user change
    log_file_open = True
    os.chmod(log_file, 0o664)
    os.chown(log_file, uid, gid)
    return (log, os.stat(log_file).st_ino)   # File handle and inode number
  except FileNotFoundError :
    eprinter(('{} Error 220: I cannot find log file {}\n'\
             +tab+'Exiting ...').format(blob,log_file))
    cleanup(); exit(3)
  except PermissionError :
    eprinter(('{} Error 230: I cannot open log file {}, permissions error.\n'\
             +tab+'Exiting ...').format(blob,log_file))
    cleanup(); exit(3)

#############################################################################################
# Read certificate and return as a pretty printed string.
# https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
# from pyasn1_modules import pem, rfc2459
# from pyasn1.codec.der import decoder
def pp_PEM (file, long=False) :
  regexp = r'^\s*[0-9a-f][0-9a-f]:'       # Matches a line of octets
  try :
    cert_txt = subprocess.check_output(["openssl", "x509", "-text", "-noout", "-in", file])
    pp_full = cert_txt.decode('utf-8')    # Result is a string
    if long : return pp_full              # Customer sees everything
    else :                                # Only the first line of the octets gets presented
      pp = []; first_octet_line = True
      for l in pp_full.split('\n') :
        if re.match(regexp,l) :           # True if octet line
          if first_octet_line : pp.append(l+' ...') ; first_octet_line = False
          else : first_octet_line = False
        else : pp.append(l) ; first_octet_line = True
      return '\n'.join(pp)
#      substrate = pem.readPemFromFile(fd)
#      cert_txt = pyasn1.codec.der.decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
#      return cert_txt.prettyPrint()
  except Exception as ex :
    msg = ('{} Error 240: pp_PEM unable to pretty print {}\n'\
           +tab+'Reason: {}')\
           .format(blob, file, ex)
    logger(msg); eprinter(msg)
    return None

#############################################################################################
# Pretty print a socket object.  Returns a string in brackets.
# Socket may be class socket.socket or ssl.SSLSocket
# Sockets to upsd are flagged.
def pp_sock (s, long=False) :
  try :              fd = s.fileno()
  except Exception : fd = -1              # Socket has been closed
  if s in [buddy_dict[i] for i in buddy_dict] :
    fd = str(fd) + ' (upsd)'              # Custom display for upsd's socket
  else : pass
  if s.__class__==ssl.SSLSocket :
    lb = lob+lwsb; rb = rwsb+rob          # E.g. ﴾...﴿ to highlight TLS wrapper
  else :
    lb = lwsb; rb = rwsb
  if long == True :
    try :              IP, port = s.getsockname()      # E.g. ('127.0.0.1', 401)
    except Exception : IP, port = (None, None)
    try :              peer_IP, peer_port = s.getpeername()  # E.g. ('127.0.0.1', 38700)
    except Exception : peer_IP = None; peer_port = None
    try :              blocking = s.getblocking()      # E.g. True
    except Exception : blocking = None
    try :              timeout = s.gettimeout()        # E.g. 3.0
    except Exception : timeout = None
#    pp = 'fd={} {}:{}->{}:{} bl={} to={}'\
#         .format(fd, IP, port, peer_IP, peer_port, blocking, timeout)
    pp = 'fd={} {}:{}->{}:{}'\
         .format(fd, IP, port, peer_IP, peer_port)
  else :
    pp = 'fd={}'.format(fd)
  return lb + pp + rb

# Pretty print a list of socket objects.  Returns a string.
def pp_sock_list (l, long=False) :
  if len(l) == 0 : return '[]'
  elif len(l) == 1 : return '['+pp_sock(l[0],long)+']'
  else :
    pp_list = [', '+pp_sock(s,long) for s in l[1:]]
    return '[' + pp_sock(l[0],long) + string_list_to_string (pp_list) + ']'

# Pretty print the buddy_dict directory
def pp_buddy_dict () :
  D = buddy_dict.copy()                   # Helper is destructive, so work on a copy.
  return '{' + pp_buddy_dict_helper(D) + '}'

def pp_buddy_dict_helper (D) :
  if len(D) == 0 : return ''
  elif len(D) == 1 :
    fd, y = D.popitem()
    return '{}:{}'.format(fd, pp_sock(y))
  else :
    fd, y = D.popitem()                   # Copy D now 1 item shorter
    return pp_buddy_dict_helper(D) + ', {}:{}'.format(fd, pp_sock(y))

# Pretty print the TLS_enabled_dict dictionary  {..., socket:bool, ...}
def pp_TLS_enabled_dict () :
  D = TLS_enabled_dict.copy()           # Helper is destructive, so work on a copy.
  return '{' + pp_TLS_enabled_dict_helper(D) + '}'

def pp_TLS_enabled_dict_helper (D) :
  if len(D) == 0 : return ''
  elif len(D) == 1 :
    fd, y = D.popitem()
    return '{}:{}'.format(fd, y)
  else :
    fd, y = D.popitem()                   # Copy D now 1 item shorter
    return pp_TLS_enabled_dict_helper(D) + ', {}:{}'.format(fd, y)

# Pretty print a string or byte code message.
# max is maximum size of displayd message
# Returns a string. with no trailing newlines
def pp_msg (msg, max=60) :
  if isinstance(msg, str) : smsg = msg
  else : smsg  = msg.decode('utf-8')
  s = no_trailing_newlines(smsg)
  ellipsis = '...'
  u = max - len(ellipsis)
  if len(s) > max :
    first = s[:u//2]                      # Use integers for indexing
    last = s[-u//2:]
    return first + ellipsis + last
  else : return s

#############################################################################################
# Simple queues using lists
# enqueue pushes value V into list Q
def enqueue (Q,V) :
  return Q.insert(0,V)

def dequeue (Q) :
  try :              V = Q.pop()
  except Exception : V = None
  return (V,Q)

#############################################################################################
# Define handler for SIGINT SIGQUIT SIGTERM: the daemon process shuts down.
# SIGHUP, SIGUSR1: action to be defined
# See https://docs.python.org/3/library/signal.html signal.signal for discussion
# of the two required arguments.
def SIG_handler(signum, frame) :
  logger('Signal handler called with signal {}'.format(signum))
  if   signum == signal.SIGINT  : SIG_called['INT'] = True
  elif signum == signal.SIGQUIT : SIG_called['QUIT'] = True
  elif signum == signal.SIGTERM :
    SIG_called['TERM'] = True             # Not used
    # Shut down
    logger('Shutting down on signal {}'.format(signum))
    cleanup(); exit(0)
  elif signum == signal.SIGHUP  : SIG_called['HUP'] = True
  elif signum == signal.SIGUSR1 : SIG_called['USR1'] = True
  else :
    logger('Cannot handle signal {}.  Ignoring.'.format(signum))

#############################################################################################
# syslogger sends text message to syslog with optional priority.
# E.g. syslogger('[crit] my_msg')
# Package syslog has priority levels (high to low):
# LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG.
# Default priority is LOG_INFO
# Syslogger levels: emerg, alert, crit, err, warning, notice, info, debug
def syslogger (message) :
  priority_dict = {'emerg':syslog.LOG_EMERG, 'alert':  syslog.LOG_ALERT,   'crit':  syslog.LOG_CRIT,
                   'err':  syslog.LOG_ERR,   'warning':syslog.LOG_WARNING, 'notice':syslog.LOG_NOTICE,
                   'info': syslog.LOG_INFO,  'debug':  syslog.LOG_DEBUG}
  m = re.match(r'^(\[(?P<a>emerg|alert|crit|err|warning|notice|info|debug)\])?[\ \t]*(?P<b>.*)',message)
  if m.group('a') : priority = priority_dict[m.group('a')]; content = m.group('b')
  else :            priority = syslog.LOG_INFO;             content = message
  try :
    syslog.syslog (priority, content)
  except Exception as ex :
    msg=('{} Error 250: syslogger error when using Python\n'\
         +tab+'syslog.syslog({},{})\n'\
         +tab+'Reason: {}')\
        .format(blob, priority, content, sys.exc_info()[:2])
    logger(msg); eprinter(msg)

#############################################################################################
# Function do_command takes a command and its options in a list of strings,
# and returns stdout, stderr as iterable list of lines of utf-8 text.
# The command may be specified as a list of strings or as a single string.
# E.g. stdout, stderr = do_command(['/bin/bash', '-s', 'ls', '-alF'])
#      stdout, stderr = do_command('ls -l .'])
#      if not stdout == None :
#        for line in stdout :
# If error, logs message before returning stdout and stderr.
# It would be better to use shlex.split(command_line_string)
def do_command (L, use_shell=False) :
  Dlogger('{} do_command({}, use_shell={}) type(L)={} ...'\
          .format(fnl(), L, use_shell, type(L)))
  try:
    # Execute the command
    RC = subprocess.Popen(L, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=use_shell)
    bstdout, bstderr = RC.communicate()
    DDlogger('... bstdout =\n{} bstderr = {}'\
             .format(bstdout.decode('utf-8'), bstderr.decode('utf-8')))
    if bstdout == None : stdout = None
    else : stdout = re.split('\n',bstdout.decode("utf-8"))     # Convert bytes to iterable lines of text
    if bstderr == None : stderr = None
    # Convert bytes to iterable lines of text and remove '' elements from list
    else : stderr = [x for x in re.split('\n',bstderr.decode("utf-8")) if x != '']
    # Handle error output from command
    if stderr != [] :
      Dlogger('do_command stderr[0]={}'.format(stderr[0]))
      if stderr[0][:8] == 'We trust' :
        msg = (('{} Warning 580: do_command receives warning message when calling\n'\
               +tab+'{}\n'\
               +tab+'stderr = {}\n'\
               +tab+'Continuing ...')\
               .format(blob, string_list_to_string(L), stderr))
        eprinter(msg) ; logger(msg)
      else :
        msg = (('{} Error 285: do_command receives error message when calling\n'\
               +tab+'{}\n'\
               +tab+'stderr = {}\n'\
               +tab+'Continuing ...')\
               .format(blob, string_list_to_string(L), stderr))
        eprinter(msg) ; logger(msg)
    return stdout, stderr                 # Official exit from this function
  # Subprocess problems
  except Exception as ex :
    msg = ('Error 290: do_command error: Unable to execute command\n'\
           '\t {}\n'\
           '\t Reason: {}\n'\
           '\t Continuing ...')\
           .format(L, ex)
    eprinter(msg) ; logger(msg)
    return None, None

#############################################################################################
# Relay command sends a command as a string on socket s to upsd,
# and returns the rc and the response as string.
# Parameter timeout supplies the timeout for the socket to upsd.
# Received and returned strings do not include \n
# E.g. rc, reply = (send_msg('VER',s)) => (n, '...' )
# Return code: 0=successful, 1=no bytes sent, 2=send socket exception, 3=send other exception,
#              4=recv socket exception 5=recv Unicode error, 6=recv other exception
# Errors from upsd have form "ERR reason" with rc=0.
# They are to be handled by the calling program.
def relay_cmd (command, s, timeout) :
  reply = '' ; reason = 'relay_cmd error'
  # Ensure that sent command is terminated by one single \n and is in byte form
  if isinstance(command, str) : byte_cmd = bytes(no_trailing_newlines(command)+'\n','utf-8')
  else :                        byte_cmd = no_trailing_newlines(command)+b'\n'
  # I want True or False not some Python wierdness
  is_list_cmd = boolean(re.match(b'^LIST\s', byte_cmd)) # pylint: disable=anomalous-backslash-in-string
  Dlogger('relay_cmd sending {} to {} is_list_cmd={}...'\
          .format(pp_msg(byte_cmd), pp_sock(s), is_list_cmd))
  try :
    byte_count = s.send(byte_cmd)         # Returns number of bytes sent
    if byte_count > 0 :       rc = 0
    else :                    rc = 1 ; ex = 'zero bytes sent'  # upsd dead?
  except socket.error :       rc = 2 ; ex = 'socket.error'
  except Exception :          rc = 3 ; ex = 'Problem in relay_cmd'
  if rc > 0 :
    Dlogger(('... relay_cmd: send rc = {},\n'\
             +tab+'Reason : {}\n'\
             +tab+'reply = {}')\
             .format(rc, reason, pp_msg(reply)))
    return (rc, reply)                    # (1,'') or (2,'')
  else :
    DDlogger('... relay_cmd sent {} to {}'.format(command, pp_sock(s)))

  # send was ok, now try for a recv from upsd
  reply = ''
  try :
    reply = no_trailing_newlines(recv_response(s, is_list_cmd, timeout).decode('utf-8'))
    rc = 0
  except Exception as ex :
    rc = 6                                # Even more bad news
    logger(('{} Error 300: relay_cmd error: recv exception\n'\
            +tab+'Reason:{}\n'\
            +tab+'Continuing with rc={}...')\
            .format(blob, ex, rc))
    return (rc,'')                        # (5,'')
  else :
    Dlogger('... relay_cmd: rc = {}, reply = {}'.format(rc, pp_msg(reply, max=200)))
    return (rc, reply)                    # (0,reply) or (rc,'')

# Function recv_response receives a reponse.
# LIST command: loops until it receives END LIST
# Not a LIST command: assume one and one only response message.
# Returns raw data as received.
# The -D option will log the exit code.
def recv_response (s, is_list_cmd, timeout) :
  Dlogger('Function recv_response({},{},{})'.format(pp_sock(s), is_list_cmd, timeout))
  s.setblocking(False)                    # Ensure socket is non blocking
  s.settimeout(timeout)                   # Ensure socket is non blocking
  total_data=[]                           # total_data received into a list of chunks
  chunk=''
  chunk_count = 0                         # How many non-empty chunks do we get ?
  begin = time.time()                     # Used for debugging
  exit_code = -10                         # Reason for deciding that we have seen the whole response
  cmd_or_resp = 'response' if s in [buddy_dict[i] for i in buddy_dict] else 'command'  # Used for debugging

  # Loop indefinitely until either END LIST received, or once only if not a LIST command
  while True :
    chunk_count = chunk_count + 1         # Counting those chunks
    try :
      chunk = s.recv(buf_size)
      type_chunk = type(chunk)            # For debugging
      len_chunk = len(chunk)              # For debugging
      total_data.append(chunk)            # Next piece of the list
      if is_list_cmd :                    # LIST command ?
        is_last_line = boolean(re.search(b'END LIST\s', chunk)) # pylint: disable=anomalous-backslash-in-string
        Dlogger(('recv_response receives {} from socket {}\n'\
                 +tab+'LIST chunk number {} length {} type {} is_last_line={}\n'\
                 +tab+'{}')\
                 .format(cmd_or_resp, pp_sock(s), chunk_count, len_chunk,\
                         type_chunk, is_last_line, pp_msg(chunk, max=200)))
        if is_last_line :
          exit_code = chunk_count
          break
        else : continue
      else :
        Dlogger(('recv_response receives {} from socket {} length {} type {}\n'\
                 +tab+'{}')\
                 .format(cmd_or_resp, pp_sock(s), len_chunk, type_chunk, pp_msg(chunk, max=200)))
        exit_code = 0
        break
    except socket.timeout :
      exit_code = -1
      Dlogger('recv_response socket.timeout is_list_cmd={} chunk_count={} exit_code={}'\
              .format(is_list_cmd, chunk_count, exit_code))
      break
    except Exception as ex:
      exit_code = -2
      msg=('{} Error 310: socket.recv error:\n'\
           +tab+'socket {}\n'\
           +tab+'Reason: {}\n'\
           +tab+'Continuing ...')\
           .format(blob, pp_sock(s, long=True), ex)
      logger(msg); eprinter(msg)

  # Join up the chunks to make hopefully complete response
  result = bytes_list_to_bytes(total_data, b'') # Join with no spacer
  elapsed_time = time.time() - begin      # How long did the recv take ?
  Dlogger(('recv_response received {} chunks in {:.3f} secs,'\
           ' exit_code={}')\
           .format(chunk_count, elapsed_time, exit_code))
  return result

# Function no_trailing_newlines removes all trailing newlines from a string,
# and returns a string.  Also works for byte strings.
def no_trailing_newlines (string) :
  if isinstance(string, str) : return string.rstrip ('\n')
  else : return string.rstrip (b'\n')

#############################################################################################
# Function string_list_to_string takes a list of strings and returns the elements as a string
# with interspacing blank as default separator.  E.g. ["Hello", "World"] -> "Hello World"
def string_list_to_string (L, sep=' ') :
  if len(L) == 0 : return ''
  elif len(L) == 1 : return L[0]
  else :
    S = L[0]
    for x in L[1:] : S += sep+x
    return S

# Function bytes_list_to_bytes takes a list of byte sequences and returns the elements as a byte
# sequence with interspacing blanks.  E.g. [b"Hello", b"World"] -> b"Hello World"
def bytes_list_to_bytes (L, sep=b' ') :
  if len(L) == 0 : return b''
  elif len(L) == 1 : return L[0]
  else :
    B = L[0]
    for x in L[1:] : B += sep+x
    return B

#############################################################################################
# function del_sock removes socket s from everywhere it is used
def del_sock (s) :
  fd = s.fileno()                         # Let's hope it exists
  s.close()
  if s in in_sock_list : in_sock_list.remove(s)
  if s in out_sock_list : out_sock_list.remove(s)
  if s in read_sock_list : read_sock_list.remove(s)
  if s in write_sock_list : write_sock_list.remove(s)
  if s in err_sock_list : err_sock_list.remove(s)
  if fd in buddy_dict :
    buddy_dict[fd].close()                # Close any socket to upsd
    del buddy_dict[fd]
  if fd in TLS_enabled_dict : del TLS_enabled_dict[fd]
  if fd in msg_q_dict : del msg_q_dict[fd]

#############################################################################################
# Cleanup on program exit
# What happens if there is no log file?
def cleanup() :
  cleanup_logger('Cleaning up ...')
  # Clean up the upsd logins
  if client_sock == None : pass
  else :
    cleanup_logger ('cleanup: Shutting down client socket (may not exist) ...')
    try : client_sock.shutdown(socket.SHUT_RDWR)
    except Exception : pass
    client_sock.close()
  # Clean up the buddy sockets to upsd
  Dlogger('cleanup: buddy_dict = {}'.format(pp_buddy_dict()))
  for fd in buddy_dict :
    try : f = buddy_dict[fd].fileno()     # Does this socket exist ?
    except Exception : continue           # No, skip to next
    cleanup_logger ('cleanup: Logging out from socket fd={} to upsd ...'\
                    .format(fd))
    rc, reply = relay_cmd('LOGOUT', buddy_dict[fd], upsdtimeout)
    cleanup_logger ('cleanup: Closing socket {} to upsd ...'\
                    .format(pp_sock(s)))
    buddy_dict[fd].close()

  # All cleaned up
  cleanup_logger('{} morituri te salutant {}\n'.format('#'*32, '#'*32))
  # Close log file
  try : log.close()                       # Close if open, also closes stdout, stderr
  except Exception : pass

# What happens if there is no log file?
def cleanup_logger(line) :
  # Does the log file exist?
  try :
    # Log file exists, we do logger's job
    rc = log.write('{} {} {}\n'.format(time_µsec(),fnl(),line))
    log.flush()                           # Get output into file
  except Exception :
    # No logging available, print to stderr
    eprinter (line)

#############################################################################################
#############################################################################################
#                                    Main program                                           #
#############################################################################################
#############################################################################################
prog_name = re.split('/',str(sys.argv[0]))[-1]  # E.g. upsdTLS.py
UpArrow = u"\u21B1"	# UPWARDS ARROW WITH TIP RIGHTWARDS 21B1 ↱
DownArrow = u"\u21B3"	# DOWNWARDS ARROW WITH TIP RIGHTWARDS 21B3 ↳
mlsb = '⟦'              # MATHEMATICAL LEFT WHITE SQUARE BRACKET (U+27E6, Ps)
mrsb = '⟧'              # MATHEMATICAL RIGHT WHITE SQUARE BRACKET (U+27E7, Pe)
lwsb = '〚'             # LEFT WHITE SQUARE BRACKET (U+301A, Ps): 〚 double width
rwsb = '〛'             # RIGHT WHITE SQUARE BRACKET (U+301B, Pe): 〛 double width
lwlb = '〖'             # LEFT WHITE LENTICULAR BRACKET (U+3016, Ps): 〖
rwlb = '〗'             # RIGHT WHITE LENTICULAR BRACKET (U+3017, Pe): 〗
lsb = '⸨'               # LEFT DOUBLE PARENTHESIS (U+2E28, Ps): ⸨
rsb = '⸩'               # RIGHT DOUBLE PARENTHESIS (U+2E29, Pe): ⸩
lob = '﴾'              # ORNATE LEFT PARENTHESIS (U+FD3E, Ps): ﴾
rob = '﴿'              # ORNATE RIGHT PARENTHESIS (U+FD3F, Pe): ﴿
fullblock = '█'        # FULL BLOCK (U+2588)
blob = fullblock*2
buf_size = 8192        # string buffer size for socket.recv

# Default values.  For more default values, see the argparser options.
NonBlocking = False                       # Server socket blocks?
stderr_redirect = False                   # Set after changing user
# Note on Python sockets:  There are two classes of sockets.  Basic socket and SSLSocket.  They have
# the same attributes, but not the same class.  We use sockets to index directories, but to avoid confusion
# the socket is identified by it's file number.
client_sock = None                        # Socket used to receive commands from UPSmon, upsc, ...
                                          # There should always be a client socket
buddy_dict = {}                           # Sockets to upsd {...,client_sock.fileno():server_sock.fileno(),...}
in_sock_list = []                         # Socket list inputs should never be empty.
upsd_sock = {}                            # Each upsd has a socket permanently open.  Addressed by (upsd_domain, upsd_port).
upsd_TLS = {}                             # Each upsd has TLS working, True/False.  Addressed by (domain, port).
out_sock_list = []                        # Socket list for outputs
msg_q_dict = {}                           # {..., socket.fileno():[V1,...,Vn], ...}
switch_IP_port = 'IP'                     # Function arg_listen internal
# INT, QUIT and TERM used to interrupt this program.  HUP and USR1 to be defined.
SIG_called = {'INT':False, 'QUIT':False, 'TERM':False, 'HUP':False, 'USR1':False}

# Since the logger may be called before the log file is opened
# we need a flag to say when the log file is/is not available.
log_file_open = False
# Has TLS been enabled ?  Could be deduced from buddy_dict but separate variable is clearer
TLS_enabled_dict = {}                     #  {..., fd:True, ...} where s is client socket file number

# An identifier for the Linux OS
OS_id = get_OS_id()
# Try to guess the non-root user and the configuration directories.
default_user, etc_dir = get_NUT_install_params ()  # E.g. ('debian', '/etc/nut')

try :              hostname = socket.gethostname()     # Name of the machine running upsd
except Exception : hostname = 'upsd'
# Indent for continuation lines
tab = ' '*len('{} '.format(time_µsec()))

# Dictionary of protocol number -> protocol name used in log messages
protocol_names = {ssl.PROTOCOL_TLS:'PROTOCOL_TLS',
                  ssl.PROTOCOL_TLS_SERVER:'PROTOCOL_TLS_SERVER',
                  ssl.PROTOCOL_TLS_CLIENT:'PROTOCOL_TLS_CLIENT',
#                  ssl.PROTOCOL_SSLv3:'PROTOCOL_SSLv3', # No longer available
#                  ssl.PROTOCOL_SSLv2:'PROTOCOL_SSLv2', # No longer available
                  ssl.PROTOCOL_TLSv1_2:'PROTOCOL_TLSv1_2',
                  ssl.PROTOCOL_TLSv1_1:'PROTOCOL_TLSv1_1',
                  ssl.PROTOCOL_TLSv1:'PROTOCOL_TLSv1'}

# Take a look at the user's calling options
# Define argument type which will be a function name
def arg_file_a (file) :                   # File must exist and be appendable
  try :
    with open(file, 'a') as fd : pass     # The with will close fd
  except Exception :
    user = getpass.getuser()              # Who is doing this evil?
    msg = ('\n'\
           +tab+'File specification error: {} is not appendable for {}.\n'\
           +tab+'Please check your file and directory permissions.')\
           .format(file, user)
    raise argparse.ArgumentTypeError(msg)
  return file

def arg_file_r (file) :                   # File must exist and be readable
  if pathlib.Path(file).exists() : pass
  else :
    msg = ('\n'\
           +tab+'File specification error: {} does not exist on this machine.')\
           .format(file)
    raise argparse.ArgumentTypeError(msg)
  try :
    with open(file, 'r') as fd : pass     # The 'with' operator will close fd
  except Exception :
    user = getpass.getuser()              # Who is doing this evil?
    msg = ('\n'\
           +tab+'File specification error: {} exists, but is not readable for {}.\n'\
           +tab+'Please check your file and directory permissions.')\
           .format(file, user)
    raise argparse.ArgumentTypeError(msg)
  return file

def arg_dir_r (dir) :                     # Directory must exist and be accessible
  if pathlib.Path(dir).exists() : pass
  else :
    msg = ('\n'\
           +tab+'Path specification error: directory {} does not exist on this machine.')\
           .format(dir)
    raise argparse.ArgumentTypeError(msg)
  if pathlib.Path(dir).is_dir() : pass
  else :
    user = getpass.getuser()              # Who is doing this evil?
    msg = ('\n'\
           +tab+'Path specification error: {} is not a directory accessible for {}.\n'\
           +tab+'Please check your directory permissions.')\
           .format(dir, user)
    raise argparse.ArgumentTypeError(msg)
  return dir

def arg_domain (domain) :                 # Domain must be resolvable
  try : hostname = socket.gethostbyname(domain) # No support for IPv6
  except socket.gaierror :
    msg = ('\n'\
           +tab+'Domain name error: No IPv4 found address for {}')\
           .format(domain)
    raise argparse.ArgumentTypeError(msg)
  return domain

def arg_port (port) :                     # Port number in range 1..65535
  if isinstance(port, int) and 1<=port and port<=65536 : pass
  else :
    msg = ('\n'\
           +tab+'Port number specification error:\n'\
           +tab+'Port number must be in range 1..65535 not {}')\
           .format(port)
    raise argparse.ArgumentTypeError(msg)
  return port

def arg_maxconn (maxconn) :               # 0-1024 incoming connections maximum
  open_max = os.sysconf('SC_OPEN_MAX')    # Max open files for given process
  if isinstance(maxconn, int) and 1<=maxconn and maxconn<=open_max : pass
  else :
    msg = ('\n'\
           +tab+'Maximum connections specification error:\n'\
           +tab+'Maximum must be in range 1..{} not {}')\
           .format(open_max, maxconn)
    raise argparse.ArgumentTypeError(msg)
  return maxconn

def arg_backlog (backlog) :               # 0-1024 backlog maximum
  open_max = os.sysconf('SC_OPEN_MAX')    # Max open files for given process
  if isinstance(backlog, int) and 1<=backlog and backlog<=open_max : pass
  else :
    msg = ('\n'\
           +tab+'Maximum incoming call backlog specification error:\n'\
           +tab+'Maximum must be in range 1..{} not {}')\
           .format(open_max, backlog)
    raise argparse.ArgumentTypeError(msg)
  return backlog

# Function arg_listen has two behaviours:
# switch_IP_port == 'IP' :   Argument is IPv4 dotted quad
# switch_IP_port == 'port' : Argument is integer port number
# argparser ensures that there are two arguments.
def arg_listen (IP_or_port) :             # IP address or port number
  # global is needed since we are not allowed a second argument to function
  global switch_IP_port # pylint: disable=global-statement
  if switch_IP_port=='IP' :
    IP = IP_or_port
    # Check that the IP is valid IPv4
    m = re.match(r'^\s*(\d+)\.(\d+)\.(\d+)\.(\d+)\s*$',IP)
    if m is None :
      msg = ('\n'\
             +tab+'Port IPv4 specification error (1):\n'\
             +tab+'IPv4 must be valid dotted quad, not {}')\
             .format(IP)
      raise argparse.ArgumentTypeError(msg)
    else : i=int(m.group(1)); j=int(m.group(2)); k=int(m.group(3)); l=int(m.group(4))
    if i<256 and j<256 and k<256 and l<256 :
      IP = '{}.{}.{}.{}'.format(i, j, k, l)
    else :
      msg = ('\n'\
             +tab+'Port IPv4 specification error (2):\n'\
             +tab+'IPv4 must be valid dotted quad, not {}')\
             .format(IP)
      raise argparse.ArgumentTypeError(msg)
    switch_IP_port = 'port'               # Next call expects port number
    return IP

  else :
    try :              port = int(IP_or_port) # Convert iff an integer
    except Exception : port = IP_or_port
    # Did we get a valid port number?
    if isinstance(port, int) and 1<=port and port<=65536 : pass
    else :
      msg = ('\n'\
             +tab+'Port number specification error:\n'\
             +tab+'Port number must be in range 1..65535, not {}')\
             .format(port)
      raise argparse.ArgumentTypeError(msg)
    switch_IP_port = 'IP'                 # Next call expects IP address
    return port

# Only root can specify the user.  User must be valid in local system.
def arg_user (user) :                     # Typically nut or upsd
  myuid = os.getuid()                     # uid of caller
  if myuid != 0 :
    msg = ('\n'\
          +tab+'Only root can specify the user, and you are not root.')
    raise argparse.ArgumentTypeError(msg)
  try :
    run_as_user = pwd.getpwnam(user)[0:4] # E.g. ('upsd', 'x', 478, 2)
  except KeyError as err :
    msg=('\n'\
         +tab+'User specification error.  User "{}" not known.\n'\
         +tab+'Maybe somewhere else, but not here.  Sorry.')\
         .format(user)
    raise argparse.ArgumentTypeError(msg)
  return user

# Take a look at the user's calling options
argparser = argparse.ArgumentParser(
  description=prog_name + ' is a Python3 script to provide secure communication from a NUT client'
              '  to a NUT server (upsd) using a TLS shim.   It runs as a daemon alongside the client, receiving'
              '  commands from the client intended for upsd, and sends them to a companion TLS shim'
              '  alongside the NUT server (upsd).  It sends upsd\'s responses back'
              '  to the client.'
              '  Status: "experimental".  Intended for demonstration and experiment.',
  epilog='License: GPL v3 or later at your choice.\n'
         'Support: nut-user mailing list.\n'
         'Documentation: http://rogerprice.org/NUT/ConfigExamples.A5.pdf')
argparser.add_argument('-D', '--debug',  action='count', default=0,
                       help='Increase the debugging level, may be repeated.')
argparser.add_argument('-c', '--clientcertfile',      nargs=1, type=arg_file_r,
                       default=etc_dir+'mkNUTcert/'+hostname+'-client.cert.pem',
                       help='Client TLS certificate file, default %(default)s',
                       metavar='<file>')
argparser.add_argument('--listen',       nargs=2, type=arg_listen,
                       default=('127.0.0.1', 3493),
                       help='Listen to client on this interface and port, default is 127.0.0.1 3493.'\
                            ' If you are already using port 3493 on the same system'\
                            ' change this to IANA port 57 "Any private terminal access".'\
                            ' Setting a port number < 1024 requires starting daemon as root.',
                       metavar=('<IPv4_address>','<port_number>'))
argparser.add_argument('--listentimeout',   nargs=1, type=float,
                       default=1.8,
                       help='Socket timeout for exchanges with client, default is %(default)s secs',
                       metavar='<float>')
argparser.add_argument('--backlog',      nargs=1, type=arg_backlog,
                       default=5,
                       help='Maximum incoming call backlog, default %(default)s',
                       metavar='<integer>')
argparser.add_argument('-l', '--logfile',      nargs=1, type=arg_file_a,
                       default='/var/log/NUT.log',
                       help='Log file, default %(default)s',
                       metavar='<file>')
argparser.add_argument('--PIDFile',      nargs=1, type=str,
                       default='/var/run/upsmonTLS.pid',
                       help='Pid file used by systemd, default %(default)s'\
                            ' Do not change this unless you know what you are doing.',
                       metavar='<file>')
argparser.add_argument('--maxconn',      nargs=1, type=arg_maxconn,
                       default=10,
                       help='Maximum number of incoming connections, default %(default)s.'\
                            ' Strictly speaking, the maximum number of sockets the daemon process'\
                            ' may have open, where getconf OPEN_MAX gives system file maximum.',
                       metavar='<integer>')
argparser.add_argument('--upsdname',   nargs=1, type=arg_domain,
                       default='localhost',
                       help='Relay incoming traffic from client to this server, default'\
                            ' is %(default)s.',
                       metavar='<domain>')
argparser.add_argument('--upsdport',   nargs=1, type=arg_port,
                       default=401,
                       help='Relay incoming traffic from client to this upsd port, default'\
                            ' is %(default)s.  Note that the upsdTLS.py shim offers port 401'\
                            ' by default.',
                       metavar='<integer>')
argparser.add_argument('--upsdtimeout',  nargs=1, type=float,
                       default=5.0,
                       help='Socket timeout for exchanges with upsd, default is %(default)s secs',
                       metavar='<float>')
argparser.add_argument('-u', '--user',   nargs=1, type=arg_user,
                       default=default_user,
                       help='After launch as root, run as this user, default %(default)s',
                       metavar='<user>')
argparser.add_argument('-v', '--version', action='version',
                       help='Show program, Python and SSL/TLS versions, then exit.',
                       version='%(prog)s {}, with SSL/TLS support: {}, '\
                               'running on Python {}'
                       .format(Version,ssl.OPENSSL_VERSION,sys.version.replace('\n',' ')))
args = argparser.parse_args()

debug = args.debug

#print('DDD vars(args)={}'.format(vars(args)))
#print('DDD -D count={}'.format(debug))
#print('DDD Number of arguments:', len(sys.argv), 'arguments.')
#print('DDD Argument List:', str(sys.argv))
#print('DDD args.config = {}'.format(args.config))

# Provide default values if arguments were omitted
# args.listen has form ['127.0.0.1', 401] if specified, ('127.0.0.1', 401) if default
backlog         = args.backlog[0]         if isinstance(args.backlog, list)         else args.backlog
clientcertfile  = args.clientcertfile[0]  if isinstance(args.clientcertfile, list)  else args.clientcertfile
log_file        = args.logfile[0]         if isinstance(args.logfile, list)         else args.logfile # logfile -> log_file
PIDFile         = args.PIDFile[0]         if isinstance(args.PIDFile, list)         else args.PIDFile
maxconn         = args.maxconn[0]         if isinstance(args.maxconn, list)         else args.maxconn
upsdname        = args.upsdname[0]        if isinstance(args.upsdname, list)        else args.upsdname
upsdport        = args.upsdport[0]        if isinstance(args.upsdport, list)        else args.upsdport
upsdtimeout     = args.upsdtimeout[0]     if isinstance(args.upsdtimeout, list)     else args.upsdtimeout
try_user        = args.user[0]            if isinstance(args.user, list)            else args.user
listen_IP       = args.listen[0]          if isinstance(args.listen, list)          else args.listen[0]
listen_port     = args.listen[1]          if isinstance(args.listen, list)          else args.listen[1]
listentimeout   = args.listentimeout[0]   if isinstance(args.listentimeout, list)   else args.listentimeout

#############################################################################################
# Open a file for logging on behalf of calling user
calling_user = pwd.getpwnam(getpass.getuser())[0:4]     # E.g. ('jschmo', 'x', 2078, 3000)
log, log_inode = open_log_file(log_file, calling_user[2], calling_user[3])   # Opened for calling user
# Kick off new session in the log file
logger('#' * 53 + '')
msg = '{} version {}, Python version {}'\
      .format(prog_name, Version, sys.version.replace('\n',' '))
logger(msg) ; syslogger(msg)
logger('nodename={} OS ID={} sysname={} release={} machine={}'\
       .format(os.uname().nodename, OS_id, os.uname().sysname, os.uname().release, os.uname().machine))
msg = 'ssl.OPENSSL_VERSION {}'.format(ssl.OPENSSL_VERSION)
logger(msg) ; syslogger(msg)
logger('This log file: {}, owner is {} with UID = {}, GID = {}'\
       .format(log_file, calling_user[0], calling_user[2], calling_user[3]))
logger('Log file notation: '+lwsb+'...'+rwsb+' is a socket managed by upsmonTLS,')
logger('Log file notation: '+lob+'...'+rob+' is a TLS wrapped socket.')
logger('Log file notation: '+lwsb+'...(upsd)'+rwsb+' is a socket to upsd.')
msg = '{} starts with caller: {}@{}  PID: {}, UID = {}, GID = {}.'\
      .format(prog_name, calling_user[0], hostname, os.getpid(), calling_user[2], calling_user[3])
logger(msg) ; syslogger(msg)
syslogger('[notice] Further {} messages will be written in file {}'.format(prog_name, log_file))
logger("Caller's working directory: {}".format(os.getcwd()))
line='Calling command:'                   # Build up display of user's parameters
for x in sys.argv:
  line = line + " {}".format(str(x))
logger(line)

# We now work out who is run_as_user, the user who will be running this server.
# Only root can specify a user.
# For current user name: getpass.getuser()
# This code is fragile, and relies heavily on the checking carried
# out by type verification function arg_user.
fork = False                                    # Do we fork ?
logger('Determining which user will run the daemon {} ...'.format(prog_name))
DDlogger('os.getuid()={} args.user={}'.format(os.getuid(), args.user))
if os.getuid() == 0 :                           # root tries to set user
  run_as_user = pwd.getpwnam(try_user)[0:4]     # E.g. ('jschmo', 'x', 2078, 3000)
  if run_as_user == 'root' :
    fork = False
    msg='{} Warning 320: daemon {} will be run as user root.'\
        .format(blob, prog_name)
    logger(msg); eprinter(msg)
  else : fork = True
  logger('... root sets {} to run daemon {}'.format(run_as_user, prog_name))
else :                                          # Caller is not root
  run_as_user = pwd.getpwuid(os.getuid())[0:4]  # E.g. ('jschmo', 'x', 2078, 3000)
  fork = False
  logger('User {} will run daemon {}'.format(run_as_user, prog_name))

if calling_user[0] == run_as_user[0] :
  logger('... daemon {} will be run by calling user {}'.format(prog_name, calling_user[0]))
else :
  logger('... daemon {} will be run by {}'.format(prog_name, run_as_user[0]))

if fork :
  msg = ('Closing log file to re-open with user {}\n'\
         +tab+ '-' * 32)\
         .format(run_as_user[0])
  logger(msg)
  log.close()
  # Reopen a file for logging as the user who will run the server
  log, log_inode = open_log_file(log_file, run_as_user[2], run_as_user[3])   # Opened for run_as_user
  logger('{} server log file inode {} reopened for user {}'\
         .format(prog_name, os.stat(log_file).st_ino, run_as_user[0]))

# Check - are we running already as some other non-privileged user?
logger('Checking - is daemon {} already running as user {} ?'\
       .format(prog_name, run_as_user[0]))
# L = ['ps', '-u', run_as_user[0], '-o', 'euser,egroup,pid,ppid,comm', '--no-header']
L = ['ps', '-C', prog_name, '-o', 'euser,egroup,pid,ppid,comm', '--no-header']
Dlogger('Check - running command: {}'.format(L))
stdout, stderr = do_command (L)      # Unicode output or None
Dlogger(('Check - \n'\
        +tab+'stdout = {}\n'\
        +tab+'stderr = {}').format(stdout, stderr))
is_previous_instance_running = False
if stderr != [] :
  msg = '{} Error 330: Internal error: STDERR:'.format(blob)
  logger(msg); eprinter(msg); is_previous_instance_running = True
  for line in stderr :
    logger(line); eprinter(line)     # Let's hear the bad news
elif stdout != None :
  for line in [x for x in stdout if x != ''] :
    DDlogger('Check - looking for {} in {}'.format(prog_name,line))
    l = re.findall('[\w.-]+',line) # pylint: disable=anomalous-backslash-in-string
    DDlogger('Check - tokens in line = {} have type {}'.format(l, type(l)))
    if l[0] != getpass.getuser() :   # Is this someone else ?
      DDlogger('Check - {} != {}'.format(l[0],getpass.getuser()))
      msg = ("{} Error 340: a previous instance of {} is already running\n"\
            +tab+"for user = {}, group = {}, pid = {}, ppid = {} .\n"\
            +tab+"Please stop this previous instance first, for\n"\
            +tab+"example with command 'killall -SIGTERM {}'\n"\
            +tab+"or 'killall -SIGKILL {}' if really needed.\n"\
            +tab+"Exiting ...")\
            .format(blob, prog_name, l[0], l[1], l[2], l[3], prog_name, prog_name)
      logger(msg); eprinter(msg)
      is_previous_instance_running = True
      break
if is_previous_instance_running : cleanup(); exit(1)
else : logger('No previous instance of {} running'.format(prog_name))

# Define the SIGINT handler used to terminate the loop.
signal.signal(signal.SIGINT, SIG_handler)
# Define the SIGQUIT handler used to terminate the loop.
signal.signal(signal.SIGQUIT, SIG_handler)
# Define the SIGTERM handler used to terminate the loop.
signal.signal(signal.SIGTERM, SIG_handler)
# Define the SIGUSR1 handler used to re-read the configuration file.
signal.signal(signal.SIGUSR1, SIG_handler)
# Define the SIGHUP handler used to re-read configuration file.
signal.signal(signal.SIGHUP, SIG_handler)

# 1. Set up socket to listen to upsmon
# 2. Fork to lower privilege
# 3. For each login request from upsmon,
#    3a. Ignore STARTTLS if received
#    3b. set up a client socket to talk to upsd/upsdTLS server
#    3c. send STARTTLS to upsd server
#    3d. if STARTTLS OK, install TLS
#    3e. Log into upsd server.
#    3f. Log into UPS units
#    3g. Begin collecting statuses.

# 1. Set up server socket for traffic from upsmon or other client
# See https://steelkiwi.com/blog/working-tcp-sockets/
client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_sock.setblocking(False)         # Non-blocking
client_sock.settimeout(5.0)            # Work in timeout mode with 5 second timeout
in_sock_list = [client_sock]           # Socket list for inputs should never be empty
logger ('Setting up server socket at {}:{} for traffic from upsmon or other client ...'
        .format(listen_IP, listen_port))
Dlogger('Trying client_sock.bind(({},{}))...'\
        .format(listen_IP, int(listen_port)))
try : client_sock.bind((listen_IP, int(listen_port)))
except socket.gaierror as err :
  msg = ('{} Error 370: Unable to bind socket:\n'\
         +tab+'IP={} port={}\n'\
         +tab+'Reason: {}\n'\
         +tab+'Exiting...')\
         .format(blob, listen_IP, listen_port, err)
  logger(msg); eprinter(msg)
  cleanup(); exit(1)
except PermissionError as err :
  msg = ('{} Error 380: Unable to bind socket:\n'\
         +tab+'IP={} port={}\n'\
         +tab+'Reason: {}\n'\
         +tab+'Exiting...')\
        .format(blob, listen_IP, listen_port, err)
  logger(msg); eprinter(msg)
  cleanup(); exit(1)
except Exception as ex :
  msg = ('{} Error 390: Unable to bind socket:\n'\
         +tab+'IP={} port={}\n'\
         +tab+'Reason: {}\n'\
         +tab+'This can happen if you restart {} quickly\n'\
         +tab+'and the previous socket to clients has not been cleared.\n'\
         +tab+'If port {} is really in use, consider listening on\n'\
         +tab+'port 57 "Any private terminal access" or\n'\
         +tab+'port apcupsd/3551 "Apcupsd information port" instead.\n'\
         +tab+'Exiting...')\
        .format(blob, listen_IP, listen_port, ex, prog_name, listen_port)
  logger(msg); eprinter(msg)
  cleanup(); exit(1)

#fqdn = client_sock.getfqdn()
client_sock.listen(backlog)
logger(('{} Message 400: client_sock {} listening on {}:{}\n'\
        +tab+'Flags: blocking={}  backlog={}.')\
        .format(blob, pp_sock(client_sock), listen_IP, listen_port, NonBlocking, backlog))

# 2. Fork to a lower privilege cannot happen before defining the "incoming"
# socket for traffic from UPSmon.py because low privilege users are not
# allowed to set up sockets to ports below 1024, and we want to be able to use
# port 401.
if fork :
  logger('Prepare to fork and move to lower privilege ...')
  Dlogger('with calling_user = {}, run_as_user = {}.'\
          .format(calling_user, run_as_user))
  # Yes, we fork and daemonize
  msg = ('Process {} forking ...')\
         .format(fnl(), os.getpid())
  logger(msg); eprinter(msg)
  # Fork a copy of the root process to create a "run_as_user" process
  # This creates a complete copy including the messages destined for NUTLOG.
  try : child_pid = os.fork ()               # Create copy of self.  Child will drop privilege
  except Exception as ex :
    msg = ('{} Error 410: Error when forking:\n'\
           +tab+'Reason: {}\n'\
           +tab+'Exiting ...')\
           .format(blob, ex)
    logger(msg); eprinter(msg)
    cleanup() ; exit (1)
  if child_pid > 0 :                         # Parent process receives child's PID
    # Write child's PID to file for systemd to enjoy.
    logger('{} Message 424: Writing child PID {} to file {}'.format(fnl(), child_pid, PIDFile))
    try :
      with open(PIDFile, 'wt') as PID_fd :
        PID_fd.write('{}'.format(child_pid))   # write likes strings, not integers
        PID_fd.close()
    except Exception as ex :
      msg=('{} Error 425: Unable to create PID file {}\n'\
           +tab+'Reason: {}\n'
           +tab+'Exiting ...')\
           .format(blob, PIDFile, ex)
      logger(msg); eprinter(msg)
      cleanup() ; exit (1)
    msg = ('{} Message 420: Parent says: child {} forked ...\n'\
           +tab+'Child\'s messages are in log file {}\n'\
           +tab+'Parent process {} does not wait for child\'s daemon process {}.\n'\
           +tab+"Hint: to stop a working daemon, type command 'killall -SIGTERM {}'\n"\
           +tab+"To stop a broken daemon, type command 'killall -SIGKILL {}'\n"\
           +tab+'Parent now exits.  Adieu.')\
           .format(blob, child_pid, log_file, os.getpid(), child_pid, prog_name, prog_name)
    logger(msg); eprinter(msg)
    # Parent exits, child is inherited by init.  Child does cleanup
    exit (0)

  # Child process still attached to TTY
  time.sleep(0.5)                            # Wait for parent to exit
  msg = '{} Message 430: Child says: I am forked process {}, my parent is process {}'\
        .format(blob, os.getpid(), os.getppid())
  logger(msg)
  # Daemonization: Child changes user: run_as_user could be ('upsd', 'x', 478, 2)
  msg = '{} Message 440: Child changing to user "{}", UID {}, GID {} ...'\
        .format(blob, run_as_user[0], run_as_user[2], run_as_user[3])
  logger(msg)
  os.setgid(run_as_user[3])
  os.setuid(run_as_user[2])
  PID = os.getpid(); UID = os.getuid(); GID = os.getgid(); PPID = os.getppid()
  logger('{} Message 450: Child changed user: {}@{}  PID: {}, UID = {}, GID = {}.'\
         .format(blob, run_as_user[0], hostname, PID, UID, GID))

  # Child changes current working directory
  home_dir = pwd.getpwuid(os.getuid()).pw_dir  # run_as_user's working directory
  try :              os.chdir(home_dir)        # Anticipate working directory problem
  except Exception : os.chdir('/')
  logger("{} Message 460: Child changed current working directory to {}"\
         .format(blob, os.getcwd()))
  umask = 0o007   # World + dog not able to see or modify files created by daemon
  os.umask(umask)
  logger(("{} Message 470: Child changed umask to octal %3.3o" % os.umask(umask))\
          .format(blob))
  # Child changes session ID, looses TTY
  os.setsid(); SID = os.getsid(PID)
  logger("{} Message 480: Child PID = {}, PPID = {}, changes SID to {}"\
         .format(blob, PID, PPID, SID))
  # Continue the daemonisation by re-directing stdout and stderr
  # If needed, restore using sys.stdout = sys.__stdout__
  msg = ('{} Message 490: Child redirecting Python\'s stdout and stderr to log file {} ...\n'\
        +tab+'Actions PRINT and EPRINT closing.  Hint: Use NUTLOG.')\
        .format(blob, log_file)
  logger(msg)
  stderr_redirect = True                       # Cleanup needs to know about this redirect
  sys.stdout = log                             # Assume permissions ok
#  sys.stdout.seek(0,2)                        # Child appends to 0th byte at end of file
  sys.stderr = log

  #  os.system('ps -elf | grep "net-mgr.py"')
  #  os.system('ps -elf | grep -E "nut[dms]|UPSmon"')
  #  os.system('netstat -an | grep "3493 "')
  #  os.system('lsof -i :nut -n +c 10')
  # Check that we really have changed user.
  DDlogger('Verify that current user {} has required UID {}...'\
           .format(run_as_user[0], run_as_user[2]))
  if run_as_user[2] != os.getuid() :
    msg = '{} Error 500: Child failed to change to user {}, UID is {}, not {}'\
          .format(blob, run_as_user[0], os.getuid(), run_as_user[2])
    logger(msg); eprinter(msg)

else : logger('No forking this time.')

#####################################################################################
# This is the main operational loop. It spends most of it's time hung
# on the select.select operation waiting for incoming traffic.
loop_count = 0                            # Count the loops
Dlogger('The fun begins, looping on select.select occurs when traffic arrives ...')
while True :
  loop_count = loop_count + 1
  try : read_sock_list, write_sock_list, err_sock_list\
        = select.select(in_sock_list, out_sock_list, in_sock_list)
  except socket.timeout :
    read_sock_list, write_sock_list, err_sock_list = ([],[],[]) # No traffic
    Dlogger(('{}'+'-'*30+' Loop {} '+'-'*10+'\n'\
             +tab+'in_sock_list={}, {} sockets.\n'\
             +tab+'buddy_dict={}, {} buddies.\n'\
             +tab+'TLS_enabled_dict={}, {} entries.\n'\
             +tab+'out_sock_list={}, {} sockets.  select.select reports no traffic, timeout.')\
             .format(date_time(), loop_count, pp_sock_list(in_sock_list, long=True), len(in_sock_list),\
                     pp_buddy_dict(), len(buddy_dict),\
                     pp_TLS_enabled_dict(), len(TLS_enabled_dict),\
                     pp_sock_list(out_sock_list, long=True), len(out_sock_list)))
  except Exception as ex :
    msg = (('{} Error 505: Unable to select next call\n'\
            +tab+'Reason: {}\n'\
            +tab+'in_sock_list={}, {} sockets.\n'\
            +tab+'buddy_dict={}, {} buddies.\n'\
            +tab+'TLS_enabled_dict={}, {} entries.\n'\
            +tab+'out_sock_list={}, {} sockets.\n'\
            +tab+'Exiting ...')\
            .format(blob, ex, pp_sock_list(in_sock_list), len(in_sock_list),\
                    pp_buddy_dict(), len(buddy_dict),\
                    pp_TLS_enabled_dict(), len(TLS_enabled_dict),\
                    pp_sock_list(out_sock_list), len(out_sock_list)))
    logger(msg); eprinter(msg)
    cleanup(); exit(1)
  else : # Traffic detected
    Dlogger(('{} '+'-'*30+' Loop {} '+'-'*10+'\n'\
             +tab+'in_sock_list={}, {} sockets.\n'\
             +tab+'buddy_dict={}, {} buddies.\n'\
             +tab+'TLS_enabled_dict={}, {} entries.\n'\
             +tab+'out_sock_list={}, {} sockets.\n'\
             +tab+'read_sock_list={}, {} sockets.\n'\
             +tab+'write_sock_list={}, {} sockets.\n'\
             +tab+'err_sock_list={}, {} sockets.')\
             .format(date_time(), loop_count,\
                     pp_sock_list(in_sock_list, long=True), len(in_sock_list),\
                     pp_buddy_dict(), len(buddy_dict),\
                     pp_TLS_enabled_dict(), len(TLS_enabled_dict),\
                     pp_sock_list(out_sock_list, long=True), len(out_sock_list),\
                     pp_sock_list(read_sock_list), len(read_sock_list),\
                     pp_sock_list(write_sock_list), len(write_sock_list),\
                     pp_sock_list(err_sock_list), len(err_sock_list)))

  for s in read_sock_list :
    Dlogger('Receiving message on socket {} in read_sock_list ...'.format(pp_sock(s)))
    s_fd = s.fileno()                     # Socket file descriptor.  An integer.
    # Has socket been closed ?
    if s_fd < 1 :
      logger('read_sock_list: Skipping closed socket {}'\
             .format(pp_sock(s)))
      continue                            # Maybe more luck with next s
    if s is client_sock :
      # Accept new incoming call from client.  in_sock = new socket
      # for send+receive, client_address is the address of client e.g. upsmon.
      # The incoming socket has a "buddy" used to relay the messages to upsd.
      in_sock, client_address = s.accept()
      Dlogger(('read_sock_list: Incoming call on client_sock={}\n'\
              +tab+'Accepted new incoming connection from {}\n'\
              +tab+'Adding socket in_sock={} to in_sock_list for read + write')\
              .format(pp_sock(client_sock), client_address, pp_sock(in_sock, long=True)))
      in_sock.setblocking(False)          # Non-blocking
      in_sock.settimeout(2)               # Work in timeout mode
      in_sock_list.append(in_sock)        # Add client socket to inputter list

      # Set up fresh socket upsd_s for commands to upsd
      # ,------,   ,----,                ,----,          ,--------,
      # | upsd |---|Shim|----------upsd_s|Shim|in_sock---| upsmon |
      # '------'   '----'                '----'          '--------'
      upsd_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      upsd_s.setblocking(False)           # Non-blocking
      upsd_s.settimeout(upsdtimeout)    # Low value speeds up the testing
      Dlogger('Setting up fresh socket upsd_s={} for commands to upsd'\
              .format(pp_sock(upsd_s)))
      buddy_dict[in_sock.fileno()] = upsd_s  # Sockets to upsd
      Dlogger('Adding buddy socket {}:{} to buddy_dict for command relay to upsd.'\
              .format(in_sock.fileno(), pp_sock(upsd_s)))
      TLS_enabled_dict[in_sock.fileno()] = False
      Dlogger('Setting TLS_enabled_dict[{}] = False.'\
              .format(in_sock.fileno()))

      Dlogger('Attempting to connect to upsd at {}:{} ...'.format(upsdname, upsdport))
      try : rc = upsd_s.connect((upsdname, int(upsdport)))
      except Exception as ex :
        msg = ('{} Error 345: Connection to {}:{} refused\n'\
               +tab+'Reason: {}\n'\
               +tab+'Hint: I expect upsd to be listening at port {}:{}\n'\
               +tab+'before I start.  Please check that upsd is running before\n'\
               +tab+'starting me.  Exiting ...')\
               .format(blob, upsdname, upsdport, ex, upsdname, upsdport)
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
      logger('{} Message 350: Connected to upsd via socket {}'\
             .format(blob, pp_sock(upsd_s, long=True)))

      # 2b. Attempt to start TLS to upsd
      Dlogger('Attempt a STARTTLS to {}:{}'.format(upsdname, upsdport))
      rc, reply = relay_cmd('STARTTLS', upsd_s, upsdtimeout)
      m = re.match(r'\s*OK.*',reply)
      m_ERR = re.match(r'.*FEATURE_NOT_CONFIGURED.*',reply)
      if m :                                  # Clear for TLS
        upsd_TLS[(upsdname, upsdport)] = True
        Dlogger('STARTTLS to {}:{}  Received reply {}'.format(upsdname, upsdport, reply))
      elif m_ERR :                                  # send_msg handles COMM->NOCOMM
        upsd_TLS[(upsdname, upsdport)] = False
        msg = ("{} Error 1110: STARTTLS to {}:{} not available.\n"\
               +tab+"Reply {}\n  Exiting ...")\
               .format(blob, upsdname, server, reply)
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
      else :                                  # send_msg handles COMM->NOCOMM
        upsd_TLS[(upsdname, upsdport)] = False
        msg = ("{} Error 1120: STARTTLS to {}:{} fails.\n"\
               +tab+"Reply {}.  Exiting ...")\
               .format(blob, upsdname, upsdport, reply)
        logger(msg); eprinter(msg)
        cleanup(); exit(1)

      # Add client side TLS to socket to upsd
      # Create TLS context
      # C source code useful for debugging the Python error messages is found at
      # https://github.com/python/cpython/blob/3.8/Modules/_ssl.c#L3380-L3460
      Dlogger('Adding clent side TLS to upsd_s={}'\
              .format(pp_sock(upsd_s)))
      try : client_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
      except Exception as ex :
        msg = ('{} Error 1140: Unable to create context:\n'\
               +tab+'clientcertfile={}\n'\
               +tab+"Reason: {}")\
               .format(blob, clientcertfile, ex)
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
      Dlogger(('TLS client_context = {}\n'\
               +tab+'protocol={}')\
               .format(client_context, protocol_names[client_context.protocol]))
      # We have a context, but are our certificates good enough?
      Dlogger('Attempting to use certificate in clientcertfile = {} ...'\
               .format(clientcertfile))
      try: client_context.load_verify_locations(clientcertfile)
      except Exception as ex :
        # cert_raw_txt = ssl._ssl._test_decode_cert(clientcertfile)   # Human readable, but needs pretty printing
        # pprint.pprint(cert_raw_txt, stream=log, indent=3)
        # https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
        # substrate = pem.readPemFromFile(open('cert.pem'))
        # cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
        msg = ('{} Error 1150: Unable to verify certificate file {}\n'\
               +tab+"Reason: {}\n"\
               '{}')\
               .format(blob, clientcertfile, ex, pp_PEM(clientcertfile))
        logger(msg); eprinter(msg)
        cleanup(); exit(1)

      # Turn off timeouts that prevent smooth operation
      # (<class 'socket.timeout'>, timeout('_ssl.c:1091: The handshake operation timed out')
      upsd_s.settimeout(None)             # https://github.com/pyca/pyopenssl/issues/168
      try : upsd_ss = client_context.wrap_socket(upsd_s, server_side=False, server_hostname=upsdname)
      except ssl.SSLError as ex :
        msg=('{} Error 1160: Unable to install TLS wrapper version {} on socket {}.\n'\
             +tab+'Reason: {}\n'\
             '{}')\
             .format(blob, ssl.OPENSSL_VERSION, pp_sock(upsd_s), ex, pp_PEM(clientcertfile))
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
      except Exception as ex :
        msg=('{} Error 1165: Unable to install TLS wrapper version {} on socket {}\n'\
             +tab+'Reason: {}\n'\
             '{}')\
             .format(blob, ssl.OPENSSL_VERSION, pp_sock(upsd_s), ex, pp_PEM(clientcertfile))
        logger(msg); eprinter(msg)
        cleanup(); exit(1)
      buddy_dict[in_sock.fileno()] = upsd_ss  # TLS Socket to upsd
      Dlogger(('Updating buddy_dict {}:{}')\
               .format(in_sock.fileno(), pp_sock(upsd_ss)))
      Dlogger(('Installed TLS version {} using TLS wrapper version {}\n'\
               +tab+'on TLS socket {} to {}:{} with client certificate (pp_PEM(clientcertfile) omitted)')\
              .format(upsd_ss.version(), ssl.OPENSSL_VERSION, pp_sock(upsd_ss), upsdname,\
                      upsdport, clientcertfile))
      # Allow client commands that require TLS
      TLS_enabled_dict[in_sock.fileno()] = True
      Dlogger(('Setting TLS_enabled_dict[{}] = {}.')\
               .format(in_sock.fileno(), TLS_enabled_dict[in_sock.fileno()]))
      upsd_ss.setblocking(False)          # Non-blocking
      upsd_ss.settimeout(upsdtimeout)     # Workaround for socket.timeout
      # Which TLS protocol is used ?
      Dlogger('Socket {} to {}:{} uses TLS version {}'\
             .format(pp_sock(upsd_ss), upsdname, upsdport, upsd_ss.version()))

      # Replace socket s by ss in in_sock_list
      old_in_sock_list = in_sock_list
      in_sock_list = [sock for sock in in_sock_list if sock.fileno() != -1]
      Dlogger('in_sock_list replaced {} by {}'.format(pp_sock_list(old_in_sock_list), pp_sock_list(in_sock_list)))
      # Add client side TLS done

      msg_q_dict[in_sock.fileno()] = []     # Create queue for messages for upsd
      Dlogger('... end of receiving message on socket {} in read_sock_list ...'.format(pp_sock(s)))
      # End of if s is client_sock : Set up fresh socket upsd_s for commands to upsd

    else :
      # 3. wait for upsmon/UPSmon to send us a STARTTLS.
      # Client has sent a message to upsd
      # s.recv and recv_response return bytes, not strings.
      raw_msg = recv_response(s, False, listentimeout)
      try : msg = no_trailing_newlines(raw_msg.decode('utf-8'))
      except UnicodeDecodeError : msg = raw_msg
      Dlogger(('read_sock_list: Socket {} receives message\n'\
               +tab+'{} with type {}')\
               .format(pp_sock(s, long=True), pp_msg(msg, max=200), type(msg)))
      Dlogger('TLS_enabled_dict = {} s = {}'.format(pp_TLS_enabled_dict(), pp_sock(s)))
      if msg == 'STARTTLS' :
        # Send refusal to upsmon, but TLS already started to upsd.
        enqueue (msg_q_dict[s_fd], 'ERR FEATURE-NOT-CONFIGURED')
        if s not in out_sock_list : out_sock_list.append(s)
        Dlogger('Refusing {}\'s STARTTLS ...'.format(pp_sock(s)))
        Dlogger(('msg_q_dict[...{}:{}...]\n'\
                 +tab+'len(out_sock_list) = {}')\
                 .format(s_fd, msg_q_dict[s_fd], len(out_sock_list)))
      elif isempty(msg) :                 # msg = '' or None
        Dlogger(('Received empty message.  Closing socket {} from {}')\
                .format(pp_sock(s), client_address))
        del_sock(s)  # resets TLS_enabled_dict if this was a client socket
      elif not TLS_enabled_dict[s_fd] :
        # Refuse commands if TLS not already installed
        enqueue (msg_q_dict[s_fd], 'ERR TLS_NOT_ENABLED')
        if s not in out_sock_list : out_sock_list.append(s)
        Dlogger('Refusing {}\'s {},  TLS_enabled_dict[{}]={} ...'\
                .format(pp_sock(s), msg, pp_sock(s), TLS_instalded_dict[s]))
        Dlogger(('msg_q_dict[...{}:{}...]\n'\
                 +tab+'len(out_sock_list) = {}')\
                 .format(s_fd, msg_q_dict[s_fd], len(out_sock_list)))
      elif msg == 'UnicodeDecodeError' :
        enqueue (msg_q_dict[s_fd], 'ERR UnicodeDecodeError')
        if s not in out_sock_list : out_sock_list.append(s)
        Dlogger(('msg_q_dict[...{}:{}...]\n'\
                 +tab+'len(out_sock_list) = {}')\
                .format(s_fd, msg_q_dict[s_fd], len(out_sock_list)))
      else :  # Non-empty text is true, '' is false.  None is false
        # Relay message to upsd, collect reply,
        # Success: rc=None. upsd dead: rc = None reply = ''
        Dlogger('Relaying message {} to upsd via socket {}'\
                .format(pp_msg(msg), pp_sock(buddy_dict[s_fd], long=True)))
        rc, reply = relay_cmd (msg, buddy_dict[s_fd], upsdtimeout)
        # Complete reply for VER
        if msg == 'VER' : reply = reply + ', via shim ' + prog_name + ' ' + Version
        # Send upsd reply back to upsmon
        msg_q_dict[s_fd].append(reply)
        if s not in out_sock_list:
          out_sock_list.append(s)

      Dlogger('... end of receiving message on socket {} in read_sock_list ...'.format(pp_sock(s)))
  # end of for s in read_sock_list

  for s in write_sock_list :
    Dlogger('Socket {} in write_sock_list ...'.format(pp_sock(s)))
    s_fd = s.fileno()                     # Socket file descriptor.  An integer.
    # Has socket been closed ?
    if s_fd < 1 :
      logger('write_sock_list: Skipping closed socket {}'\
             .format(pp_sock(s)))
      continue
    # Next message to be sent on socket s
    next_msg, msg_q_dict[s_fd] = dequeue(msg_q_dict[s_fd])
    if next_msg == None :
      out_sock_list.remove(s)
      Dlogger('write_sock_list: queue = {}, removing socket {} from out_sock_list'\
              .format(msg_q_dict[s_fd],  pp_sock(s)))
    else :
      byte_msg = bytes(no_trailing_newlines(next_msg)+'\n','utf-8')
      Dlogger(('write_sock_list: sending message\n'\
               +tab+'{}\n'\
               +tab+'to {} ...')\
               .format(pp_msg(next_msg, max=200), pp_sock(s)))
      try :
        byte_count = s.send(byte_msg)       # Returns number of bytes sent
        if byte_count > 0 :       rc = 0
        else :                    rc = 1 ; ex = 'zero bytes sent'  # upsd dead?
      except socket.error :       rc = 2 ; ex = 'socket.error'
      except Exception :          rc = 3 ; ex = 'Problem in relay_cmd'
      if rc > 0 :
        Dlogger('... fails rc = {} reason: {}'.format(rc, ex))
      else : Dlogger('write_sock_list: ... sent rc = {}'.format(rc))

  for s in err_sock_list :
    Dlogger('Socket {} in err_sock_list: also removing buddy socket ...'\
            .format(pp_sock(s)))
    s_fd = s.fileno()                     # Socket file descriptor.  An integer.
    # Has socket been closed ?
    if s_fd < 1 :
      logger('err_sock_list: Skipping closed socket {}'\
             .format(pp_sock(s)))
      continue
    del_sock(s)

  # Is the server socket alive?
  Dlogger(('end of loop {}: new socket list lengths: in_sock_list={}, buddy_dict={}, TLS_enabled_dict={}, out_sock_list={}')\
           .format(loop_count, len(in_sock_list), len(buddy_dict), len(TLS_enabled_dict), len(out_sock_list)))
  if len(in_sock_list)==0 :
    logger('{} Message 540: Server socket listening on {}:{} has died.'\
           .format(blob, listen_IP, listen_port))
    break
  # Were we interrupted?
  if SIG_called['INT'] :
    logger('{} Message 550: SIGINT terminates {}.'.format(blob, prog_name))
    break
  if SIG_called['QUIT'] :
    logger('{} Message 560: SIGQUIT terminates {}.'.format(blob, prog_name))
    break
  if SIG_called['TERM'] :
    logger('{} Message 570: SIGTERM terminates {}.'.format(blob, prog_name))
    break
  if loop_count<100000000 :             # Debug: n loops only
    continue  # while in_sock_list
  else :
    Dlogger('Terminating {} with loop_count = {}'\
            .format(prog_name, loop_count))
    cleanup()
    exit(0)
  # end of while True

cleanup()
exit(0)
