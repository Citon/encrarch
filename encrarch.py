#!/usr/bin/python

# encrarch.py - Encrypt and Archive: PGP encrypted archive
#
# Copy all files matching a given pattern to a temporary location
# then write to portable drive or other location using gpg to encrypt
#
# ! Requires gnupg module from http://code.google.com/p/python-gnupg/ !
#
# Copyright 2012 Citon Computer Corporation
#
# Author: Paul Hirsch <paul.hirsch@citon.com>

VERSION = "v0.2 (2012-01-02)"

# General imports
import sys, os, errno, traceback, time, re, datetime

# File and encryption handling
import fnmatch, shutil, gnupg

# Configuration handling
import ConfigParser   # XXX - Change to "configparser" for Python 3.0
import optparse  # Should add argparse support down the road

# Logging imports
import logging, logging.handlers, smtplib, syslog
from email.mime.text import MIMEText

# Defaults
DEFCONFFILE = "/etc/encrarch.conf"
DEFINSTANCENAME = "encrarch"

def findSourceFiles (pattern, basepath):
    """
    Find files matching pattern under basepath. Return array with filename /
    relative path pairs. Uses fnmatch for filtering
    """
    sourcefiles = []
    for base, dirs, files in os.walk(basepath):
        # Only process files that match our filter
        for filename in fnmatch.filter(files, pattern):
            # Remove the source base path to get a relative path
            relpath = re.sub(r'^' + basepath, '', base)
            sourcefiles.append([filename, relpath])

    return sourcefiles


def getFreeSpace(folder):
    """ 
    Return folder/drive free space (in bytes) - UNIX Only
    """
    return os.statvfs(folder).f_bfree * os.statvfs(folder).f_frsize


def roomForFiles(sourcebase, sources, destfolder):
    """
    Check if there is room for the given file set in the given destfolder
    Sources must be an array of arrays with file/patch pairs as members.
    Returns two values:
     * The available space minus the required space. (Negative values are bad!)
     * The required space by itself
    """

    # Add up numbers
    tsize = 0
    for sourcefile, relpath in sources:
        tsize += os.stat(os.path.normpath(os.sep.join((sourcebase,relpath,sourcefile)))).st_size

    return (getFreeSpace(destfolder) - tsize, tsize)


def makeDirTree (path):
    """
    Recursively create a new directory tree
    """
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST:
            pass
        else: raise


def copySourceToTempSource (source, sourcebase, tempbase):
    """
    Take an array of filename / path pairs underneath basepath and copy into
    temp directory, returning a new array with filename, path pairs, adjusted
    for the temp path
    """
    destfiles = []
    for (filename, relpath) in source:
        destpath = os.path.normpath(os.sep.join((tempbase, relpath)))

        # Create the temp folder path as needed
        makeDirTree(destpath)

        # Copy the file into temp
        shutil.copyfile(os.path.normpath(os.sep.join((sourcebase,relpath,filename))),os.path.join(destpath,filename))

        destfiles.append([filename, destpath])


def clearTempSource (source, tempbase):
    """
    Clear the given source/path pairs out of tempbase
    """
    for (filename, relpath) in source:
        destpath = os.path.normpath(os.sep.join((tempbase, relpath)))
        os.unlink(destpath)


def lookupKeyFingerprint (fingerprint):
    """
    Check for existence of a recipient key and return their first UID, or an
    empty string if not found
    """
    # Create our GnuPG instance
    gpg = gnupg.GPG()

    # Check that the recipient's key exists
    found = ""
    for gpgkey in gpg.list_keys():
        fp = gpgkey['fingerprint']
        if fp[-8:] == fingerprint:
            # Found!   Grab the first UID name
            found = gpgkey['uids'][0]
            break

    if not (found):
        raise Exception, "Could not find key for fingerprint ID " + fingerprint

    return found


def encryptSourcesToDestination (source, tempbase, destbase, recipient, logger):
    """
    Take an array of filename, path pairs and run through GnuPGP, encrypting
    for recipient (a key ID) and outputting to files under the destination path.
    Also takes logger as argument.  Returns a new filename, path pair array
    """
    destfiles = []

    # Create our GnuPG instance
    gpg = gnupg.GPG()

    for (filename, basepath) in source:
        destpath = os.path.normpath(os.sep.join((destbase, basepath)))

        # Create the folder path as needed
        try:
            makeDirTree(destpath)
        except OSError:
            logger.warning("Could not build destination folders under %s: Skipping %s" % (destpath, filename))
            continue

        # Open the source file with default system buffering
        sfile = os.path.normpath(os.sep.join((tempbase,basepath,filename)))
        try:
            sfileh = open(sfile,'rb', -1)
        except:
            logger.warning("Could not open source %s for reading: Skipping" % sfile)
            continue

        # Add the standard .gpg suffix, then set the full path and temp
        # path
        filename += ".gpg"
        fullfilename = os.path.join(destpath, filename)
        fulltempfilename = fullfilename + ".tmp"

        # Crypt! (To a temp file) 
        try:
            gpg.encrypt_file(sfileh, recipient, output=fulltempfilename, armor=False)
        except Exception as detail:
            # This catches and ignores exceptions - XXX - Should be 
            # updated to only catch what is expected from the GnuPG module
            logger.warning("Problem while encrypting %s: \"%s\" - Skipping" % (sfile, detail))  
            
            # Attempt to unlink the temp file, if it was created
            try:
                os.unlink(fulltempfilename)
            except OSError as exc:
                # Ignore error for missing temp file - good!
                if exc.errno == errno.EEXIST:
                    pass
                else:
                    # Pass this up - Something else is happening
                    raise

            # Process the next file
            continue
        
        # Move the temp to the final location
        try:
            os.rename(fulltempfilename, fullfilename)
        except OSError as exc: # Python >2.5
            if exc.errno == errno.EEXIST:
                pass
            else:
                raise
        
        destfiles.append([filename, destpath])

        logger.info("Completed encrypting file %s" % fullfilename)


class EmailReportHandler(logging.Handler):
    """
    Buffer and generate email reports
    """

    def __init__(self, smtpserver, fromaddr, toaddrs, subjectprefix):
        """
        Setup email reporter:

         smtpserver - Hostname or IP of SMTP relay
         fromaddr - String with email address of sender
         toaddrs - Array of email addresses to send to
         subjectprefix - Common prefix to prepend to all subject lines
        """

        logging.Handler.__init__(self)

        self.smtpserver = smtpserver
        self.fromaddr = fromaddr
        self.toaddrs = toaddrs
        self.subjectprefix = subjectprefix

        # Start with an empty buffer and a NOTSET (0) level high water mark
        self.buf = ""
        self.maxlevel = 0
        self.starttime = time.strftime("%Y-%m-%d %H:%M:%S")

    def emit(self, record):
        """
        Add line to buffer (This is different than most logging handlers,
        which would ship the message immediately on an emit)
        """

        # Save the text
        self.buf += self.format(record) + "\r\n"

        # Update our high water mark for collected messaged
        if record.levelno > self.maxlevel: self.maxlevel = record.levelno

    def send(self, subject, body):
        """
        Send email report with a given subject line and body
        """
        
        # Add runtime info and combine the body provided as an argument
        # with the collected logs
        body += "\r\nStart Time: %s" % self.starttime
        body += "\r\nEnd Time  : %s" % time.strftime("%Y-%m-%d %H:%M:%S") 
        body += "\r\n\r\n" + self.buf
        msg = MIMEText(body)

        # Check maximum level and add a special note in the subject for anything
        # above INFO
        if self.maxlevel > 20:
            notice = "(" + logging.getLevelName(self.maxlevel) + " ALERT) "
        else:
            notice = ""

        # Build our message header
        msg['Subject'] = self.subjectprefix + " " + notice + subject
        msg['From'] = self.fromaddr
        msg['To'] = "; ".join(self.toaddrs)

        # Fire!
        server = smtplib.SMTP(self.smtpserver)
        # server.set_debuglevel(1)
        server.sendmail(self.fromaddr, self.toaddrs, msg.as_string())
        server.quit()


class singleInstance(object):
    """
    PID file based single-instance check
    Based on recipe from http://code.activestate.com/recipes/546512-creating-a-single-instance-application-linux-versi/
    """
                        
    def __init__(self, pidPath):
        '''
        pidPath - Full path to pid file to store running pid in
        '''
        self.pidPath = pidPath

        # Default - Assume not running
        self.lasterror = False

        # Attempt to open pid file and check for running process
        try:
            # Errors out if not present
            pid = open(pidPath, 'r').read().strip()

            # Errors out if process is not running
            os.kill(int(pid), 0)
            
            # Looks like it IS running already
            self.lasterror = True

        except (IOError, OSError):
            # Could not open pid file, or process not running - Either way,
            # we are clear
            self.lasterror = False

        if not self.lasterror:
            # Write out new pid file
            fp = open(pidPath, 'w')
            fp.write(str(os.getpid()))
            fp.close()

    def alreadyrunning(self):
        return self.lasterror

    def __del__(self):
        if not self.lasterror:
            os.unlink(self.pidPath)


class Error(Exception):
    """
    Base class for custom exceptions
    """
    pass

class CapacityError(Error):
    """
    Exception due to low disk space/calculated space
    """

    def __init__(self, overage, msg):
        self.overage = abs(overage)
        self.msg = msg

    def __str__(self):
        """
        Return the stored message
        """
        return self.msg


class GeneralError(Error):
    """
    Well handled exceptions - These represent normal operation errors and not
    coding or critical system problems
    """

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class Configure(ConfigParser.ConfigParser):
    """
    Read and maintain configuration settings - Customized for this program
    """

    def __init__(self):
        """
        Read in configuration from command line and config file(s).  Stores
        a cleaned dictionary called "settings" that should be usable without
        further processing
        """
        ConfigParser.ConfigParser.__init__(self)

        settings = {}

        # Parse arguments - XXX - Move this to argparse soon
        #  Great example of merged ConfigParser/argparse:
        #  http://blog.vwelch.com/2011/04/combining-configparser-and-argparse.html
        progname = os.path.basename(__file__)
        parser = optparse.OptionParser(usage="%s [-c FILE]" % progname, version="%s %s" % (progname, VERSION))
        parser.add_option("-c", "--config", dest="conffile", help="use configuration from FILE", metavar="FILE")
        (options, args) = parser.parse_args()
        
        if options.conffile is None:
            # No config passed, so try the default
            conffile = DEFCONFFILE
        else:
            conffile = options.conffile

        if not os.path.isfile(conffile):
            # This is just a quick check that the config file exists
            parser.error("Configuration file %s not found" % conffile)
    
        try:
            # Read in configuration file
            self.read(conffile)
        except ValueError:
            raise GeneralError("Bad value in config file - Check your %(variable)s replacements!")

        if not self.has_section('encrarch'):
            raise GeneralError("You MUST have a [encrarch] section! None found in %s\n" % conffile)

        # The current config file setup only cares about the [encrarch] settings
        # at this time.  It will be stored in the settings hash

        # Check for required settings under the [encrarch] section
        req = ['encryptto', 'sourcebase', 'sourcematch', 'destroot', 'pidfile'] 
        errs = ""
        for item in req:
            if not self.has_option('encrarch', item):
                errs += "\n* You must set '%s' in your configuration file" % item
            else:
                settings[item] = self.get('encrarch', item)

        if errs:
            # Spit out all missing parameters at once
            raise GeneralError(errs)

        # If SMTP reporting is enabled, check for those required values
        if self.has_option('encrarch', 'emailon'):
            settings['emailon'] = self.get('encrarch', 'emailon').lower()
            if re.match('all|errors', settings['emailon']):
                req = ['smtpserver', 'emailto', 'emailfrom', 'emailsubject'] 
                errs = ""
                for item in req:
                    if not self.has_option('encrarch', item):
                        errs += "\n* For SMTP reports, you must set '%s' in your configuration file" % item
                    else:
                        if item == 'emailto':
                            settings[item] = self.get('encrarch', item).split(';')
                        else:
                            settings[item] = self.get('encrarch', item)
                        
                        
                if errs:
                    # Spit out all missing parameters at once
                    raise GeneralError(errs)
        
            else:
                # Bad setting
                raise ConfigParser.Error("Invalid 'emailon' value - Must be all or errors")


        # Process optionals to allow for less error prone handling going forward
        settings['instancename'] = self.get('encrarch', 'instancename', 'encrarch')

        if 'temppreserve' in settings:
            settings['temppreserve'] = config['encrarch'].getboolean('temppreserve')
        else:
            settings['temppreserve'] = False
        
        # Do not save a temp copy by default
        settings['tempbase'] = self.get('encrarch', 'tempbase', '')

        settings['destdateformat'] = self.get('encrarch', 'destdateformat', '%Y-%m')
        
        # Set logging level
        if self.has_option('encrarch', 'loglevel'):
            settings['loglevel'] = self.get('encrarch', 'loglevel').upper()
            if not re.match('CRITICAL|ERROR|WARNING|INFO|DEBUG', settings['loglevel']):
                raise ConfigParser.Error("Invalid loglevel '%s' - Must be CRITICAL, ERROR, WARNING, INFO, or DEBUG" % settings['loglevel'])
        else:
            settings['loglevel'] = "INFO"

        # Set the value right here to the logging friendly value
        settings['loglevel'] = getattr(logging, settings['loglevel'])

        # Save screened settings back to config 
        self.settings = settings

    def get_settings(self):
        """
        Return the stored settings dictionary
        """
        return self.settings


def main ():
    # Get configuration with our special Config class
    try:
        conf = Configure()
    except Exception, err:
        sys.exit("Problem loading configuration: %s" % err)

    # Pull settings hash for quick access
    sets = conf.get_settings()

    # Build full destination path
    destbase = os.path.join(sets['destroot'], time.strftime(sets['destdateformat']))

    # Setup base logger and formatting
    logger = logging.getLogger(sets['instancename'])
    logger.setLevel(sets['loglevel'])
    
    # Syslog-ish messages with a starting timestamp
    format = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')

    # Simple console logger
    clog = logging.StreamHandler()
    clog.setFormatter(format)
    logger.addHandler(clog)
    
    # Syslog - XXX - Should add ability to change log facility
    slog = logging.handlers.SysLogHandler(facility=syslog.LOG_DAEMON)
    logger.addHandler(slog)
    
    # Custom EmailReport handler - Designed to collect all messages and send
    # one blast at the end
    if 'emailon' in sets:
        elog = EmailReportHandler(sets['smtpserver'], sets['emailfrom'], sets['emailto'], sets['emailsubject'])
        elog.setFormatter(format)
        logger.addHandler(elog)

    # Handy lambda to pretty print sizes - From Anonymous post to
    # http://www.5dollarwhitebox.org/drupal/node/84
    humansize = lambda s:[(s%1024**i and "%.1f"%(s/1024.0**i) or str(s/1024**i))+x.strip() for i,x in enumerate(' KMGTPEZY') if s<1024**(i+1) or i==8][0]
    
    # Wrap main flow so we can email alert reliably
    try:
        # Check for parallel run and die if another is really running
        thisapp = singleInstance(sets['pidfile'])
        if thisapp.alreadyrunning():
            logger.error("Previous instance already running! Remove pidfile %s if incorrect" % sets['pidfile'])
            raise GeneralError("Already Running")
            
        # Mark our start time
        starttime = time.time()
            
        # Make sure the GPG key exists before wasting a bunch of cycles
        try:
            recuser = lookupKeyFingerprint(sets['encryptto'])
        except:
            logger.error("Could not find key for ID %s" % sets['encryptto'])
            raise GeneralError("Missing PGP Key")

        # Find our source files and copy into temp folders
        sources = findSourceFiles(sets['sourcematch'], sets['sourcebase'])
        
        if not (len(sources)):
            logger.warn("No suitable files matching %s found in %s" % (sets['sourcematch'], sets['sourcebase']))
            raise GeneralError("No Files To Backup")

        # Check for required space on final destination drive
        (calcroom, reqspace) = roomForFiles(sets['sourcebase'], sources, sets['destroot'])

        if calcroom < 0:
            logger.error("Insufficient space under %s to hold total archive size of %sB! Free %sB to allow archive" % (sets['destroot'], humansize(reqspace), humansize(abs(calcroom))))
            raise CapacityError(calcroom, "Low Pre-Archive Destination Space")

        # If using a temp location, copy our sources to it
        if sets['tempbase']:
            logger.info("Copying from %s to temporary location %s" % (sets['sourcebase'], sets['tempbase']))
            copySourceToTempSource(sources, sets['sourcebase'], sets['tempbase'])
            workingsourcebase = sets['tempbase']

        else:
            # We will work with the real source, not a temp source
            workingsourcebase = sets['sourcebase']

        # Create dest folders and encrypt/compress files, saving into folders
        logger.info("Encrypting files for %s" % recuser)

        encryptSourcesToDestination(sources, workingsourcebase, destbase, sets['encryptto'], logger)

        # Shut it down and report elapsed time
        endtime = time.time()
        logger.debug("Completed archiving of %sB after %s" % (humansize(reqspace), datetime.timedelta(seconds=int(endtime - starttime))))

        # Recheck free space - We need to notify the user if the NEXT archive run is
        # likely to fail so they have time to switch out destinations.
        (calcroom, reqspace) = roomForFiles(sets['sourcebase'], sources, sets['destroot'])

        if calcroom < 0:
            logger.error("Preemptive notice: Next archive may fail!  Low space on %s - Please free %sB before next archive" % (sets['destroot'], humansize(abs(calcroom))))
            raise CapacityError(calcroom, "Low Post-Archive Destination Space")

    except CapacityError as detail:
        if 'emailon' in sets: elog.send("Destination Capacity Insufficient", "Please free at least %sB on %s" % (humansize(detail.overage), sets['destroot']))
        sys.exit(1)
    except GeneralError as detail:
        if 'emailon' in sets: elog.send("Problems Encountered", "GeneralError: %s\r\nPlease review the log and investigate as needed" % detail)
        sys.exit(1)
    except KeyboardInterrupt:
        if 'emailon' in sets: elog.send("Archive Canceled", "Archive canceled by user")
        sys.exit(1)
    except:
        if 'emailon' in sets: elog.send("Unhandled Problems Encountered", "Unexpected errors were encountered - Please review and forward to support:\r\n\r\n%s" % traceback.format_exc())
        raise
    else:
        if (('emailon' in sets) and (sets['emailon'] == "all")):  
            elog.send("Archive Completed Without Errors", "Job completed normally. Archived/encrypted from %s to %s" % (sets['sourcebase'], sets['destroot']))
 
    finally:
        # Clear our temp files if being used and set to clear temp
        if sets['temppreserve'] == True and sets['tempbase']:
            clearTempSource(sources, sets['tempbase'])

    exit(0)


if __name__ == '__main__':
    main()


