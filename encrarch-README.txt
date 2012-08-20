================================
 encrarch - Encrypt and Archive
================================

**encrarch** uses GnuPG to create an encrypted archive of one or more files in a source directory.  Its main use is for securely storing disk 2 disk backups on removable media, like external hard drives.  The removable media can be manually rotated on a schedule to create weekly, monthly, yearly, etc. archives.

**encrarch** relies on GnuPG.  Safe key handling is crucial to the security of the system, and your ability to recover from the encrypted backups.  (See PRECAUTIONS)


REQUIREMENTS
------------
* Designed for UNIX/Linux - May require modification to run on Windows
* Python 2.6+
* GnuPG


INSTALLATION
------------
* Install the python-gnupg package from http://code.google.com/p/python-gnupg/
  (Example shows fetching current version - Adjust accordingly)

::

  cd /tmp
  wget "http://python-gnupg.googlecode.com/files/python-gnupg-0.2.8.tar.gz"
  tar xvzf python-gnupg-0.2.8.tar.gz
  cd python-gnupg-0.2.8
  python setup.py install

* For standard systems, copy encrarch.py into /usr/local/bin

::

 cp encrarch.py /usr/local/bin

* For QNAP or other systems that use a "ramdrive" that is erased on boot up, store *encrarch.py* in a persistent location.  (For instance, on QNAP, under a share.)  **GnuPG settings and keys will also be lost on reboot for most of these systems.  Make sure to save the user's ~/.gnupg folder after making changes.  A simple script to copy this back into place on boot will take care of the rest.**


GNUPG SETUP AND KEY HANDLING
----------------------------
For those unfamiliar with Gnu Privacy Guard, some basic setup is required before use.

* A pubic/secret keypair must be created.  As the user that will run *encrarch.py*, you can create a new key as follows:

::
 
 gpg --gen-key
 
 # Choose RSA and RSA for the key type
 # Choose 2048 as the key size
 # Set key NOT to expire (0)
 # Confirm that the key should not expire at all
 # Set a real name for the key like "HOSTNAME encrarch" - Example: "nas1 encrarch"
 # Set an email address like hostname.encrarch@customerdomain - Example: nas1.encrarch@example.net
 # Set a comment if desired
 # Press O to okay the key settings
 # Enter a STRONG passphrase - DO NOT REUSE THIS PHRASE OR USE AN EXISTING PASSWORD!
 # Note the pub key's ID, which follows "pub 2048/" in the returned text.  (You can also use gpg --list-keys to view the ID)
 
* Note the key ID!  This will be used in the configuration 
* For best performance with good security, add the next two lines to the users ~/.gnupg/gpg.conf file to disable compression and use the fast and secure AES-128 cipher:

::

 personal-compress-preferences Uncompressed
 personal-cipher-preferences AES

* Remember that ramdrive based systems will often DELETE /root/ and other user folders on reboot, so copy the ~/.gnupg folder to a persistent location on the system before rebooting and use the gnupghome configuration option in your encrarch config to point to the alternate location.

This is the single most import part of this whole system: **IF YOU LOSE THE SECRET KEY, YOU CAN NOT READ THE ARCHIVES!** ALWAYS make an emergency backup of your secret (private) key!

* Insert an empty and formatted USB stick (preferably very small) into the system
* Change directory to the base of the mounted thumb drive

::

 cd /mount/sda1

* Export your public and private keyrings to armored text files:

::

 # Use of a descriptive filename will help prevent confusion - SYSTEMNAME-YYYY-MM-DD is shown:
 gpg -a --export > SYSTEMNAME-YYYY-MM-DD-public.asc
 gpg -a --export-secret-keys > SYSTEMNAME-YYYY-MM-DD-private.asc
 
 # Example: If the system was named ancient1 and the date was Jan. 13th, 1045:
 gpg -a --export > ancient1-1045-01-13-public.asc
 gpg -a --export-secret-keys > ancient1-1045-01-13-private.asc

* You may want to also copy this document (that you are reading right now) to the USB drive for an emergency reference.
* **UNMOUNT THE THUMBDRIVE IMMEDIATELY AND STORE IN A VERY SECURE PLACE!** - The exported keys are NOT protected!!

* *To import your private and public keys from the backup copy:*

::

 gpg --import < IMPORTKEYFILE


PRECAUTIONS
-----------

**READ THESE PRECAUTIONS CAREFULLY!** Failure to follow these guidelines may result in a useless archive or data theft!  Note the massive overuse of bold text and capitals below are for good reason.  Yes: I am yelling!

* **PRIVATE KEYS EXPORTED TO USB DRIVES ARE NOT ENCRYPTED!!!!** - Unmount the drive and store in a safety deposit box or safe. It is for emergency use ONLY!

* **YOUR DATA WILL NOT BE READABLE WITHOUT THE PRIVATE (SECRET) PGP KEY!!!** - Make sure to save the USB backup somewhere safe. This can be in the same vault or remote location as the removable hard drives containing the encrypted files.

* **NEVER TRANSPORT THE USB BACKUP KEY WITH ANY DEVICE CONTAINING FILES ENCRYPTED FOR THE KEY!!!** - If lost or stolen, someone with both the USB key and any form of encrypted files WILL be able to decrypt the files.

* **IF YOU ARE USING A QNAP OR OTHER NAS WITH A RAMDISK** - You need to take additional steps to SAVE the PGP keys on your system so they will not be lost on a reboot!  encrarch supports placing the user's keys and options into an alternate path instead of ~/.gnupg.

* **TEST YOUR RECOVERY PROCESS!!!** - What good is a backup you can't use?  Make sure to test your backup process, and include test recoveries of *encrarch* created archives with your regular disaster recovery tests.


CONFIGURATION
-------------

encrarch requires a Python configparser configuration file.  (Future versions may support full configuration via command line.)

Use the included *encrarch.conf-SAMPLE* as a starting point, copying it to */etc/encrarch.conf* (standard systems) or in a safe/persistent location (QNAP/other flash systems).  If the file is not named */etc/encrarch.conf*, you must set it via command line with the *-c CONFIGFILE* option.  Each configuration file defines a source, a destination, and a key to encrypt to.  Use multiple files as needed.

The following outlines configuration steps, showing example settings that may or may not be useful.  You MUST customize your configuration!

* Set an "instance" name - This is to distinguish between multiple jobs.  (The default of "encrarch" is fine if you are only running one encrarch job)

::

 instancename = encrarch

* Set the sourcebase to the directory you want to copy from.  This can contain subdirectories - encrarch will search for files to backup

::

 sourcebase = /mnt/backups

* Set the source file matching pattern.  For most D2D backups, using *.<SUFFIXNAME> is suitable.  (*.vbk for Veeam, *.spf|*.spi for Shadow Protect, etc)  See pydoc fnmatch for more information

::

 sourcematch = \*.vbk

* Enable skipping of older files with the same starting name.  Most backup systems create files that start with the job name and then have a timestamp.  For instance, VEEAM uses "JOBNAMEYYYY-MM-DDThhmmss.vbk".  If multiple full backups are in the same folder and are part of the same job, this feature allows you to skip all but the latest (by modification stamp on the file).  Comment out to disable the feature. 

::

 sourcejobnameregex = ^(.+)\d{4}\-\d{2}\-\d{2}T\d{6}\.vbk

* Set the base directory to archive to.  Archived files will be stored in time stamped subfolders of this base.

::

 destroot = /mnt/save

* Date format for first subfolder under destroot to save to - See the strftime() Python documentation for more options.  The default is %Y-%m which is YYYY-MM.  Using %Y-%m, you can call this every day and over time will end up with one folder per-month containing the last backup of the month.

::

 destdateformat = %Y-%m

* For large jobs, you may want to use a temp space to store a copy of the files being encrypted.  Set the tempbase value if you want to enable this behavior

::

 tempbase = /mnt/scratchdrive

* In some cases, you may even want to keep the temp copy around.  Set temppreserve to true to prevent deletion of temp files after encrypting

::

 temppreserve = true

* If the gpg binary is not installed under a folder listed in your PATH, or if your PATH is not set, (as the case in some crude crons), gpgbinary should be set to the full path to your gpg binary. Uncomment to keep the default (just "gpg")

::

 gpgbinary = /opt/gnupg/bin/gpg

* If you are running encrarch as an alternate user, or if you have moved your GnuPG configuration and key files to an alternate location, you can set gnupghome to the full path for the alternate .gnupg folder.  If not set, the default is /home/USERNAME/.gnupg 

::

 gnupghome = /home/someotherdude/.gnupg

* You must set the GnuPG key you wish to encrypt TO.  Use "gpg --list-keys" to find the fingerprint, which is a 8 character hex value.  For example, for this output

::

  pub   2048D/A7D02D34 2011-01-09 [expires: 2013-01-08]
  uid                  Paul M. Person <paulguy@thepaulguy.int>

- the ID is A7D02D34 and the configuration would be

::

 encryptto = A7D02D34

* Set syslog to true to enable writing log messages to the DAEMON syslog facility

::

 syslog = true

* You can log to an optional log file - Set filelog to the name of the file to enable

::

 logfile = "/path/to/logfile"

* If filelog is set, you can set a size limit (in bytes).  Set to 0 to allow infinite size. 1MB shown

::

 logfilesize = 1048576 

* If a file size limit is set, you can set a number of old log files to keep

::

 logfilekeep = 7

* Email reports can be sent on "errors" or "all" conditions.  Comment out the emailon line if you do not want to send email

::

 emailon = errors

* If emailon is set, you must configure an SMTP server IP or domain name - SMTP auth is not supported at this time, so add the IP of the machine running encrarch to the list of allowed IPs in your SMTP server

::

 smtpserver = 10.11.12.13

* emailon also requires one or more email addresses to notify via email - Separate multiple addresses with commas

::
 
 emailto = jerry.only@misfits.int, danzig@danzigcorp.net

* Set the from email address 

::

 emailfrom  = encrarch@example.int

* Set the prefix for the Subject: line in email notices.  Additional information is added after the prefix.  Note that in the example below, encrarch replaces %(instancename)s with the *instancename* set at the top.  The setting below is recommended

::

 emailsubject = [%(instancename)s]

* While the logging module used by encrarch does allow for direct configuration via a config file, it is overkill at this time.  So, logging is always to syslog.  Set the level to log below.  The default is INFO.  Valid settings are: CRITICAL, ERROR, WARNING, INFO, or DEBUG

::

 loglevel = DEBUG

* Use of a PID file allows *encrarch* to exit if another run of the same instanc e name is in progress.  The setting below is usually fine, and will update automaticlly based on the instancename.

::

 pidfile = /var/tmp/%(instancename)s.pid


USAGE
-----

If you run encrarch without any options, it will use the default configuration file */etc/encrarch.conf*

::

 encrarch.py

Use the -c option to define an alternate configuration file

::

 encrarch.py -c /some/other/encrarchconfig.conf

The encrarch process is as follows:

* The *sourcebase* path is searched for files matching *sourcematch*
* Free space under *destroot* is checked.  encrarch aborts if the destination path does not have the required free space to hold the addition contents being copied. (The larger your source, the more free space required.)
* If *tempbase* is defined, subfolders matching the structure of *sourcebase* are created and then all files matching *sourcematch* are copied into the *tempbase* path
* File by file (for each matching *sourcematch*)

 - The source file is read from out of *tempbase*, if
   set, or *sourcebase* if no temp base is defined
 - The source file is encrypted using GnuPG and the *encrypto* key
 - Encrypted data is written into *destroot*/*destdateformat*, where *destdateformat* is replaced using the current date.  If *tempbase* is used, the files are read from temp, else they are read directly from *sourcebase*.  Each file is saved to *SOURCEFILENAME.tmp* while writing
 - Once encryption completes for the file, it is renamed to *SOURCEFILENAME*

* While running, encrarch logs messages to STDERR and to syslog using the the DAEMON facility.  In most cases, this means messages appear in /var/log/messages. 
* When complete, the free space in *destroot* is again checked.  A preemptive warning is sent if the next run would fail due to limited free space.
* If *emailon* is set, email notification will be sent on and error (if set to "error") or for either and error or a normal result (if set to "all")
* If *tempbase* IS set and *temppreserve* is NOT set, files are removed from *tempbase*

Recovery of data from an encrarch created archive set is a manual process, requiring free space to place the decrypted files and **the GnuPG secret key** to match the key used to encrypt.

* For each file you wish to recover:

::

 gpg -do DESTINATIONFILENAME SOURCEFILENAME
 
 # For instance, if your archive is mounted under /mnt/sdc1, and you want
 # to recover the file "FullBackup.vbk.gpg" from /mnt/sdc1/2012-11/FullBackup/
 # to /share/Recovery/FullBackup.vbk :
 gpg -do /share/Recovery/FullBackup.vbk /mnt/sdc1/2012-11/FullBackup/FullBackup.vbk.gpg


ADDITIONAL INFORMATION
----------------------
* *pydoc encrarch* - Embedded documentation from encrarch.py
* *man gpg* - GnuPG main manual page



:Authors:

Paul M. Hirsch <paul.hirsch@citon.com>


