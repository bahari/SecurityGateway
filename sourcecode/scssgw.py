#############################################################################################################
# File:        scssgw.py
# Description: Main security gateway script to initiate secure network connection to RPS
#              ----------------------------------------------------------------------------------------------
# Notes      : Major, Minor and Revision notes:
#              ----------------------------------------------------------------------------------------------
#              Major    - Software major number will counting up each time there is a major changes on the 
#                         software features. Minor number will reset to '0' and revision number will reset
#                         to '1' (on each major changes). Initially major number will be set to '1'
#              Minor    - Software minor number will counting up each time there is a minor changes on the
#                         software. Revision number will reset to '1' (on each minor changes).
#              Revision - Software revision number will counting up each time there is a bug fixing on the
#                         on the current major and minor number.
#              ----------------------------------------------------------------------------------------------
#              Current Features & Bug Fixing Information
#              ----------------------------------------------------------------------------------------------
#              0001     - Initiate encryption process for NC2VPN file and stored the encrypted file permanently
#                         inside local folder. Each time new NC2VPN file are stored inside USB stick, it will
#                         automatically generate the new encrypted NC2VPN file inside the local folder.
#              0002     - Initiate decryption process for local stored encrypted NC2VPN file to initiate VPN
#                         tunnel. After each VPN tunnel initiation, the NC2VPN decrypted file will be deleted
#                         permanently.
#              0003     - Automatically create private and public key for NC2VPN file decryption process. Each time
#                         after encrypted process, the private key will be transfer automatically to the
#                         USB stick and the existing NC2VPN file inside the stick will be deleted.
#              0004     - The security gateway only valid when client machine connected and USB stick are plug
#                         in to the controller.
#              0005     - Automatic monitored USB stick availability inside controller.
#              0006     - Continuous monitored connected client, USB stick availability, 4G LTE modem current
#                         status and VPN tunnel connectivity.
#              0007     - Continuous monitored battery status for power management functionalities.
#              0008     - LCD functionalities for current gateway status and information.
#              0009     - Adding SDR radio monitoring server mode by macro script parameter upon initiate the
#                         script. During this mode, ping process to the connected client, VPN functionalities
#                         crypto functionalities and USB stick monitoring will be disable.
#              0010     - Used different type of SDR radio monitoring server mode (rsp_tcp) upon initiate the
#                         script.
#              0011     - Macro for optional different radio server, which consists of option soapy sdr server
#                         RSPTCP server and custom gnuradio radio data server
#              0012     - Add logic for radio server option based on macro arguments selection at networkMon()
#                         function.
#              0013     - Add try-except for LCD and UPS-lite i2c devices at the beginning of the script, to
#                         check whether i2c devices are exist or not.
#              0014     - Add flag for i2c devices availability checking for LCD and UPS-lite. Add flag 
#                         checking on the LCD operation function (lcdOperation()) and battery status operation
#                         function (checkBattStatus()). When either one of the i2c devices are failed, it will
#                         switch to default print statement for LCD operation and default value for current 
#                         battery status value.
#
#              ----------------------------------------------------------------------------------------------
# Author : Ahmad Bahari Nizam B. Abu Bakar.
#
# Version: 1.0.1
# Version: 1.0.2 - Add feature item [0010]. Please refer above description
# Version: 1.0.3 - Add feature item [0011,0012]. Please refer above description
# Version: 1.0.4 - Add feature item [0013,0014]. Please refer above description
#
# Date   : 18/02/2021 (INITIAL RELEASE DATE)
#          UPDATED - 23/02/2021 - 1.0.2
#          UPDATED - 02/03/2021 - 1.0.3
#          UPDATED - 02/03/2021 - 1.0.4
#
#############################################################################################################

from __future__ import unicode_literals
import os, re, sys, time, socket
import thread
import logging
import logging.handlers
import subprocess
import struct
#import smbus
import pyinotify
#import I2C_LCD_driver
import pyudev

import os.path
from os import path

# Global variable declaration
backLogger         = False    # Macro for logger
raspiIO            = False    # Macro for pi zero w IO interfacing
radioMode          = False    # Macro for radio mode functionalities
ubuntuTouch        = False    # Macro for ubuntu touch devices
radioOpt           = 0        # Macro for radio data mode of transmission
radioValid         = False    # Flag to indicate SDR radio server are successfully initiated
dCryptProc         = False    # Flag to indicate decryption process are successfully done 
eCryptProc         = False    # Flag to indicate encryption process are successfully done
tunnelValid        = False    # Flag to indicate the VPN tunnel are successfully initiated
net4gValid         = False    # Flag to indicate 4G network are successfully initiated
scrollUP           = False    # Scroll UP process flag during tact switch is pressed
scrollDWN          = False    # Scroll DOWN process flag during tact switch is pressed
i2cUps             = False    # Flag to check UPS-Lite i2c initialization status
i2cLcd             = False    # Flag to check LCD i2c initialization status
initPihole         = False
wifiShutDown       = False
pubKeyPath         = ''       # Public key to decrypt the USB thumb drive
usbMountPath       = ''       # USB mount path directory
nc2VpnKeyPath      = ''       # NC2VPN encrypted key file directory location 
nc2VpnKeyTPath     = ''       # NC2VPN decrypted key temporary file directory location
currUSBPath        = ''       # Current detected USB stick path after insertion
lcdBattVolt        = ''       # Stored current battery voltage value for LCD information display
lcdBattCap         = ''       # Stored current battery capacity value for LCD information display
clientIPAddr       = ''       # Stored client machine IP address that connected to the gateway
publicIPaddr       = ''       # Stored public IP address
delayRdBatt        = 0        # Read battery status via i2c interval counter
lcdBlTimeOut       = 0        # LCD back light time out counter/delay 
lcdOperSel         = 0        # LCD display operation mode for different display info
lcdDlyStatCnt      = 0        # LCD display info switch between date-time, gateway and battery current status
netMonChkCnt       = 0        # Network monitoring process checking counter
net4gAtmptCnt      = 0        # 4G LTE modem connection attempt counter
vpnAtmptCnt        = 0        # VPN tunnel connection attempt counter

# Check for macro arguments
if (len(sys.argv) > 1):
    tmpFlag = False
    tmpFlagg = False
    for x in sys.argv:
        if x != 'scssgw.py':
            # Get the SIM card public IP address
            if tmpFlag == False:
                publicIPaddr = x
                tmpFlag = True

            # Get the rest of the parameters 
            elif tmpFlag == True:
                # Get client IP address for pinging process
                if tmpFlagg == False:
                    clientIPAddr = x
                    tmpFlagg = True
                elif tmpFlagg == True:
                    # Optional macro if we want to enable text file log
                    if x == 'LOGGER':
                        backLogger = True
                    # Optional macro if we want to enable raspberry pi IO interfacing
                    elif x == 'RASPI':
                        raspiIO = True
                    # Optional macro for radio gateway functionality
                    elif x == 'RADIO':
                         radioMode = True
                    # Option for soapy sdr server
                    elif x == 'OPT01':
                        radioOpt = 0
                    # Option for RSPTCP server
                    elif x == 'OPT02':
                        radioOpt = 1
                    # Option for custom gnuradio radio data server
                    elif x == 'OPT3':
                        radioOpt = 2
                    # Option for ubuntu touch devices
                    elif x == 'UBUNTU':
                        ubuntuTouch = True

# Setup log file 
if backLogger == True:
    paths = os.path.dirname(os.path.abspath(__file__))
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logfile = logging.handlers.TimedRotatingFileHandler('/tmp/secgw.log', when="midnight", backupCount=3)
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    logfile.setFormatter(formatter)
    logger.addHandler(logfile)

# Print macro arguments for debugging purposes
# Write to logger
if backLogger == True:
    logger.info("DEBUG_MACRO: Arguments: %s %s %s %s %s %s" % (publicIPaddr, backLogger, raspiIO, radioMode, radioOpt, str(ubuntuTouch)))
# Print statement
else:
    print "DEBUG_MACRO: Arguments: %s %s %s %s %s %s" % (publicIPaddr, backLogger, raspiIO, radioMode, radioOpt, str(ubuntuTouch))
                
# Setup for pi zero w GPIO interfacing
if raspiIO == True:
    import RPi.GPIO as GPIO

    # Setup for raspberry pi GPIO
    # Setup GPIO 
    GPIO.setmode(GPIO.BCM)

    # GPIO17 INPUT for activate scroll UP LCD information
    # Active LOW
    GPIO.setup(17, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    # GPIO18 INPUT for activate scroll DOWN LCD information
    # Active LOW
    GPIO.setup(24, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    # GPIO27 for LCD back light indicator 
    GPIO.setup(27, GPIO.OUT)

    # Turn OFF LCD back light
    GPIO.output(27, GPIO.LOW)
    #GPIO.output(27, GPIO.HIGH)
    
# Retrieve public key stored location
pubKeyPath = '/sources/common/sourcecode/piSecurityGateway/key.public'

# For Raspberry PI controller
if ubuntuTouch == False:
    # USB thumb drive mount path
    usbMountPath = '/media/root'

# For Ubuntu Touch smartphone
else:
    # USB thumb drive mount path
    usbMountPath = '/media/phablet'
    
# nc2vpn key path - Encrypted file
nc2VpnKeyPath = '/sources/common/vpn-client-key/nc2vpn-key'
# nc2vpn key temporary path - Decrypted file
nc2VpnKeyTPath = '/sources/common/vpn-client-key/temp-nc2vpn-key'
# Client computer hard coded IP address
clientIPAddr = '192.168.4.201'

# Only check when using Raspberry PI controller
if ubuntuTouch == False:
    import smbus
    import I2C_LCD_driver
    
    # Checking the LCD i2c device availability
    try:
        # Initialize i2c bus for USB lite
        i2cBus = smbus.SMBus(1)
        i2cUps = True
    except:
        i2cUps = False

    # Checking the UPS-Lite i2c device availability
    try:    
        # Initialize i2c bus for LCD
        mylcd = I2C_LCD_driver.lcd()
        i2cLcd = True
    except:
        i2cLcd = False

# Class for USB thumb drive insertion automatic notification
# Also include encrypt and decrypt nc2vpn key process
# Process that will be done:
# 1 - Check file contents inside USB file, whether to encrypt or decrypt - Checking the availability of crypto private key.
#     If there is no private key (key.private), then new encrypt process for nc2Vpn file need to be done.
#     If private key are available, then only decrypt process that need to be done
# 2 - 
class EventHandler(pyinotify.ProcessEvent):
        
    def __init__(self, public_key, nc2vpnkeypath, nc2vpnkeytpath):
        self.public_key = public_key
        self.nc2vpnkeypath = nc2vpnkeypath
        self.nc2vpnkeytpath = nc2vpnkeytpath
        self.cryptoType = False
        
    def process_IN_CREATE(self, event):
        global backLogger
        global lcdOperSel
        global dCryptProc
        global eCryptProc
        global currUSBPath
        global radioMode
        
        if os.path.isdir(event.pathname) and radioMode == False:
            # Copy the detected USB path to local variable, for later usage
            currUSBPath = event.pathname

            # Write to logger
            if backLogger == True:
                # print("New mounted volume detected: " + event.pathname)
                logger.info("DEBUG_CRYPTO: New mounted volume detected: %s" % (event.pathname))
            # Print statement
            else:
                print "DEBUG_CRYPTO: New mounted volume detected: %s" % (event.pathname)

            # Wait for the volume to be mounted and avoid permission errors
            time.sleep(1)
            
            # Check private key existence
            tempCmd = 'cd ' + event.pathname + ';ls -la'
            out = subprocess.Popen([tempCmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout,stderr = out.communicate()

            # NO error after command execution
            if stderr == None:
                # Continue with decrypt process
                if 'key.private' in stdout:
                    self.cryptoType = True
                # Continue with encrypt process
                else:
                    self.cryptoType = False
            
            # Start decrypt process
            if self.cryptoType == True:
                # Write to logger
                if backLogger == True:
                    logger.info("DEBUG_CRYPTO: Start DECRYPT process")
                # Print statement
                else:
                    print "DEBUG_CRYPTO: Start DECRYPT process"

                # Change LCD operation mode
                lcdOperSel = 5

                # Delete the contents of nc2vpn key inside temporary folder
                tempArgs = 'cd ' + self.nc2vpnkeytpath + ';rm -rf *'
                out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()

                # NO error after command execution
                if stderr == None:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_CRYPTO: Delete temporary nc2vpn key files successful")
                    # Print statement
                    else:
                        print "DEBUG_CRYPTO: Delete temporary nc2vpn key files successful"

                    # Wait before execute another command
                    time.sleep(1)
                
                    # Start decrypt the nc2vpn key and stored it inside temporary folder
                    # Command:
                    # python3 decrypt.py --source=/path/to/your/drive/ --destination=/path/to/your/drive/ --private-key=/path/to/your/key.private
                    tempPrivKeyPath = event.pathname + '/key.private'
                    out = subprocess.Popen(['python3', 'decrypt.py', '--source', self.nc2vpnkeypath, '--destination', self.nc2vpnkeytpath, '--private-key', tempPrivKeyPath], \
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        if 'Decrypting:' in stdout:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_CRYPTO: Decrypt nc2vpn key successful")
                            # Print statement
                            else:
                                print "DEBUG_CRYPTO: Decrypt nc2vpn key successful"

                            # Change LCD operation mode
                            lcdOperSel = 7
                
                            # Set status of decrypt process
                            dCryptProc = True
                        # Operation failed
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_CRYPTO: Decrypt nc2vpn key FAILED!")
                                logger.info("DEBUG_CRYPTO: DECRYPT process FAILED!")
                            # Print statement
                            else:
                                print "DEBUG_CRYPTO: Decrypt nc2vpn key FAILED!"
                                print "DEBUG_CRYPTO: DECRYPT process FAILED!"

                            # Change LCD operation mode
                            lcdOperSel = 12
                            # Set status of decrypt process
                            dCryptProc = False
                            
                    # Operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_CRYPTO: Decrypt nc2vpn key FAILED!")
                            logger.info("DEBUG_CRYPTO: DECRYPT process FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_CRYPTO: Decrypt nc2vpn key FAILED!"
                            print "DEBUG_CRYPTO: DECRYPT process FAILED!"

                        # Change LCD operation mode
                        lcdOperSel = 12
                        # Set status of decrypt process
                        dCryptProc = False
                            
                # Operation failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_CRYPTO: Delete temporary nc2vpn key files FAILED!")
                        logger.info("DEBUG_CRYPTO: DECRYPT process FAILED!")
                    # Print statement
                    else:
                        print "DEBUG_CRYPTO: Delete temporary nc2vpn key files FAILED!"
                        print "DEBUG_CRYPTO: DECRYPT process FAILED!"

                    # Change LCD operation mode
                    lcdOperSel = 12
                    # Set status of decrypt process
                    dCryptProc = False
                            
            # Start encrypt process
            else:
                # Write to logger
                if backLogger == True:
                    logger.info("DEBUG_CRYPTO: Start ENCRYPT process")
                # Print statement
                else:
                    print "DEBUG_CRYPTO: Start ENCRYPT process"

                # Change LCD operation mode
                lcdOperSel = 1
                
                # Delete first public and private key
                out = subprocess.Popen(["rm -rf key.public key.private"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()

                # NO error after command execution
                if stderr == None:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_CRYPTO: Delete public and private key successful")
                    # Print statement
                    else:
                        print "DEBUG_CRYPTO: Delete public and private key successful"

                    # Wait before execute another command
                    time.sleep(1)

                    # Delete nc2vpn encrypted files from folder: /sources/common/vpn-client-key/nc2vpn-key
                    tempArgs = tempArgs = 'cd ' + self.nc2vpnkeypath + ';rm -rf *'
                    out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_CRYPTO: Delete encrypted nc2vpn key files successful")
                        # Print statement
                        else:
                            print "DEBUG_CRYPTO: Delete encrypted nc2vpn key files successful"

                        # Wait before execute another command
                        time.sleep(1)
                    
                        # Create public and private key first
                        out = subprocess.Popen(['python3', 'generate_keys.py'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            if 'Generated public key at:' in stdout:
                                if 'Generated private key at:' in stdout:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_CRYPTO: Generate crypto public and private key successful")
                                    # Print statement
                                    else:
                                        print "DEBUG_CRYPTO: Generate crypto public and private key successful"

                                    # Wait before execute another command
                                    time.sleep(1)

                                    # Start encrypt nc2vpn key files
                                    out = subprocess.Popen(['python3', 'encrypt.py', '--source', event.pathname, '--destination', self.nc2vpnkeypath, '--public-key', self.public_key], \
                                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                    stdout,stderr = out.communicate()

                                    # NO error after command execution
                                    if stderr == None:
                                        if 'Encrypting:' in stdout:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_CRYPTO: Encrypt nc2vpn key successful")
                                            # Print statement
                                            else:
                                                print "DEBUG_CRYPTO: Encrypt nc2vpn key successful"

                                            # Wait before execute another command
                                            time.sleep(1)

                                            # Delete nc2vpn key inside USB thumb drive
                                            tempArgs = 'cd ' + event.pathname + ';rm -rf *'
                                            out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                                            stdout,stderr = out.communicate()

                                            # NO error after command execution
                                            if stderr == None:
                                                # Write to logger
                                                if backLogger == True:
                                                    logger.info("DEBUG_CRYPTO: Delete nc2vpn key inside USB thumb drive successful")
                                                # Print statement
                                                else:
                                                    print "DEBUG_CRYPTO: Delete nc2vpn key inside USB thumb drive successful"

                                                # Wait before execute another command
                                                time.sleep(1)

                                                # Copy private key to USB thumbdrive
                                                tempArgs = 'cp key.private ' + event.pathname 
                                                out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                                                stdout,stderr = out.communicate()
                                                
                                                # NO error after command execution
                                                if stderr == None:
                                                    # Write to logger
                                                    if backLogger == True:
                                                        logger.info("DEBUG_CRYPTO: Copy private key to USB thumb drive successful")
                                                    # Print statement
                                                    else:
                                                        print "DEBUG_CRYPTO: Copy private key to USB thumb drive successful"

                                                    # Wait before execute another command
                                                    time.sleep(1)

                                                    # Delete private key from local folder
                                                    out = subprocess.Popen(['rm -rf key.private'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                                    stdout,stderr = out.communicate()

                                                    # NO error after command execution
                                                    if stderr == None:
                                                        # Write to logger
                                                        if backLogger == True:
                                                            logger.info("DEBUG_CRYPTO: Delete private key from local folder successful")
                                                            logger.info("DEBUG_CRYPTO: ENCRYPT process successful")
                                                        # Print statement
                                                        else:
                                                            print "DEBUG_CRYPTO: Delete private key from local folder successful"
                                                            print "DEBUG_CRYPTO: ENCRYPT process successful"

                                                        # Change LCD operation mode
                                                        lcdOperSel = 3
                                                        # Set status of encrypt process
                                                        eCryptProc = True
                
                                                    # Operation failed
                                                    else:
                                                        # Write to logger
                                                        if backLogger == True:
                                                            logger.info("DEBUG_CRYPTO: Delete private key from local folder FAILED!")
                                                            logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                                                        # Print statement
                                                        else:
                                                            print "DEBUG_CRYPTO: Delete private key from local folder FAILED!"
                                                            print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                                                        # Change LCD operation mode
                                                        lcdOperSel = 13
                                                        # Set status of decrypt process
                                                        eCryptProc = False

                                                # Operation failed
                                                else:
                                                    # Write to logger
                                                    if backLogger == True:
                                                        logger.info("DEBUG_CRYPTO: Copy private key to USB thumb drive FAILED!")
                                                        logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                                                    # Print statement
                                                    else:
                                                        print "DEBUG_CRYPTO: Copy private key to USB thumb drive FAILED!"
                                                        print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                                                    # Change LCD operation mode
                                                    lcdOperSel = 13
                                                    # Set status of decrypt process
                                                    eCryptProc = False

                                            # Operation failed
                                            else:
                                                # Write to logger
                                                if backLogger == True:
                                                    logger.info("DEBUG_CRYPTO: Delete nc2vpn key inside USB thumb drive FAILED!")
                                                    logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                                                # Print statement
                                                else:
                                                    print "DEBUG_CRYPTO: Delete nc2vpn key inside USB thumb drive FAILED!"
                                                    print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                                                # Change LCD operation mode
                                                lcdOperSel = 13
                                                # Set status of decrypt process
                                                eCryptProc = False

                                        # Operation failed
                                        else:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_CRYPTO: Encrypt nc2vpn key FAILED!")
                                                logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                                            # Print statement
                                            else:
                                                print "DEBUG_CRYPTO: Encrypt nc2vpn key FAILED"
                                                print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                                            # Change LCD operation mode
                                            lcdOperSel = 13
                                            # Set status of decrypt process
                                            eCryptProc = False
                                            
                                    # Operation failed
                                    else:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_CRYPTO: Encrypt nc2vpn key FAILED!")
                                            logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_CRYPTO: Encrypt nc2vpn key FAILED"
                                            print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                                        # Change LCD operation mode
                                        lcdOperSel = 13
                                        # Set status of decrypt process
                                        eCryptProc = False
                                    
                                # Operation failed
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_CRYPTO: Generate crypto public and private key FAILED!")
                                        logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                                    # Print statement
                                    else:
                                        print "DEBUG_CRYPTO: Generate crypto public and private key FAILED!"
                                        print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                                    # Change LCD operation mode
                                    lcdOperSel = 13
                                    # Set status of decrypt process
                                    eCryptProc = False
                                        
                            # Operation failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_CRYPTO: Generate crypto public and private key FAILED!")
                                    logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                                # Print statement
                                else:
                                    print "DEBUG_CRYPTO: Generate crypto public and private key FAILED!"
                                    print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                                # Change LCD operation mode
                                lcdOperSel = 13
                                # Set status of decrypt process
                                eCryptProc = False
                                
                        # Operation failed
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_CRYPTO: Generate crypto public and private key FAILED!")
                                logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                            # Print statement
                            else:
                                print "DEBUG_CRYPTO: Generate crypto public and private key FAILED!"
                                print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                            # Change LCD operation mode
                            lcdOperSel = 13
                            # Set status of decrypt process
                            eCryptProc = False
                                        
                    # Operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_CRYPTO: Delete encrypted nc2vpn key files FAILED!")
                            logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_CRYPTO: Delete encrypted nc2vpn key files FAILED!"
                            print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                        # Change LCD operation mode
                        lcdOperSel = 13
                        # Set status of decrypt process
                        eCryptProc = False
                        
                # Operation failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_CRYPTO: Delete public and private key FAILED!")
                        logger.info("DEBUG_CRYPTO: ENCRYPT process FAILED!")
                    # Print statement
                    else:
                        print "DEBUG_CRYPTO: Delete public and private key FAILED!"
                        print "DEBUG_CRYPTO: ENCRYPT process FAILED!"

                    # Change LCD operation mode
                    lcdOperSel = 13
                    # Set status of decrypt process
                    eCryptProc = False
    
# Doing string manipulations
def mid(s, offset, amount):
    return s[offset-1:offset+amount-1]

# Read current battery voltage
def readBattVoltage(bus):
    address = 0x36
    read = bus.read_word_data(address,2)
    swapped = struct.unpack("<H", struct.pack(">H", read))[0]
    voltage = swapped * 1.25 / 1000 / 16

    return voltage

# Read current battery capacity
def readBattCapacity(bus):
    address = 0x36
    read = bus.read_word_data(address,4)
    swapped = struct.unpack("<H", struct.pack(">H", read))[0]
    capacity = swapped / 256

    return capacity

# Check the routing table IP address
def chkRouteAddIpAddress (ipAddress, ipAddressCnt):
    existCnt = 0
    retResult = False
    # Execute the command
    process = subprocess.Popen(['route'], shell=True, stdout=subprocess.PIPE)
    # Loop the result
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            tempOut = output.strip()
            #print tempOut
            # Check through IP address buffer
            for a in range(ipAddressCnt):
                # IP address exist inside routing table
                if ipAddress[a] in tempOut:
                    #print 'masuk'
                    #print ipAddress[a]
                    existCnt += 1    

    if existCnt > 0:
        retResult = True
            
    return retResult
                
# KILL all openvpn instances
def terminateOpenVpn (command):
    openVpnPid = []
    openVpnCnt = 0

    # Execute the command
    process = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE)
    # Loop the result
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            tempOut = output.strip()

            foundDig = False
            pidNo = ''
            respLen = len(tempOut)
            
            # Go through the read line
            for a in range(0, (respLen + 1)):
                oneChar = mid(tempOut, a, 1)
                # Check PID digit
                if oneChar.isdigit():
                    foundDig = True
                    pidNo += oneChar
                elif foundDig == True and oneChar == ' ':
                    break

            # First array index
            if openVpnCnt == 0:
                openVpnPid = [pidNo]
                openVpnCnt += 1           

            # Subsequent array index
            else:
                openVpnPid.append(pidNo)
                openVpnCnt += 1

    return openVpnPid, openVpnCnt
                
# Get the openvpn routing info
def getOpenVpnRouteInfo (command):
    routeInfo = []
    routeInfoCnt = 0
    timeOut = 0
    openVpnStat = False
    
    # Execute the command
    process = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE)
    # Loop until get ip routing info
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            tempOut = output.strip()
            # Getting the ip routing info
            if 'ip route add' in tempOut:
                # Get the 'ip route add' segment
                ipRouteCmd = ''
                #spaceCnt = 0
                bSlashFound = False
                getIpRoute = False
                lenOut = len(tempOut)

                # Go through the read line
                for a in range(0, (lenOut + 1)):
                    oneChar = mid(tempOut, a, 1)
                    # Check for back slash character
                    if oneChar == '/' and getIpRoute == False:
                        ipRouteCmd += oneChar
                        getIpRoute = True
                    # Start get the ip route add rules 
                    elif getIpRoute == True:
                        ipRouteCmd += oneChar
                        
##                    # Count space char 
##                    if oneChar == ' ' and getIpRoute == False:
##                        spaceCnt += 1
##                        if spaceCnt == 5:
##                            getIpRoute = True
##
##                    # Start get the ip route add rules 
##                    elif getIpRoute == True:
##                        ipRouteCmd += oneChar 

                # First array index
                if routeInfoCnt == 0:
                    routeInfo = [ipRouteCmd]
                    routeInfoCnt += 1    

                # Subsequent array index
                else:
                    routeInfo.append(ipRouteCmd)
                    routeInfoCnt += 1

            # Exit loop
            elif 'Initialization Sequence Completed' in tempOut:
                openVpnStat = True
                break    
            
            #time.sleep(1)

            timeOut += 1
            # 1 minute time out in case failed to initiate openvpn
            if timeOut == 500:
                openVpnStat = False
                break

    # Previously initiate openvpn successfull
    if openVpnStat == True:
        # Kill back the openvpn instances
        openVpnPID = []    # Current openvpn PID instances
        openVpnPIDCnt = 0  # Current openvpn PID counter

        # Get openvpn PID
        openVpnPID, openVpnPIDCnt = terminateOpenVpn('ps aux | grep -v grep | grep openvpn')
        # Openvpn instances exist
        if openVpnPIDCnt > 0:
            # Execute kill instance command
            for a in range (openVpnPIDCnt):
                tempArgs = 'kill -9 ' + openVpnPID[a]
                
                out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()
                
                # NO error after command execution
                if stderr == None:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_UTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a]))
                    # Print statement
                    else:
                        print "DEBUG_UTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a])

        # There is NO openvpn instances
        else:
            # Write to logger
            if backLogger == True:
                logger.info("DEBUG_UTOUCH: NO OpenVPN instance EXIST!")
            # Print statement
            else:
                print "DEBUG_UTOUCH: NO OpenVPN instance EXIST!" 
    
    return routeInfo, routeInfoCnt

# Check and monitor USB thumb drive plug in status
def checkUSBUtouchStatus (threadname, delay):
    global eCryptProc
    global dCryptProc
    global initPihole
    global wifiShutDown
    
    # Forever loop
    while True:
        # Loop every 0.5s
        time.sleep(delay)

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='usb')

        monitor.start()
        for device in iter(monitor.poll, None):
            if device.action != 'add':
                if eCryptProc == True or dCryptProc == True:
                    # STOP VPN tunnel
                    openVpnPID = []    # Current openvpn PID instances
                    openVpnPIDCnt = 0  # Current openvpn PID counter

                    # Get openvpn PID
                    openVpnPID, openVpnPIDCnt = terminateOpenVpn('ps aux | grep -v grep | grep openvpn')
                    # Openvpn instances exist
                    if openVpnPIDCnt > 0:
                        # Execute kill instance command
                        for a in range (openVpnPIDCnt):
                            tempArgs = 'kill -9 ' + openVpnPID[a]
                            
                            out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                            stdout,stderr = out.communicate()
                            
                            # NO error after command execution
                            if stderr == None:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_USBUTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a]))
                                # Print statement
                                else:
                                    print "DEBUG_USBUTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a])

                    # There is NO openvpn instances
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_USBUTOUCH: NO OpenVPN instance EXIST!")
                        # Print statement
                        else:
                            print "DEBUG_USBUTOUCH: NO OpenVPN instance EXIST!"

                    dCryptProc = False
                    eCryptProc = False
                    initPihole = False
                    wifiShutDown = False
                    
# Communication and process monitoring for Ubuntu Touch smartphone
def uTouchCommProc (threadname, delay):
    global dCryptProc
    global nc2VpnKeyTPath
    global nc2VpnKeyPath
    global initPihole
    global wifiShutDown
    global eCryptProc
    global backLogger
    global currUSBPath
    
    networkManFailed = False
    initOthers = False
    nc2VpnTunn = False
        
    fileDel = False
    fileExist = False
    fileName = ''
        
    checkProcCnt = 0
    pingAtmptCnt = 0
    vpnTunAtmptCnt = 0
    piHoleCnt = 0
    
    ipRouteArr = []  # Ip route add command that not successfully initiate by openvpn
    ipRouteCnt = 0   # Ip route add index counter
    execSuccCnt = 0  # Ip route add process success counter
        
    # Forever loop
    while True:
        # Loop every 0.5s
        time.sleep(delay)

        # Previously there was encryption process take place
        # Start decryption process for secure gateway initialization
        if eCryptProc == True:
            # Clear encryption process
            eCryptProc = False
            # Set status of decrypt process
            dCryptProc = True
                        
##            # Write to logger
##            if backLogger == True:
##                logger.info("DEBUG_UTOUCH: Start DECRYPT process")
##            # Print statement
##            else:
##                print "DEBUG_UTOUCH: Start DECRYPT process"
##
##            # Delete the contents of nc2vpn key inside temporary folder
##            tempArgs = 'cd ' + nc2VpnKeyTPath + ';rm -rf *'
##            out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
##            stdout,stderr = out.communicate()
##
##            # NO error after command execution
##            if stderr == None:
##                # Write to logger
##                if backLogger == True:
##                    logger.info("DEBUG_UTOUCH: Delete temporary nc2vpn key files successful")
##                # Print statement
##                else:
##                    print "DEBUG_UTOUCH: Delete temporary nc2vpn key files successful"
##
##                # Wait before execute another command
##                time.sleep(1)
##            
##                # Start decrypt the nc2vpn key and stored it inside temporary folder
##                # Command:
##                # python3 decrypt.py --source=/path/to/your/drive/ --destination=/path/to/your/drive/ --private-key=/path/to/your/key.private
##                tempPrivKeyPath = currUSBPath + '/key.private'
##                out = subprocess.Popen(['python3', 'decrypt.py', '--source', nc2VpnKeyPath, '--destination', nc2VpnKeyTPath, '--private-key', tempPrivKeyPath], \
##                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
##                stdout,stderr = out.communicate()
##
##                # NO error after command execution
##                if stderr == None:
##                    if 'Decrypting:' in stdout:
##                        # Write to logger
##                        if backLogger == True:
##                            logger.info("DEBUG_UTOUCH: Decrypt nc2vpn key successful")
##                        # Print statement
##                        else:
##                            print "DEBUG_UTOUCH: Decrypt nc2vpn key successful"
##
##                        # Clear encryption process
##                        eCryptProc = False
##                        # Set status of decrypt process
##                        dCryptProc = True
##                    # Operation failed
##                    else:
##                        # Write to logger
##                        if backLogger == True:
##                            logger.info("DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!")
##                            logger.info("DEBUG_UTOUCH: DECRYPT process FAILED!")
##                        # Print statement
##                        else:
##                            print "DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!"
##                            print "DEBUG_UTOUCH: DECRYPT process FAILED!"
##
##                        # Set status of decrypt process
##                        dCryptProc = False
##                        
##                # Operation failed
##                else:
##                    # Write to logger
##                    if backLogger == True:
##                        logger.info("DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!")
##                        logger.info("DEBUG_UTOUCH: DECRYPT process FAILED!")
##                    # Print statement
##                    else:
##                        print "DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!"
##                        print "DEBUG_UTOUCH: DECRYPT process FAILED!"
##
##                    # Set status of decrypt process
##                    dCryptProc = False
##                        
##            # Operation failed
##            else:
##                # Write to logger
##                if backLogger == True:
##                    logger.info("DEBUG_UTOUCH: Delete temporary nc2vpn key files FAILED!")
##                    logger.info("DEBUG_UTOUCH: DECRYPT process FAILED!")
##                # Print statement
##                else:
##                    print "DEBUG_UTOUCH: Delete temporary nc2vpn key files FAILED!"
##                    print "DEBUG_UTOUCH: DECRYPT process FAILED!"
##
##                # Set status of decrypt process
##                dCryptProc = False
                
        # Only check other networks process when USB thumb drive are plug in
        elif dCryptProc == True:
            # Start back WIFI
            if wifiShutDown == True:
                # Enable WIFI radio hardware    
                out = subprocess.Popen(["nmcli radio wifi on"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()

                # NO error after command execution
                if stderr == None:
                    wifiShutDown = False
                    
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_UTOUCH: Bring UP WIFI SUCCESSFULL")
                    # Print statement
                    else:
                        print "DEBUG_UTOUCH: Bring UP WIFI SUCCESSFULL"

                    # Wait before execute another command
                    time.sleep(1)
                            
                    # Restart network-manager service
                    out = subprocess.Popen(["service network-manager restart"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # Restart network-manager successful
                        if 'start/running' in stdout:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: RESTART network-manager SUCCESSFULL")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: RESTART network-manager SUCCESSFULL"
                
                            networkManFailed = False  # Clear network-manager check flag, all is running well, no need to check it
                            initOthers = True         # Set flag for process initialization and status check
                                
                        # Restart network-manager failed!
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: RESTART network-manager FAILED!, will restart back in the next cycle")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: RESTART network-manager FAILED!, will restart back in the next cycle"

                            networkManFailed = True  # Set network-manager check flag, network problem, retry to start back on the next process cycle
                            initOthers = False       # Clear flag for process initialization and status check, network problem, drop the checking
                    
                    # Command operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_UTOUCH: RESTART network-manager FAILED!, will restart back in the next cycle")
                        # Print statement
                        else:
                            print "DEBUG_UTOUCH: RESTART network-manager FAILED!, will restart back in the next cycle"

                        networkManFailed = True  # Set network-manager check flag, network problem, retry to start back on the next cycle
                        initOthers = False       # Clear flag for process initialization and status check, network problem, drop the checking

                # Command operation failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_UTOUCH: Bring UP WIFI FAILED!, will restart back in the next cycle")
                    # Print statement
                    else:
                        print "DEBUG_UTOUCH: Bring UP WIFI FAILED!, will restart back in the next cycle"

            # Previously network-manager failed to start
            elif networkManFailed == True:
                # Restart pihole DNS server
                out = subprocess.Popen(["pihole restartdns"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()

                # NO error after command execution
                if stderr == None:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_UTOUCH: Initialize pihole DNS SUCCESSFULL")
                    # Print statement
                    else:
                        print "DEBUG_UTOUCH: Initialize pihole DNS SUCCESSFULL"

                    # Wait before execute another command
                    time.sleep(1)
                    
                    # Restart network-manager service
                    out = subprocess.Popen(["service network-manager restart"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # Restart network-manager successful
                        if 'start/running' in stdout:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: RESTART network-manager SUCCESSFULL")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: RESTART network-manager SUCCESSFULL"

                            if ipRouteCnt > 0:
                                # Execute ip route add command
                                for a in range (ipRouteCnt):
                                    out = subprocess.Popen([ipRouteArr[a]], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                    stdout,stderr = out.communicate()
                                    
                                    # NO error after command execution
                                    if stderr == None:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_UTOUCH: IP route add [%s] SUCCESSFULL" % (ipRouteArr[a]))
                                        # Print statement
                                        else:
                                            print "DEBUG_UTOUCH: IP route add [%s] SUCCESSFULL" % (ipRouteArr[a])

                            networkManFailed = False  # Clear network-manager check flag, all is running well, no need to check it
                            initOthers = True         # Set flag for process initialization and status check
                            checkProcCnt = 0
                                                    
                        # Restart network-manager failed!
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: RESTART network-manager FAILED!, will restart back in the next cycle")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: RESTART network-manager FAILED!, will restart back in the next cycle"
                            
                    # Command operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_UTOUCH: RESTART network-manager FAILED! [stderr], will restart back in the next cycle")
                        # Print statement
                        else:
                            print "DEBUG_UTOUCH: RESTART network-manager FAILED! [stderr], will restart back in the next cycle"

                # Command operation failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_UTOUCH: Initialize pihole DNS FAILED! [stderr], will reinitialize back in the next cycle")
                    # Print statement
                    else:
                        print "DEBUG_UTOUCH: Initialize pihole DNS FAILED! [stderr], will reinitialize back in the next cycle"    

            # Initialization and checking for others parameter
            if initOthers == True:
                # Test the 4G network by executing ping process
                if checkProcCnt == 0:
                    # Ping every 60 seconds
                    #if pingChkCnt == 60:
                    #    pingChkCnt = 0

                    out = subprocess.Popen(["ping -c 1 google.com"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) 
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # 4G network OK
                        if '1 received' in stdout:
                            checkProcCnt = 1 # Pihole restart DNS and pihole status check, on next process cycle
                            pingAtmptCnt = 0
                            
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: 4G network OK")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: 4G network OK"

                        # 4G network FAILED!
                        elif '0 received' or 'failure' in stdout:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: 4G network FAILED!")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: 4G network FAILED!"

                            # Increment for ping check attempt
                            pingAtmptCnt += 1
                            # 10 attempt still network failed, prepare to restart network-manager
                            if pingAtmptCnt == 10:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_UTOUCH: 4G network FAILED!, prepare to restart network-manager")
                                # Print statement
                                else:
                                    print "DEBUG_UTOUCH: 4G network FAILED!, prepare to restart network-manager"
                                
                                initOthers = False        # Disable aother process initialization and checking
                                networkManFailed = True   # Restart network-manager
                                checkProcCnt = 0          # Reset check process counter
                                pingAtmptCnt = 0

                    # Command operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_UTOUCH: 4G network FAILED!, prepare to restart network-manager")
                        # Print statement
                        else:
                            print "DEBUG_UTOUCH: 4G network FAILED!, prepare to restart network-manager"

                        # Increment for ping check attempt
                        pingAtmptCnt += 1
                        # 60 attempt still network failed, prepare to restart network-manager
                        if pingAtmptCnt == 60:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: 4G network FAILED!, prepare to restart network-manager")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: 4G network FAILED!, prepare to restart network-manager"
                            
                            initOthers = False        # Disable aother process initialization and checking
                            networkManFailed = True   # Restart network-manager
                            checkProcCnt = 0          # Reset check process counter
                            pingAtmptCnt = 0

                # Start nc2vpn tunnel if not start yet and continuously monitored the tunnel
                elif checkProcCnt == 1:
                    # First initialization of the nc2vpn tunnel
                    if nc2VpnTunn == False:
                        fileDel = False

                        # Check and retrieve nc2vpn .ovpn file name
                        tempData = os.listdir(nc2VpnKeyTPath)
                                                
                        # Go through the resulted data
                        for files in tempData:
                            if '.ovpn' in files:
                                fileName = files
                                fileExist = True  # Set a flag to indicate vpn file already previously decrypted   
                                break

                        # NO file or previously has been deleted, decrypt back nc2vpn key
                        if fileExist == False:
                            # Start decrypt the nc2vpn key and stored it inside temporary folder
                            # Command:
                            # python3 decrypt.py --source=/path/to/your/drive/ --destination=/path/to/your/drive/ --private-key=/path/to/your/key.private
                            tempPrivKeyPath = currUSBPath + '/key.private'
                            out = subprocess.Popen(['python3', 'decrypt.py', '--source', nc2VpnKeyPath, '--destination', nc2VpnKeyTPath, '--private-key', tempPrivKeyPath], \
                                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                            stdout,stderr = out.communicate()

                            # NO error after command execution
                            if stderr == None:
                                if 'Decrypting:' in stdout:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_UTOUCH: Decrypt nc2vpn key successful")
                                    # Print statement
                                    else:
                                        print "DEBUG_UTOUCH: Decrypt nc2vpn key successful"

                                # Operation failed, will retry to decrypt on the next process cycle
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!")
                                    # Print statement
                                    else:
                                        print "DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!"

                            # Operation failed, will retry to decrypt on the next process cycle
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!")
                                # Print statement
                                else:
                                    print "DEBUG_UTOUCH: Decrypt nc2vpn key FAILED!"

                        # Temporary nc2vpn key exist
                        else:
                            # Clear the IP route add buffer
                            if ipRouteCnt > 0:
                                for a in range (ipRouteCnt):
                                    ipRouteArr[a] = ''
                                ipRouteCnt = 0
                                
                            # Get the ip route add info    
                            tempArgs = 'cd ' + nc2VpnKeyTPath + ';openvpn --config ' + fileName
                            ipRouteArr, ipRouteCnt = getOpenVpnRouteInfo(tempArgs)
                            # Previously successfully get the ip route add info
                            if ipRouteCnt > 0:
                                # Wait before execute another command
                                time.sleep(1)
                        
                                # START VPN tunnel
                                tempArgs = 'cd ' + nc2VpnKeyTPath + ';openvpn --config ' + fileName + ' --daemon'
                                out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_UTOUCH: Init. OpenVPN sequence completed")
                                    # Print statement
                                    else:
                                        print "DEBUG_UTOUCH: Init. OpenVPN sequence completed"
                                
                                    nc2VpnTunn = True  # Set a flag to check periodically vpn tunnel 
                                    checkProcCnt = 0   # Reset check process counter, start with ping process, on next process cycle
                                    
                                # Command operation failed
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_UTOUCH: Init. OpenVPN sequence FAILED! [stderr]")
                                    # Print statement
                                    else:
                                        print "DEBUG_UTOUCH: Init. OpenVPN sequence FAILED! [stderr]"

                            # Get the info failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_UTOUCH: Init. OpenVPN sequence FAILED!")
                                # Print statement
                                else:
                                    print "DEBUG_UTOUCH: Init. OpenVPN sequence FAILED!"
                                
                    # OpenVPN checking by checking tun0 interface 
                    else:
                        # Check tun0 interface
                        out = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()
                        
                        # NO error after command execution
                        if stderr == None:
                            # VPN tunnel exist
                            if 'tun0' in stdout:
                                # Delete previous decrypted vpn file, to ensure secured vpn transaction
                                if fileDel == False:
                                    # Delete the contents of nc2vpn key inside temporary folder
                                    tempArgs = 'cd ' + nc2VpnKeyTPath + ';rm -rf *'
                                    out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                    stdout,stderr = out.communicate()
                                    
                                    # NO error after command execution
                                    if stderr == None:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_UTOUCH: Delete temporary nc2vpn key files successful")
                                        # Print statement
                                        else:
                                            print "DEBUG_UTOUCH: Delete temporary nc2vpn key files successful"    

                                    fileDel = True

                                # Initiate ip route add process
                                # Get the routing table IP address
                                ipAddress = []
                                ipAddressCnt = 0
                                chkExist = False
                                for a in range (ipRouteCnt):
                                    foundChar = False
                                    ipAddr = ''
                                    respLen = len(ipRouteArr[a])
                                    
                                    # Go through the ip route array contents
                                    for b in range(0, (respLen + 1)):
                                        oneChar = mid(ipRouteArr[a], b, 1)
                                        # Check the IP address
                                        if oneChar.isdigit() or oneChar == '.':
                                            foundChar = True
                                            ipAddr += oneChar
                                        elif foundChar == True and oneChar == '/':
                                            break

                                    # First array index
                                    if ipAddressCnt == 0:
                                        ipAddress = [ipAddr]
                                        ipAddressCnt += 1
                                        
                                    # Subsequent array index
                                    else:
                                        ipAddress.append(ipAddr)
                                        ipAddressCnt += 1

                                # Start check the routing table
                                chkExist = chkRouteAddIpAddress(ipAddress, ipAddressCnt)
                                # Routing for openvpn IP address still not exist
                                if chkExist == False:
                                    # Execute ip route add command
                                    for a in range (ipRouteCnt):
                                        out = subprocess.Popen([ipRouteArr[a]], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                        stdout,stderr = out.communicate()
                                        
                                        # NO error after command execution
                                        if stderr == None:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_UTOUCH: IP route add [%s] SUCCESSFULL" % (ipRouteArr[a]))
                                            # Print statement
                                            else:
                                                print "DEBUG_UTOUCH: IP route add [%s] SUCCESSFULL" % (ipRouteArr[a])

                                            execSuccCnt += 1
                                        
                                    # Previous IP route add process successfull
                                    if execSuccCnt == ipRouteCnt:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_UTOUCH: IP route add process SUCCESSFULL")
                                            logger.info("DEBUG_UTOUCH: Init. OpenVPN sequence completed")
                                        # Print statement
                                        else:
                                            print "DEBUG_UTOUCH: IP route add process SUCCESSFULL"
                                            print "DEBUG_UTOUCH: Init. OpenVPN sequence completed"

                                        execSuccCnt = 0    
                                        nc2VpnTunn = True  # Set a flag to check periodically vpn tunnel 
                                        checkProcCnt = 0   # Reset check process counter, start with ping process, on next process cycle

                                    # Previous IP route add process failed!
                                    else:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_UTOUCH: IP route add process FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_UTOUCH: IP route add process FAILED!"
                                            
                                        openVpnPID = []    # Current openvpn PID instances
                                        openVpnPIDCnt = 0  # Current openvpn PID counter
                                        
                                        # Get openvpn PID
                                        openVpnPID, openVpnPIDCnt = terminateOpenVpn('ps aux | grep -v grep | grep openvpn')
                                        # Openvpn instances exist
                                        if openVpnPIDCnt > 0:
                                            # Execute kill instance command
                                            for a in range (openVpnPIDCnt):
                                                tempArgs = 'kill -9 ' + openVpnPID[a]
                                                
                                                out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                                stdout,stderr = out.communicate()
                                                
                                                # NO error after command execution
                                                if stderr == None:
                                                    # Write to logger
                                                    if backLogger == True:
                                                        logger.info("DEBUG_UTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a]))
                                                    # Print statement
                                                    else:
                                                        print "DEBUG_UTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a])
                                                    
                                        # There is NO openvpn instances
                                        else:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_UTOUCH: NO OpenVPN instance EXIST!")
                                            # Print statement
                                            else:
                                                print "DEBUG_UTOUCH: NO OpenVPN instance EXIST!"

                                # Routing for openvpn IP address already exist
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_UTOUCH: Routing table IP address EXIST")
                                    # Print statement
                                    else:
                                        print "DEBUG_UTOUCH: Routing table IP address EXIST"
                                                                                                    
                                checkProcCnt = 0   # Reset check process counter, start with ping process, on next process cycle

                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_UTOUCH: VPN tunnel OK")
                                # Print statement
                                else:
                                    print "DEBUG_UTOUCH: VPN tunnel OK"

                            # VPN tunnel not exist
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_UTOUCH: VPN tunnel tun0 NOT exist!")
                                # Print statement
                                else:
                                    print "DEBUG_UTOUCH: VPN tunnel tun0 NOT exist!"

                                # Increment VPN tunnel check attempt counter
                                vpnTunAtmptCnt += 1
                                # 60 attempt still tun0 interface not exist, prepare to kill openvpn
                                if vpnTunAtmptCnt == 60:
                                    # STOP VPN tunnel
                                    openVpnPID = []    # Current openvpn PID instances
                                    openVpnPIDCnt = 0  # Current openvpn PID counter

                                    # Get openvpn PID
                                    openVpnPID, openVpnPIDCnt = terminateOpenVpn('ps aux | grep -v grep | grep openvpn')
                                    # Openvpn instances exist
                                    if openVpnPIDCnt > 0:
                                        # Execute kill instance command
                                        for a in range (openVpnPIDCnt):
                                            tempArgs = 'kill -9 ' + openVpnPID[a]
                                            
                                            out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                            stdout,stderr = out.communicate()
                                            
                                            # NO error after command execution
                                            if stderr == None:
                                                # Write to logger
                                                if backLogger == True:
                                                    logger.info("DEBUG_UTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a]))
                                                # Print statement
                                                else:
                                                    print "DEBUG_UTOUCH: KILL OpenVPN instance [%s] SUCCESSFULL" % (openVpnPID[a])

                                    # There is NO openvpn instances
                                    else:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_UTOUCH: NO OpenVPN instance EXIST!")
                                        # Print statement
                                        else:
                                            print "DEBUG_UTOUCH: NO OpenVPN instance EXIST!"    

                                    vpnTunAtmptCnt = 0
                                    nc2VpnTunn = False   # Reset a flag to initiate back OpenVpn, checking network connectivity first 
                                    checkProcCnt = 0     # Reset check process counter, start with ping process, on next process cycle
                                    
        # USB key detached
        else:
##            # First initialization of the pihole
##            if initPihole == False:
##                # First check wifi status
##                out = subprocess.Popen(["nmcli radio wifi"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
##                stdout,stderr = out.communicate()
##                # NO error after command execution
##                if stderr == None:
##                    # Wifi still in enabled mode, shut it down
##                    if 'enabled' in stdout:
##                        DEFNULL = open(os.devnull, 'w')
##                        retcode = subprocess.call(['/usr/local/bin/pihole', 'restartdns'], stdout=DEFNULL, stderr=subprocess.STDOUT)
##
##                        # Write to logger
##                        if backLogger == True:
##                            logger.info("DEBUG_UTOUCH: Initialize pihole DNS SUCCESSFULL")
##                        # Print statement
##                        else:
##                            print "DEBUG_UTOUCH: Initialize pihole DNS SUCCESSFULL"
##                                
####                        # Restart pihole DNS server
####                        out = subprocess.Popen(["/usr/local/bin/pihole restartdns"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
####                        stdout,stderr = out.communicate()
####
####                        # NO error after command execution
####                        if stderr == None:
####                            # Write to logger
####                            if backLogger == True:
####                                logger.info("DEBUG_UTOUCH: Initialize pihole DNS SUCCESSFULL")
####                            # Print statement
####                            else:
####                                print "DEBUG_UTOUCH: Initialize pihole DNS SUCCESSFULL"
##
##                        initPihole = True
##            
##            # Previously pihole already been initialized
##            else:
            # Shutdown WIFI if USB key NOT attached
            if wifiShutDown == False:
                checkProcCnt = 0
                vpnTunAtmptCnt = 0
                pingAtmptCnt = 0

                initOthers = False
                networkManFailed = False
                nc2VpnTunn = False

                # First check wifi status
                out = subprocess.Popen(["nmcli radio wifi"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()
                # NO error after command execution
                if stderr == None:
                    # Wifi still in enabled mode, shut it down
                    if 'enabled' in stdout: 
                        # Wait before execute another command
                        time.sleep(1)
                                   
                        # Disable WIFI radio hardware    
                        out = subprocess.Popen(["nmcli radio wifi off"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_UTOUCH: Shutdown WIFI")
                            # Print statement
                            else:
                                print "DEBUG_UTOUCH: Shutdown WIFI"

                    # Wifi already been shutdown
                    elif 'disabled' in stdout:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_UTOUCH: Previously WIFI already been SHUTDOWN")
                        # Print statement
                        else:
                            print "DEBUG_UTOUCH: Previously WIFI already been SHUTDOWN"

                        wifiShutDown = True

            # Previously WIFI already been shutdown
            else:
                # Write to logger
                if backLogger == True:
                    logger.info("DEBUG_UTOUCH: NC2VPN Secure GW OFFLINE")
                # Print statement
                else:
                    print "DEBUG_UTOUCH: NC2VPN Secure GW OFFLINE"
    
# Connection and tunnel monitoring - network monitoring and validation
def networkMon (threadname, delay):
    global dCryptProc
    global clientIPAddr
    global netMonChkCnt
    global tunnelValid
    global net4gValid
    global net4gAtmptCnt
    global nc2VpnKeyTPath
    global nc2VpnKeyPath
    global vpnAtmptCnt
    global currUSBPath
    global lcdOperSel
    global radioMode
    global radioValid
    global radioOpt
    global publicIPaddr
    
    fileName = ''
    fileExist = False
    fileDel = False
    tempData = []
                
    # Forever loop
    while True:
        # Loop every 0.5s
        time.sleep(delay)

        # Radio mode
        if radioMode == True:
            # Initiate and check 4G LTE modem
            if netMonChkCnt == 0:
                # 4G network not start yet, or previously has already terminated
                if net4gValid == False:
                    # Start initiate 4G network
                    retResult = initiate4GModem()
                    # Successful
                    if retResult == True:
                        net4gValid = True
                        netMonChkCnt = 1

                        # Change LCD operation mode
                        lcdOperSel = 9
                    
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: Initiate 4G LTE modem successful")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: Initiate 4G LTE modem successful"

                    # Failed
                    else:
                        # STOP 4G LTE modem 
                        out = subprocess.Popen(['qmicli', '-d', '/dev/cdc-wdm0', '--device-open-sync', '--dms-get-operating-mode'], \
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            if 'HW restricted:' in stdout:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: STOP 4G LTE modem successful - Init. 4G LTE modem")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: STOP 4G LTE modem successful - Init. 4G LTE modem"
                                        
                                # Wait before execute another command
                                time.sleep(1)

                                # Bring wwan0 interface DOWN
                                out = subprocess.Popen(['ifconfig', 'wwan0', 'down'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: Bringing DOWN wwan0 successful - Init. 4G LTE modem")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: Bringing DOWN wwan0 successful - Init. 4G LTE modem"

                                # Operation failed
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - Init. 4G LTE modem")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - Init. 4G LTE modem"

                            # Operation failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: STOP 4G LTE modem FAILED! - Init. 4G LTE modem")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: STOP 4G LTE modem FAILED! - Init. 4G LTE modem"

                        # Operation failed
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - init. 4G LTE modem")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - init. 4G LTE modem"

                        # Retry again the sequence
                        netMonChkCnt = 0

                # 4G network checking by pinging process to google.com 
                else:
                    # Start PING google.com
                    out = subprocess.Popen(['ping', '-c', '1', 'google.com'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # 4G network OK
                        if '1 received' in stdout:
                            net4gValid = True

                            net4gAtmptCnt = 0
                            netMonChkCnt = 1

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: 4G network OK")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: 4G network OK"
                                
                        # 4G network FAILED!
                        elif '0 received' or 'failure' in stdout:
                            # Increment attempt to check 4G network by pinging process
                            net4gAtmptCnt += 1

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: PING google.com FAILED! - PING google.com attempt FAILED! [%s]" % (net4gAtmptCnt))
                            # Print statement
                            else:
                                print "DEBUG_NETMON: PING google.com FAILED! - PING google.com attempt FAILED! [%s]" % (net4gAtmptCnt)
                                
                            # After  checking 5 times, still 4G network failed, do:
                            # 1 - Stop 4G modem properly
                            # 2 - Bring wwan0 interface DOWN
                            if net4gAtmptCnt == 5:
                                net4gAtmptCnt = 0

                                # STOP 4G LTE modem
                                out = subprocess.Popen(['qmicli', '-d', '/dev/cdc-wdm0', '--device-open-sync', '--dms-get-operating-mode'], \
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    if 'HW restricted:' in stdout:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_NETMON: STOP 4G LTE modem successful - PING google.com attempt FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_NETMON: STOP 4G LTE modem successful - PING google.com attempt FAILED!"
                                        
                                        # Wait before execute another command
                                        time.sleep(1)

                                        # Bring wwan0 interface DOWN
                                        out = subprocess.Popen(['ifconfig', 'wwan0', 'down'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                        stdout,stderr = out.communicate()

                                        # NO error after command execution
                                        if stderr == None:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_NETMON: Bringing DOWN wwan0 successful - PING google.com attempt FAILED!")
                                            # Print statement
                                            else:
                                                print "DEBUG_NETMON: Bringing DOWN wwan0 successful - PING google.com attempt FAILED!"

                                            # Wait before execute another command
                                            time.sleep(1)

                                            # KILL udhcpc instances
                                            out = subprocess.Popen(['killall', 'udhcpc'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                            stdout,stderr = out.communicate()

                                            # NO error after command execution
                                            if stderr == None:
                                                # Write to logger
                                                if backLogger == True:
                                                    logger.info("DEBUG_NETMON: KILL  udhcpc SUCCESSFUL")
                                                    logger.info("DEBUG_NETMON: Initiate 4G LTE modem on the next cycle...")
                                                # Print statement
                                                else:
                                                    print "DEBUG_NETMON: KILL  udhcpc SUCCESSFUL"
                                                    print "DEBUG_NETMON: Initiate 4G LTE modem on the next cycle..."
                                            
                                                # Retry again the sequence, start with pinging client process  
                                                net4gValid = False
                                                netMonChkCnt = 0

                                        # Operation failed
                                        else:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - PING google.com attempt FAILED!")
                                            # Print statement
                                            else:
                                                print "DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - PING google.com attempt FAILED!"

                                    # Operation failed
                                    else:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_NETMON: STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_NETMON: STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!"

                                # Operation failed
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!"    

                    # Operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: Command execution to PING google.com FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: Command execution to PING google.com FAILED!"
                            
            # Initiate and check SDR radio monitoring server
            elif netMonChkCnt == 1:
                # Radio monitoring server not start yet, or previously has already terminated
                if radioValid == False:
                    # Checking SDR availability
                    out = subprocess.Popen(["lsusb"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # SDR USB bus ID
                        if '1df7:3000' in stdout:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: SDR module available")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: SDR module available"
                                    
                            # Wait before execute another command
                            time.sleep(1)

                            # Option for soapy sdr server
                            if radioOpt == 0:
                                tempArg = "SoapySDRServer --bind=" + "'" + publicIPaddr + ":1234' " + "> /dev/null 2>&1 &"
                                out = subprocess.Popen([tempArg], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                
                            # Option for RSPTCP server
                            elif radioOpt == 1:
                                tempArg = "rsp_tcp -E -a " + publicIPaddr + " > /dev/null 2>&1 &"
                                out = subprocess.Popen([tempArg], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                            # Option for custom gnuradio radio data server
                            elif radioOpt == 2:
                                out = subprocess.Popen(["/sources/common/sourcecode/radio-server; /usr/bin/python radio_server.py > /dev/null 2>&1 &"], \
                                                       shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                            stdout,stderr = out.communicate()

                            # NO error after command execution
                            if stderr == None:
                                radioValid = True
                                netMonChkCnt = 0

                                # Change LCD operation mode
                                lcdOperSel = 14
                                
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: Initiate radio monitoring server successful")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: Initiate radio monitoring server successful"
                                
                            # Operation failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: Command execution to initiate radio monitoring server FAILED!")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: Command execution to initiate radio monitoring server FAILED!"
                                    
                        # SDR NOT available
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: SDR module NOT available")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: SDR module NOT available"

                            # Change LCD operation mode
                            lcdOperSel = 15
                    
                # Radio monitoring server status check by checking the server process ID
                else:
                    # Option for soapy sdr server
                    if radioOpt == 0:
                        out = subprocess.Popen(["ps aux | grep -v grep | grep SoapySDRServer"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                    # Option for RSPTCP server
                    elif radioOpt == 1:
                        out = subprocess.Popen(["ps aux | grep -v grep | grep rsp_tcp"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                    # Option for custom gnuradio radio data server
                    elif radioOpt == 2:
                        out = subprocess.Popen(["ps aux | grep -v grep | grep radio_server"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()    

                    # NO error after command execution
                    if stderr == None:
                        foundDig = False
                        pidNo = ''
                        respLen = len(stdout)
                        for a in range(0, (respLen + 1)):
                            oneChar = mid(stdout, a, 1)
                            # Check PID digit
                            if oneChar.isdigit():
                                foundDig = True
                                pidNo += oneChar
                            elif foundDig == True and oneChar == ' ':
                                break

                        # PID found
                        if foundDig == True and pidNo != '':
                            radioValid = True
                            netMonChkCnt = 0

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: Radio monitoring server OK: PID: [%s]" % (pidNo))
                            # Print statement
                            else:
                                print "DEBUG_NETMON: Radio monitoring server OK: PID: [%s]" % (pidNo)

                        # PID not found
                        else:
                            radioValid = False
                            netMonChkCnt = 0

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: Radio monitoring server TERMINATED, will be restarted on the next cycle")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: Radio monitoring server TERMINATED, will be restarted on the next cycle"

                    # Operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: Command execution to check radio monitoring server status FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: Command execution to radio monitoring server status FAILED!"        
                            
        # Security gateway mode
        else:
            # Check the client computer network, by pinging process
            if netMonChkCnt == 0:
                # Start PING client computer
                out = subprocess.Popen(['ping', '-c', '1', clientIPAddr], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()

                # NO error after command execution
                if stderr == None:
                    # Client computer already connected to wifi
                    if '1 received' in stdout:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: PING client computer successful")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: PING client computer successful"

                    # Client computer disconnected from wifi
                    # To check whether client computer still connected to wifi network
                    elif '0 received' in stdout:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: PING client computer FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: PING client computer FAILED!"

                    # Only check other networks process when USB thumbdrive are plug in
                    if dCryptProc == True:
                        netMonChkCnt = 1
                    else:
                        netMonChkCnt = 0
                        
                # Operation failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_NETMON: Command execution to PING client computer FAILED!")
                    # Print statement
                    else:
                        print "DEBUG_NETMON: Command execution to PING client computer FAILED!"
                            
            # Start 4G network if its not start yet and continuously monitored the network
            elif netMonChkCnt == 1 and dCryptProc == True:
                # 4G network not start yet, or previously has already terminated
                if net4gValid == False:
                    # Start initiate 4G network
                    retResult = initiate4GModem()
                    # Successful
                    if retResult == True:
                        net4gValid = True
                        netMonChkCnt = 2

                        # Change LCD operation mode
                        lcdOperSel = 9
                    
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: Initiate 4G LTE modem successful")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: Initiate 4G LTE modem successful"
                        
                    # Failed
                    else:
                        # STOP 4G LTE modem 
                        out = subprocess.Popen(['qmicli', '-d', '/dev/cdc-wdm0', '--device-open-sync', '--dms-get-operating-mode'], \
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            if 'HW restricted:' in stdout:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: STOP 4G LTE modem successful - Init. 4G LTE modem")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: STOP 4G LTE modem successful - Init. 4G LTE modem"
                                        
                                # Wait before execute another command
                                time.sleep(1)

                                # Bring wwan0 interface DOWN
                                out = subprocess.Popen(['ifconfig', 'wwan0', 'down'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: Bringing DOWN wwan0 successful - Init. 4G LTE modem")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: Bringing DOWN wwan0 successful - Init. 4G LTE modem"

                                # Operation failed
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - Init. 4G LTE modem")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - Init. 4G LTE modem"

                            # Operation failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: STOP 4G LTE modem FAILED! - Init. 4G LTE modem")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: STOP 4G LTE modem FAILED! - Init. 4G LTE modem"

                        # Operation failed
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - init. 4G LTE modem")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - init. 4G LTE modem"

                        # Retry again the sequence, start with pinging client process 
                        netMonChkCnt = 0

                # 4G network checking by pinging process to google.com 
                else:
                    # Start PING google.com
                    out = subprocess.Popen(['ping', '-c', '1', 'google.com'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # 4G network OK
                        if '1 received' in stdout:
                            net4gValid = True

                            net4gAtmptCnt = 0
                            netMonChkCnt = 2

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: 4G network OK")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: 4G network OK"
                                
                        # 4G network FAILED!
                        elif '0 received' or 'failure' in stdout:
                            # Increment attempt to check 4G network by pinging process
                            net4gAtmptCnt += 1

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: PING google.com FAILED! - PING google.com attempt FAILED! [%s]" % (net4gAtmptCnt))
                            # Print statement
                            else:
                                print "DEBUG_NETMON: PING google.com FAILED! - PING google.com attempt FAILED! [%s]" % (net4gAtmptCnt)
                                
                            # After  checking 5 times, still 4G network failed, do:
                            # 1 - Stop 4G modem properly
                            # 2 - Bring wwan0 interface DOWN
                            if net4gAtmptCnt == 5:
                                net4gAtmptCnt = 0

                                # STOP 4G LTE modem
                                out = subprocess.Popen(['qmicli', '-d', '/dev/cdc-wdm0', '--device-open-sync', '--dms-get-operating-mode'], \
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    if 'HW restricted:' in stdout:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_NETMON: STOP 4G LTE modem successful - PING google.com attempt FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_NETMON: STOP 4G LTE modem successful - PING google.com attempt FAILED!"
                                        
                                        # Wait before execute another command
                                        time.sleep(1)

                                        # Bring wwan0 interface DOWN
                                        out = subprocess.Popen(['ifconfig', 'wwan0', 'down'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                        stdout,stderr = out.communicate()

                                        # NO error after command execution
                                        if stderr == None:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_NETMON: Bringing DOWN wwan0 successful - PING google.com attempt FAILED!")
                                            # Print statement
                                            else:
                                                print "DEBUG_NETMON: Bringing DOWN wwan0 successful - PING google.com attempt FAILED!"

                                            # Wait before execute another command
                                            time.sleep(1)

                                            # KILL udhcpc instances
                                            out = subprocess.Popen(['killall', 'udhcpc'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                            stdout,stderr = out.communicate()

                                            # NO error after command execution
                                            if stderr == None:
                                                # Write to logger
                                                if backLogger == True:
                                                    logger.info("DEBUG_NETMON: KILL  udhcpc SUCCESSFUL")
                                                    logger.info("DEBUG_NETMON: Initiate 4G LTE modem on the next cycle...")
                                                # Print statement
                                                else:
                                                    print "DEBUG_NETMON: KILL  udhcpc SUCCESSFUL"
                                                    print "DEBUG_NETMON: Initiate 4G LTE modem on the next cycle..."
                                                    
                                                # Retry again the sequence, start with pinging client process  
                                                net4gValid = False
                                                netMonChkCnt = 0

                                        # Operation failed
                                        else:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - PING google.com attempt FAILED!")
                                            # Print statement
                                            else:
                                                print "DEBUG_NETMON: Bringing DOWN wwan0 FAILED! - PING google.com attempt FAILED!"

                                    # Operation failed
                                    else:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_NETMON: STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_NETMON: STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!"

                                # Operation failed
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: Command execution to STOP 4G LTE modem FAILED! - PING google.com attempt FAILED!"    

                    # Operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: Command execution to PING google.com FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: Command execution to PING google.com FAILED!"
                        
            # Start nc2vpn tunnel if not start yet and continuously monitored the tunnel
            elif netMonChkCnt == 2 and dCryptProc == True:
                # VPN tunnel not start yet
                if tunnelValid == False:
                    fileDel = False
                    
                    # Check and retrieve nc2vpn .ovpn file name
                    tempData = os.listdir(nc2VpnKeyTPath)
                    
                    # Go through the resulted data
                    for files in tempData:
                        if '.ovpn' in files:
                            fileName = files
                            fileExist = True
                            break

                    # NO file or previously has been deleted, decrypt back nc2vpn key
                    if fileExist == False:
                        # Start decrypt the nc2vpn key and stored it inside temporary folder
                        # Command:
                        # python3 decrypt.py --source=/path/to/your/drive/ --destination=/path/to/your/drive/ --private-key=/path/to/your/key.private
                        tempPrivKeyPath = currUSBPath + '/key.private'
                        out = subprocess.Popen(['python3', 'decrypt.py', '--source', nc2VpnKeyPath, '--destination', nc2VpnKeyTPath, '--private-key', tempPrivKeyPath], \
                                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            if 'Decrypting:' in stdout:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: Decrypt nc2vpn key successful")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: Decrypt nc2vpn key successful"

                            # Operation failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_NETMON: Decrypt nc2vpn key FAILED!")
                                # Print statement
                                else:
                                    print "DEBUG_NETMON: Decrypt nc2vpn key FAILED!"

                        # Operation failed
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: Decrypt nc2vpn key FAILED!")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: Decrypt nc2vpn key FAILED!"
                                    
                    # Temporary nc2vpn key exist
                    else:
                        # START VPN tunnel
                        tempArgs = 'cd ' + nc2VpnKeyTPath + ';openvpn --config ' + fileName + ' --daemon'
                        out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: Init. OpenVPN sequence completed - Init. OpenVPN")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: Init. OpenVPN sequence completed - Init. OpenVPN"
                            
                            tunnelValid = True
                            netMonChkCnt = 0

                            # Change LCD operation mode
                            lcdOperSel = 11
                                             
                        # Operation failed
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: Command execution to initiate OpenVPN FAILED! - Init. OpenVPN")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: Command execution to initiate OpenVPN FAILED! - Init. OpenVPN"

                # OpenVPN checking by checking tun0 interface 
                else:
                    # Check tun0 interface
                    out = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # VPN tunnel still exist
                        if 'tun0' in stdout:
                            if fileDel == False:
                                # Delete the contents of nc2vpn key inside temporary folder
                                tempArgs = 'cd ' + nc2VpnKeyTPath + ';rm -rf *'
                                out = subprocess.Popen([tempArgs], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()
                                
                                # NO error after command execution
                                if stderr == None:
                                    tunnelValid = True
                                    netMonChkCnt = 0

                                    # Change LCD operation mode
                                    lcdOperSel = 11
                                    
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: Delete temporary nc2vpn key files successful")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: Delete temporary nc2vpn key files successful"    

                                fileDel = True
                                
                            tunnelValid = True
                            vpnAtmptCnt = 0
                            netMonChkCnt = 0

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: VPN tunnel OK")
                            # Print statement
                            else:
                                print "DEBUG_NETMON: VPN tunnel OK"
                                
                        # VPN tunnel not exist
                        else:
                            # Increment attempt to check VPN tunnel by checking tun0 interface existense
                            vpnAtmptCnt += 1

                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_NETMON: VPN tunnel tun0 NOT exist! - tun0 identification attempt FAILED! [%s]" % (vpnAtmptCnt))
                            # Print statement
                            else:
                                print "DEBUG_NETMON: VPN tunnel tun0 NOT exist! - tun0 identification attempt FAILED! [%s]" % (vpnAtmptCnt)

                            # After  checking 5 times, still tun0 not exist, do:
                            # KILL VPN tunnel
                            if vpnAtmptCnt == 5:
                                vpnAtmptCnt = 0

                                # STOP VPN tunnel
                                out = subprocess.Popen(['killall', 'openvpn'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    if 'no process found' in stdout:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_NETMON: Openvpn process NOT found - tun0 identification attempt FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_NETMON: Openvpn process NOT found - tun0 identification attempt FAILED!"
                                    else:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_NETMON: KILL openvpn successful - tun0 identification attempt FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_NETMON: KILL openvpn successful - tun0 identification attempt FAILED!"

                                    # Retry again the sequence, start with pinging client process  
                                    tunnelValid = False
                                    netMonChkCnt = 0

                                # Operation failed
                                else:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_NETMON: KILL openvpn FAILED! - tun0 identification attempt FAILED!")
                                    # Print statement
                                    else:
                                        print "DEBUG_NETMON: KILL openvpn FAILED! - tun0 identification attempt FAILED!"

                    # Operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_NETMON: Command execution to check tun0 interface FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_NETMON: Command execution to check tun0 interface FAILED!"
                            
# Display information on the i2c LCD
def lcdOperation (threadname, delay):
    global lcdOperSel
    global lcdDlyStatCnt
    global lcdBattVolt        
    global lcdBattCap
    global lcdBlTimeOut
    global scrollUP
    global scrollDWN
    global tunnelValid
    global net4gValid
    global radioMode
    global radioValid
    global i2cLcd
    
    # Forever loop
    while True:
        # Loop every 0.5s
        time.sleep(delay)

        # Try execution
        try:
            # Default LCD display information
            if lcdOperSel == 0:
                # Turn ON LCD back light for 10s
                if GPIO.input(17) == False or GPIO.input(24) == False:
                    # Turn ON LCD back light
                    GPIO.output(27, GPIO.HIGH)
                    lcdBlTimeOut = 0
                elif lcdBlTimeOut == 20:
                    # Turn OFF LCD back light
                    GPIO.output(27, GPIO.LOW)
                    lcdBlTimeOut = 0
                else:
                    # Increment LCD back light counter
                    lcdBlTimeOut += 1

                lcdDlyStatCnt += 1
                # Display security gw current status
                if lcdDlyStatCnt < 10:
                    if lcdDlyStatCnt == 0:
                        mylcd.lcd_clear()

                    # Security gateway mode
                    if radioMode == False:
                        if tunnelValid == False and net4gValid == False:
                            # Previously i2c LCD initialization are successful
                            if i2cLcd == True:
                                mylcd.lcd_display_string('NC2VPN Secure GW', 1)
                                mylcd.lcd_display_string('    OFFLINE     ', 2)

                            # Previously i2c LCD initialization are failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_LCD: NC2VPN Secure GW")
                                    logger.info("DEBUG_LCD: OFFLINE")
                                # Print statement
                                else:
                                    print "DEBUG_LCD: NC2VPN Secure GW"
                                    print "DEBUG_LCD: OFFLINE"
                                
                        elif tunnelValid == True and net4gValid == True:
                            # Previously i2c LCD initialization are successful
                            if i2cLcd == True:
                                mylcd.lcd_display_string('NC2VPN Secure GW', 1)
                                mylcd.lcd_display_string('     ONLINE     ', 2)

                            # Previously i2c LCD initialization are failed    
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_LCD: NC2VPN Secure GW")
                                    logger.info("DEBUG_LCD: ONLINE")
                                # Print statement
                                else:
                                    print "DEBUG_LCD: NC2VPN Secure GW"
                                    print "DEBUG_LCD: ONLINE"
                    # Radio mode
                    else:
                        if radioValid == False and net4gValid == False:
                            # Previously i2c LCD initialization are successful
                            if i2cLcd == True:
                                mylcd.lcd_display_string(' Radio Mon. Svr ', 1)
                                mylcd.lcd_display_string('    OFFLINE     ', 2)

                            # Previously i2c LCD initialization are failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_LCD: Radio Mon. Svr")
                                    logger.info("DEBUG_LCD: OFFLINE")
                                # Print statement
                                else:
                                    print "DEBUG_LCD: NC2VPN Secure GW"
                                    print "DEBUG_LCD: OFFLINE"
                                    
                        elif radioValid == True and net4gValid == True:
                            # Previously i2c LCD initialization are successful
                            if i2cLcd == True:
                                mylcd.lcd_display_string(' Radio Mon. Svr ', 1)
                                mylcd.lcd_display_string('     ONLINE     ', 2)

                            # Previously i2c LCD initialization are failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_LCD: Radio Mon. Svr")
                                    logger.info("DEBUG_LCD: ONLINE")
                                # Print statement
                                else:
                                    print "DEBUG_LCD: NC2VPN Secure GW"
                                    print "DEBUG_LCD: ONLINE"
                    
                # Display date and time for 5s
                elif lcdDlyStatCnt >= 10 and lcdDlyStatCnt < 20:
                    if lcdDlyStatCnt == 10:
                        mylcd.lcd_clear()

                    # Previously i2c LCD initialization are successful
                    if i2cLcd == True:
                        mylcd.lcd_display_string("Time: %s" %time.strftime("%H:%M:%S"), 1)
                        mylcd.lcd_display_string("Date: %s" %time.strftime("%m/%d/%Y"), 2)

                    # Previously i2c LCD initialization are failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_LCD: Time: %s" %time.strftime("%H:%M:%S"))
                            logger.info("DEBUG_LCD: Date: %s" %time.strftime("%m/%d/%Y"))
                        # Print statement
                        else:
                            print "DEBUG_LCD: Time: %s" %time.strftime("%H:%M:%S")
                            print "DEBUG_LCD: Date: %s" %time.strftime("%m/%d/%Y")
                                    
                # Display battery status for 5s
                elif lcdDlyStatCnt >= 20 and lcdDlyStatCnt < 30:
                    if lcdDlyStatCnt == 20:
                        mylcd.lcd_clear()

                    if lcdBattCap > 100:
                        lcdBattCap = 100

                    # Previously i2c LCD initialization are successful
                    if i2cLcd == True:
                        mylcd.lcd_display_string("Volt: %5.2fV" % lcdBattVolt, 1)
                        mylcd.lcd_display_string("Cap: %5i%%" % lcdBattCap, 2)

                    # Previously i2c LCD initialization are failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_LCD: Volt: %5.2fV" % lcdBattVolt)
                            logger.info("DEBUG_LCD: Cap: %5i%%" % lcdBattCap)
                        # Print statement
                        else:
                            print "DEBUG_LCD: Volt: %5.2fV" % lcdBattVolt
                            print "DEBUG_LCD: Cap: %5i%%" % lcdBattCap
                            
                # Reset counter
                elif lcdDlyStatCnt == 30:
                    lcdDlyStatCnt = 0

            elif lcdOperSel == 1:
                # Turn ON LCD back light
                GPIO.output(27, GPIO.HIGH)

                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    mylcd.lcd_display_string('ENCRYPT Process ', 1)
                    mylcd.lcd_display_string('Please wait.....', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: ENCRYPT Process")
                        logger.info("DEBUG_LCD: Please wait.....")
                    # Print statement
                    else:
                        print "DEBUG_LCD: ENCRYPT Process"
                        print "DEBUG_LCD: Please wait....."
                            
                lcdOperSel = 2

            elif lcdOperSel == 3:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    mylcd.lcd_display_string('ENCRYPT Process ', 1)
                    mylcd.lcd_display_string('Successful      ', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: ENCRYPT Process")
                        logger.info("DEBUG_LCD: Successful")
                    # Print statement
                    else:
                        print "DEBUG_LCD: ENCRYPT Process"
                        print "DEBUG_LCD: Successful"
                        
                # Delay a bit, to display another info
                time.sleep(3)

                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    mylcd.lcd_display_string('Please remove   ', 1)
                    mylcd.lcd_display_string('USB stick.......', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: Please remove")
                        logger.info("DEBUG_LCD: USB stick.......")
                    # Print statement
                    else:
                        print "DEBUG_LCD: Please remove"
                        print "DEBUG_LCD: USB stick......."
                
                lcdOperSel = 4

            elif lcdOperSel == 5:
                # Turn ON LCD back light
                GPIO.output(27, GPIO.HIGH)

                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    mylcd.lcd_display_string('DECRYPT Process ', 1)
                    mylcd.lcd_display_string('Please wait.....', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: DECRYPT Process")
                        logger.info("DEBUG_LCD: Please wait.....")
                    # Print statement
                    else:
                        print "DEBUG_LCD: DECRYPT Process"
                        print "DEBUG_LCD: Please wait....."

                lcdOperSel = 6

            elif lcdOperSel == 7:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    mylcd.lcd_display_string('DECRYPT Process ', 1)
                    mylcd.lcd_display_string('Successful      ', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: DECRYPT Process")
                        logger.info("DEBUG_LCD: Successful")
                    # Print statement
                    else:
                        print "DEBUG_LCD: DECRYPT Process"
                        print "DEBUG_LCD: Successful"

                lcdOperSel = 8

            elif lcdOperSel == 9:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    mylcd.lcd_display_string('Init. 4G modem  ', 1)
                    mylcd.lcd_display_string('Successful      ', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: Init. 4G modem")
                        logger.info("DEBUG_LCD: Successful")
                    # Print statement
                    else:
                        print "DEBUG_LCD: Init. 4G modem"
                        print "DEBUG_LCD: Successful"
                        
                lcdOperSel = 10

            elif lcdOperSel == 11:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    mylcd.lcd_display_string('Init. NC2VPN    ', 1)
                    mylcd.lcd_display_string('Successful      ', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: Init. NC2VPN")
                        logger.info("DEBUG_LCD: Successful")
                    # Print statement
                    else:
                        print "DEBUG_LCD: Init. NC2VPN"
                        print "DEBUG_LCD: Successful"
                        
                # Delay a bit, to display another info
                time.sleep(3)

                lcdOperSel = 0
                lcdDlyStatCnt = 0
                lcdBlTimeOut = 0

            elif lcdOperSel == 12:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    # Write to LCD info
                    mylcd.lcd_display_string('DECRYPT Process ', 1)
                    mylcd.lcd_display_string('Failed!         ', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: DECRYPT Process")
                        logger.info("DEBUG_LCD: Failed!")
                    # Print statement
                    else:
                        print "DEBUG_LCD: DECRYPT Process"
                        print "DEBUG_LCD: Failed!"

                # Delay a bit, to display another info
                time.sleep(3)

                lcdOperSel = 0
                lcdDlyStatCnt = 0
                lcdBlTimeOut = 0
                
            elif lcdOperSel == 13:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    # Write to LCD info
                    mylcd.lcd_display_string('ENCRYPT Process ', 1)
                    mylcd.lcd_display_string('Failed!         ', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: ENCRYPT Process")
                        logger.info("DEBUG_LCD: Failed!")
                    # Print statement
                    else:
                        print "DEBUG_LCD: ENCRYPT Process"
                        print "DEBUG_LCD: Failed!"

                # Delay a bit, to display another info
                time.sleep(3)

                lcdOperSel = 0
                lcdDlyStatCnt = 0
                lcdBlTimeOut = 0

            elif lcdOperSel == 14:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    # Write to LCD info
                    mylcd.lcd_display_string('Init. Radio Svr ', 1)
                    mylcd.lcd_display_string('Successful      ', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: Init. Radio Svr")
                        logger.info("DEBUG_LCD: Successful")
                    # Print statement
                    else:
                        print "DEBUG_LCD: Init. Radio Svr"
                        print "DEBUG_LCD: Successful"
                        
                # Delay a bit, to display another info
                time.sleep(3)

                lcdOperSel = 0
                lcdDlyStatCnt = 0
                lcdBlTimeOut = 0

            elif lcdOperSel == 15:
                # Previously i2c LCD initialization are successful
                if i2cLcd == True:
                    mylcd.lcd_clear()
                    # Write to LCD info
                    mylcd.lcd_display_string('SDR NOT Exist!  ', 1)
                    mylcd.lcd_display_string('Please reconnect', 2)

                # Previously i2c LCD initialization are failed
                else:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_LCD: SDR NOT Exist!")
                        logger.info("DEBUG_LCD: Please reconnect")
                    # Print statement
                    else:
                        print "DEBUG_LCD: SDR NOT Exist!"
                        print "DEBUG_LCD: Please reconnect"
                        
                # Delay a bit, to display another info
                time.sleep(3)

                lcdOperSel = 0
                lcdDlyStatCnt = 0
                lcdBlTimeOut = 0
                
        # Error in execution
        except:
            # Write to logger
            if backLogger == True:
                logger.info("DEBUG_LCD: LCD FAILED!")
            # Print statement
            else:
                print "DEBUG_LCD: LCD FAILED!"
            
# Check UPS lite HAT battery status
def checkBattStatus (threadname, delay):
    global backLogger
    global delayRdBatt
    global lcdBattVolt        
    global lcdBattCap
    global i2cUps
    
    delayFlag = False     

    # Forever loop
    while True:
        # Loop every 0.5s
        time.sleep(delay)

        # Try execution
        try:
            delayRdBatt += 1

            # Read current battery voltage every 5s
            if delayRdBatt == 10:
                # Previously i2c LCD initialization are successful
                if i2cUps == True:
                    # Read current battery voltage and capacity
                    # Stored it to local variable
                    lcdBattVolt = readBattVoltage(i2cBus)
                    lcdBattCap = readBattCapacity(i2cBus)

                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_BATT: Volt: %5.2fV" % lcdBattVolt)
                        logger.info("DEBUG_BATT: Cap: %5i%%" % lcdBattCap)
                    # Print statement
                    else:
                        print "DEBUG_BATT: Volt: %5.2fV" % lcdBattVolt
                        print "DEBUG_BATT: Cap: %5i%%" % lcdBattCap

                # Previously i2c LCD initialization are failed
                else:
                    lcdBattVolt = 'NA'
                    lcdBattCap = 'NA'
                    
                delayRdBatt = 0

        # Error in execution
        except:
            # Write to logger
            if backLogger == True:
                logger.info("DEBUG_BATT: UPS-Lite FAILED!")
            # Print statement
            else:
                print "DEBUG_BATT: UPS-Lite FAILED!"

# Check and monitor USB thumb drive plug in status
def checkUSBStatus (threadname, delay):
    global eCryptProc
    global dCryptProc
    global tunnelValid
    global net4gValid
    global lcdOperSel
    global lcdDlyStatCnt
    global lcdBlTimeOut
    global netMonChkCnt
    global backLogger

    # Forever loop
    while True:
        # Loop every 0.5s
        time.sleep(delay)

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='usb')

        monitor.start()
        for device in iter(monitor.poll, None):
            if device.action != 'add':
                if eCryptProc == True or dCryptProc == True:
                    # STOP 4G LTE modem
                    out = subprocess.Popen(['qmicli', '-d', '/dev/cdc-wdm0', '--device-open-sync', '--dms-get-operating-mode'], \
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        if 'HW restricted:' in stdout:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_USBMON: STOP 4G LTE modem successful")
                            # Print statement
                            else:
                                print "DEBUG_USBMON: STOP 4G LTE modem successful"
                            
                            # Wait before execute another command
                            time.sleep(1)

                            # Bring wwan0 interface DOWN
                            out = subprocess.Popen(['ifconfig', 'wwan0', 'down'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                            stdout,stderr = out.communicate()

                            # NO error after command execution
                            if stderr == None:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_USBMON: Bringing DOWN wwan0 successful")
                                # Print statement
                                else:
                                    print "DEBUG_USBMON: Bringing DOWN wwan0 successful"

                                # Wait before execute another command
                                time.sleep(1)

                                # KILL udhcpc instances
                                out = subprocess.Popen(['killall', 'udhcpc'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_USBMON: KILL  udhcpc SUCCESSFUL")
                                    # Print statement
                                    else:
                                        print "DEBUG_USBMON: KILL  udhcpc SUCCESSFUL"
                                                        
                                    # Wait before execute another command
                                    time.sleep(1)
                                
                                    # STOP VPN tunnel
                                    out = subprocess.Popen(['killall', 'openvpn'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                    stdout,stderr = out.communicate()

                                    # NO error after command execution
                                    if stderr == None:
                                        if 'no process found' in stdout:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_USBMON: Openvpn process NOT found")
                                            # Print statement
                                            else:
                                                print "DEBUG_USBMON: Openvpn process NOT found"
                                        else:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_USBMON: KILL openvpn successful")
                                            # Print statement
                                            else:
                                                print "DEBUG_USBMON: KILL openvpn successful"

                                    # Operation failed
                                    else:
                                        # Write to logger
                                        if backLogger == True:
                                            logger.info("DEBUG_USBMON: KILL openvpn FAILED!")
                                        # Print statement
                                        else:
                                            print "DEBUG_USBMON: KILL openvpn FAILED!"

                            # Operation failed
                            else:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_USBMON: Bringing DOWN wwan0 FAILED!")
                                # Print statement
                                else:
                                    print "DEBUG_USBMON: Bringing DOWN wwan0 FAILED!"

                        # Operation failed
                        else:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_USBMON: STOP 4G LTE modem FAILED!")
                            # Print statement
                            else:
                                print "DEBUG_USBMON: STOP 4G LTE modem FAILED!"

                    # Operation failed
                    else:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_USBMON: Command execution to STOP 4G LTE modem FAILED!")
                        # Print statement
                        else:
                            print "DEBUG_USBMON: Command execution to STOP 4G LTE modem FAILED!"

                    # Turn ON LCD back light
                    GPIO.output(27, GPIO.HIGH)

                    # Reset necessary LCD operation variable
                    lcdDlyStatCnt = 0
                    lcdOperSel = 0
                    lcdBlTimeOut = 0
                    
                    eCryptProc = False
                    dCryptProc = False

                    netMonChkCnt = 0
                    tunnelValid = False
                    net4gValid = False
                    
# Initiate 4G LTE modem - Prepare the 4G connection network with service provider
def initiate4GModem ():
    global backLogger
    global publicIPaddr
    
    retResult = False
    
    # Check current 4G LTE modem status first
    # Command: qmicli -d /dev/cdc-wdm0 --dms-get-operating-mode
    # Reply:
    # [/dev/cdc-wdm0] Operating mode retrieved:
    # Mode: 'online' or 'offline'
    # HW restricted: 'no'
    out = subprocess.Popen(['qmicli', '-d', '/dev/cdc-wdm0', '--dms-get-operating-mode'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = out.communicate()

    # NO error after command execution
    if stderr == None:
        execResult = stdout
            
        # 4G LTE modem OFFLINE, start to wake up 4G LTE modem
        # Command: qmicli -d /dev/cdc-wdm0 --dms-set-operating-mode='online'
        # Reply:
        # [/dev/cdc-wdm0] Operating mode set successfully
        if 'unknown' in execResult: 
            out = subprocess.Popen(['qmicli', '-d', '/dev/cdc-wdm0', "--dms-set-operating-mode=online"], \
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout,stderr = out.communicate()

            # NO error after command execution
            if stderr == None:
                execResult = stdout

                # Wake up 4G LTE modem successful, start bring interface wwan0 down
                # Command: ifconfig wwan0 down
                # Reply: NA
                if 'successfully' in execResult:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_4G_MODEM: Set modem operating mode SUCCESSFUL")
                    # Print statement
                    else:
                        print "DEBUG_4G_MODEM: Set modem operating mode SUCCESSFUL"

                    # Wait before execute another command
                    time.sleep(1)
                    
                    out = subprocess.Popen(['ifconfig', 'wwan0', 'down'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()

                    # NO error after command execution
                    if stderr == None:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_4G_MODEM: Bringing DOWN interface wwan0 SUCCESSFUL")
                        # Print statement
                        else:
                            print "DEBUG_4G_MODEM: Bringing DOWN interface wwan0 SUCCESSFUL"

                        # Wait before execute another command
                        time.sleep(1)
                    
                        # Enable OS Raw IP Mode setting (not persistent)
                        # Command (bash): echo Y > /sys/class/net/wwan0/qmi/raw_ip
                        # Reply: NA
                        out = subprocess.Popen(["echo Y > /sys/class/net/wwan0/qmi/raw_ip"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            # Write to logger
                            if backLogger == True:
                                logger.info("DEBUG_4G_MODEM: Enable OS Raw IP Mode setting SUCCESSFUL")
                            # Print statement
                            else:
                                print "DEBUG_4G_MODEM: Enable OS Raw IP Mode setting SUCCESSFUL"

                            # Wait before execute another command
                            time.sleep(1)
                    
                            # Enable back wwan0 interface
                            # Command: ifconfig wwan0 up
                            # Reply: NA 
                            out = subprocess.Popen(['ifconfig', 'wwan0', 'up'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                            stdout,stderr = out.communicate()

                            # NO error after command execution
                            if stderr == None:
                                # Write to logger
                                if backLogger == True:
                                    logger.info("DEBUG_4G_MODEM: Bringing UP interface wwan0 SUCCESSFUL")
                                # Print statement
                                else:
                                    print "DEBUG_4G_MODEM: Bringing UP interface wwan0 SUCCESSFUL"

                                # Wait before execute another command
                                time.sleep(1)

                                # Register the network with APN name
                                # Command: qmicli -p -d /dev/cdc-wdm0 --device-open-net='net-raw-ip|net-no-qos-header' --wds-start-network="apn='celcom3g',username=' ',password=' ',ip-type=4" --client-no-release-cid
                                # Reply;
                                # [/dev/cdc-wdm0] Network started
                                # Packet data handle: '2264423824'
                                # [/dev/cdc-wdm0] Client ID not released:
                                # Service: 'wds'
                                # CID: '20'
                                out = subprocess.Popen(['qmicli', '-p', '-d', '/dev/cdc-wdm0', "--device-open-net=net-raw-ip|net-no-qos-header", \
                                                        '--wds-start-network=', "apn='celcom3g',username=' ',password=' ',ip-type=4", \
                                                        '--client-no-release-cid'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                stdout,stderr = out.communicate()

                                # NO error after command execution
                                if stderr == None:
                                    execResult = stdout
                                    
                                    if 'Network started' in execResult:
                                        if 'CID' in execResult:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_4G_MODEM: 4G network registration SUCCESSFUL")
                                            # Print statement
                                            else:
                                                print "DEBUG_4G_MODEM: 4G network registration SUCCESSFUL"

                                            # Wait before execute another command
                                            time.sleep(1)
                    
                                            # Finally, configure the IP address and the default route with udhcpc
                                            # Command: udhcpc -i wwan0
                                            # Reply:
                                            # udhcpc: sending discover
                                            # udhcpc: sending select for 183.171.144.62
                                            # udhcpc: lease of 183.171.144.62 obtained, lease time 7200
                                            out = subprocess.Popen(['udhcpc', '-i', 'wwan0'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                            stdout,stderr = out.communicate()

                                            # NO error after command execution
                                            if stderr == None:
                                                execResult = stdout

                                                # 4G LTE modem initialization with network provider completed
                                                #if '183.171.144.62 obtained' in execResult:
                                                tempChk = publicIPaddr + ' obtained'
                                                if tempChk in execResult:
                                                    # Write to logger
                                                    if backLogger == True:
                                                        logger.info("DEBUG_4G_MODEM: Obtained public IP address SUCCESSFUL")
                                                    # Print statement
                                                    else:
                                                        print "DEBUG_4G_MODEM: Obtained public IP address SUCCESSFUL"
                                                
                                                    retResult = True
                                                    return retResult
                                        
        # No need to initiate 4G LTE modem, previously has already initiated
        else:
            # Previously 4G LTE modem already online, start bring interface wwan0 down
            # Command: ifconfig wwan0 down
            # Reply: NA    
            out = subprocess.Popen(['ifconfig', 'wwan0', 'down'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout,stderr = out.communicate()

            # NO error after command execution
            if stderr == None:
                # Write to logger
                if backLogger == True:
                    logger.info("DEBUG_4G_MODEM: Bringing DOWN interface wwan0 SUCCESSFUL")
                # Print statement
                else:
                    print "DEBUG_4G_MODEM: Bringing DOWN interface wwan0 SUCCESSFUL"

                # Wait before execute another command
                time.sleep(1)
                    
                # Enable OS Raw IP Mode setting (not persistent)
                # Command (bash): echo Y > /sys/class/net/wwan0/qmi/raw_ip
                # Reply: NA
                out = subprocess.Popen(["echo Y > /sys/class/net/wwan0/qmi/raw_ip"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()

                # NO error after command execution
                if stderr == None:
                    # Write to logger
                    if backLogger == True:
                        logger.info("DEBUG_4G_MODEM: Enable OS Raw IP Mode setting SUCCESSFUL")
                    # Print statement
                    else:
                        print "DEBUG_4G_MODEM: Enable OS Raw IP Mode setting SUCCESSFUL"

                    # Wait before execute another command
                    time.sleep(1)
                    
                    # Enable back wwan0 interface
                    # Command: ifconfig wwan0 up
                    # Reply: NA 
                    out = subprocess.Popen(['ifconfig', 'wwan0', 'up'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout,stderr = out.communicate()                

                    # NO error after command execution
                    if stderr == None:
                        # Write to logger
                        if backLogger == True:
                            logger.info("DEBUG_4G_MODEM: Bringing UP interface wwan0 SUCCESSFUL")
                        # Print statement
                        else:
                            print "DEBUG_4G_MODEM: Bringing UP interface wwan0 SUCCESSFUL"

                        # Wait before execute another command
                        time.sleep(1)
                    
                        # Register the network with APN name
                        # Command: qmicli -p -d /dev/cdc-wdm0 --device-open-net='net-raw-ip|net-no-qos-header' --wds-start-network="apn='celcom3g',username=' ',password=' ',ip-type=4" --client-no-release-cid
                        # Reply;
                        # [/dev/cdc-wdm0] Network started
                        # Packet data handle: '2264423824'
                        # [/dev/cdc-wdm0] Client ID not released:
                        # Service: 'wds'
                        # CID: '20'
                        out = subprocess.Popen(['qmicli', '-p', '-d', '/dev/cdc-wdm0', "--device-open-net=net-raw-ip|net-no-qos-header", \
                                                '--wds-start-network=', "apn='celcom3g',username=' ',password=' ',ip-type=4", \
                                                '--client-no-release-cid'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        stdout,stderr = out.communicate()

                        # NO error after command execution
                        if stderr == None:
                            execResult = stdout
                            
                            if 'Network started' in execResult:
                                if 'CID' in execResult:
                                    # Write to logger
                                    if backLogger == True:
                                        logger.info("DEBUG_4G_MODEM: 4G network registration SUCCESSFUL")
                                    # Print statement
                                    else:
                                        print "DEBUG_4G_MODEM: 4G network registration SUCCESSFUL"

                                    # Wait before execute another command
                                    time.sleep(1)
                    
                                    # Finally, configure the IP address and the default route with udhcpc
                                    # Command: udhcpc -i wwan0
                                    # Reply:
                                    # udhcpc: sending discover
                                    # udhcpc: sending select for 183.171.144.62
                                    # udhcpc: lease of 183.171.144.62 obtained, lease time 7200
                                    out = subprocess.Popen(['udhcpc', '-i', 'wwan0'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                                    stdout,stderr = out.communicate()

                                    # NO error after command execution
                                    if stderr == None:
                                        execResult = stdout

                                        # 4G LTE modem initialization with network provider completed
                                        #if '183.171.144.62 obtained' in execResult:
                                        tempChk = publicIPaddr + ' obtained'
                                        if tempChk in execResult:
                                            # Write to logger
                                            if backLogger == True:
                                                logger.info("DEBUG_4G_MODEM: Obtained public IP address SUCCESSFUL")
                                            # Print statement
                                            else:
                                                print "DEBUG_4G_MODEM: Obtained public IP address SUCCESSFUL"

                                            retResult = True
                                            return retResult
    return retResult
            
# Script entry point
def main():
    global pubKeyPath
    global usbMountPath
    global nc2VpnKeyPath
    global nc2VpnKeyTPath
    global raspiIO
    global radioMode
    global ubuntuTouch
    
    # Using Raspberry PI computer
    if ubuntuTouch == False:
        mylcd.lcd_clear()

        # Create thread to get battery status 
        try:
            thread.start_new_thread(checkBattStatus, ("[checkBattStatus]", 0.5 ))
        except:
            # Write to logger
            if backLogger == True:
                logger.info("THREAD_ERROR: Unable to start [checkBattStatus] thread")
            # Print statement
            else:
                print "THREAD_ERROR: Unable to start [checkBattStatus] thread"

        # Create thread for LCD operation                 
        try:
            thread.start_new_thread(lcdOperation, ("[lcdOperation]", 0.5 ))
        except:
            # Write to logger
            if backLogger == True:
                logger.info("THREAD_ERROR: Unable to start [lcdOperation] thread")
            # Print statement
            else:
                print "THREAD_ERROR: Unable to start [lcdOperation] thread"

        # Create thread for network monitoring and validation
        try:
            thread.start_new_thread(networkMon, ("[networkMon]", 1 ))
        except:
            # Write to logger
            if backLogger == True:
                logger.info("THREAD_ERROR: Unable to start [networkMon] thread")
            # Print statement
            else:
                print "THREAD_ERROR: Unable to start [networkMon] thread"

        # Secure gateway feature
        if radioMode == False:
            # Create thread for USB thumb drive removal
            try:
                thread.start_new_thread(checkUSBStatus, ("[checkUSBStatus]", 0.5 ))
            except:
                # Write to logger
                if backLogger == True:
                    logger.info("THREAD_ERROR: Unable to start [checkUSBStatus] thread")
                # Print statement
                else:
                    print "THREAD_ERROR: Unable to start [checkUSBStatus] thread"

            # Setup pyInotify
            wm = pyinotify.WatchManager()  # Watch Manager
            mask = pyinotify.IN_CREATE     # watched events

            notifier = pyinotify.Notifier(wm, EventHandler(pubKeyPath, nc2VpnKeyPath, nc2VpnKeyTPath))

            wdd = wm.add_watch(usbMountPath, mask)

            notifier.loop()  # Blocking loop

        # Radio monitoring mode 
        else:
            # Forever loop - Just to ensure the script are running
            while True:
                # Loop every 1s
                time.sleep(1)

    # Using Ubuntu Touch smartphone 
    else:
        # Create thread for network monitoring and validation
        try:
            thread.start_new_thread(uTouchCommProc, ("[uTouchCommProc]", 1 ))
        except:
            # Write to logger
            if backLogger == True:
                logger.info("THREAD_ERROR: Unable to start [uTouchCommProc] thread")
            # Print statement
            else:
                print "THREAD_ERROR: Unable to start [uTouchCommProc] thread"

        # Check directory existence
        directExists = False
        while directExists == False:
            # Check for folder availability
            directExists = path.exists('/media/phablet')
            # Start create the directory
            if directExists == False:
                out = subprocess.Popen(['cd /media;mkdir phablet'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout,stderr = out.communicate()
                
                # NO error after command execution
                if stderr == None:
                    # Write to logger
                    if backLogger == True:
                        logger.info("MAIN: Create /media/phablet directory SUCCESSFULL")
                    # Print statement
                    else:
                        print "MAIN: Create /media/phablet directory SUCCESSFULL"

                    directExists = True               
        
        # Create thread for checking current USB thumb drive status
        try:
            thread.start_new_thread(checkUSBUtouchStatus, ("[checkUSBUtouchStatus]", 0.5 ))
        except:
            # Write to logger
            if backLogger == True:
                logger.info("THREAD_ERROR: Unable to start [checkUSBUtouchStatus] thread")
            # Print statement
            else:
                print "THREAD_ERROR: Unable to start [checkUSBUtouchStatus] thread"

        # Setup pyInotify
        wm = pyinotify.WatchManager()  # Watch Manager
        mask = pyinotify.IN_CREATE     # watched events

        notifier = pyinotify.Notifier(wm, EventHandler(pubKeyPath, nc2VpnKeyPath, nc2VpnKeyTPath))

        wdd = wm.add_watch(usbMountPath, mask)

        notifier.loop()  # Blocking loop
    
if __name__ == "__main__":
    main()


            
