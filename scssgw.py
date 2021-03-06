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

import os, re, sys, time, socket
import thread
import logging
import logging.handlers
import subprocess
import struct
import smbus
import pyinotify
import I2C_LCD_driver
import pyudev

# Global variable declaration
backLogger         = False    # Macro for logger
raspiIO            = False    # Macro for pi zero w IO interfacing
radioMode          = False    # Macro for radio mode functionalities
radioOpt           = 0        # Macro for radio data mode of transmission
radioValid         = False    # Flag to indicate SDR radio server are successfully initiated
dCryptProc         = False    # Flag to indicate decryption process are successfully done 
eCryptProc         = False    # Flag to indicate encryption process are successfully done
pingValid          = False    # Flag to indicate the client machine are already connected
tunnelValid        = False    # Flag to indicate the VPN tunnel are successfully initiated
net4gValid         = False    # Flag to indicate 4G network are successfully initiated
scrollUP           = False    # Scroll UP process flag during tact switch is pressed
scrollDWN          = False    # Scroll DOWN process flag during tact switch is pressed
i2cUps             = False    # Flag to check UPS-Lite i2c initialization status
i2cLcd             = False    # Flag to check LCD i2c initialization status
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
    for x in sys.argv:
        if x != 'scssgw.py':
            # Get the SIM card public IP address
            if tmpFlag == False:
                publicIPaddr = x
                tmpFlag = True
            elif tmpFlag == True:
                # Optional macro if we want to enable text file log
                if x == 'LOGGER':
                    backLogger = True
                # Optional macro if we want to enable raspberry pi IO interfacing
                elif x == 'RASPI':
                    raspiIO = True
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

# Setup log file 
if backLogger == True:
    path = os.path.dirname(os.path.abspath(__file__))
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logfile = logging.handlers.TimedRotatingFileHandler('/tmp/secgw.log', when="midnight", backupCount=3)
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    logfile.setFormatter(formatter)
    logger.addHandler(logfile)

# Print macro arguments for debugging purposes
# Write to logger
if backLogger == True:
    logger.info("DEBUG_MACRO: Arguments: %s %s %s %s %s" % (publicIPaddr, backLogger, raspiIO, radioMode, radioOpt))
# Print statement
else:
    print "DEBUG_MACRO: Arguments: %s %s %s %s %s" % (publicIPaddr, backLogger, raspiIO, radioMode, radioOpt)
                

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
# USB thumb drive mount path
usbMountPath = '/media/root'
# nc2vpn key path - Encrypted file
nc2VpnKeyPath = '/sources/common/vpn-client-key/nc2vpn-key'
# nc2vpn key temporary path - Decrypted file
nc2VpnKeyTPath = '/sources/common/vpn-client-key/temp-nc2vpn-key'
# Client computer hard coded IP address
clientIPAddr = '192.168.4.201'

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
                if 'key.private' in stdout:
                    self.cryptoType = True
            
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

# Connection and tunnel monitoring - network monitoring and validation
def networkMon (threadname, delay):
    global dCryptProc
    global clientIPAddr
    global pingValid
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
                        pingValid = True

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
    global pingValid
    global tunnelValid
    global net4gValid
    global radioMode
    global radioValid
    global i2cLcd
    
    # Forever loop
    while True:
        # Loop every 0.5s
        time.sleep(delay)

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
        
        delayRdBatt += 1

        # Read current battery voltage every 5s
        if delayRdBatt == 10:
            # Previously i2c LCD initialization are successful
            if i2cUps == True:
                # Read current battery voltage and capacity
                # Stored it to local variable
                lcdBattVolt = readBattVoltage(i2cBus)
                lcdBattCap = readBattCapacity(i2cBus)

            # Previously i2c LCD initialization are failed
            else:
                lcdBattVolt = 'NA'
                lcdBattCap = 'NA'
                
            delayRdBatt = 0

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
    
if __name__ == "__main__":
    main()


            
