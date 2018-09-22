#######################################################################
"""
Dependencies: Python3.6.6, paramiko
Flow:
UserInput for remote device-> Using paramiko, send commands and obtain appropriate output for commands-> Use pyregex to extract data to populate datastructures-> Ask for user input for displaying information
"""


import re
import paramiko
import getpass
import time

#Add later
IP_ADDRESS = input("Provide device IP> ")
username = input("Enter the username> ")
password = input("Enter the password> ")

# IP_ADDRESS = '192.168.56.101'
# username = 'vagrant'
# password = 'vagrant'

remoteIP = IP_ADDRESS
username = username
password = password

handler = paramiko.SSHClient();

handler.set_missing_host_key_policy(paramiko.AutoAddPolicy())
handler.connect(IP_ADDRESS, username=username, password=password, look_for_keys=False, allow_agent=False)
print("Connection Established..Now sending commands")
time.sleep(2)
shell = handler.invoke_shell()

output = shell.recv(1000)
shell.send("ip addr show\n")
time.sleep(2)
data = shell.recv(1000)

EXPRESSION = r"(eth\d|lo|wifi\d):\s\<[A-Za-z0-9,_]*\>\s[a-zA-Z0-9,_ ]*\\r\\n\s{1,10}link/(ether|loopback)\s([0-9a-zA-Z:]*)\sbrd\s[0-9a-z:]*\\r\\n(\s{1,6}inet\s([0-9\/.]*))?"

r1 = re.findall(EXPRESSION,str(data))

interfaces = [list(item) for item in r1]

interfaces_type_dict = {}
interfaces_mac_dict = {}
interfaces_ip_dict = {}

for item in interfaces :
    interfaces_type_dict[item[0]] = item[1]
    interfaces_mac_dict[item[0]] = item[2]
    interfaces_ip_dict[item[0]] = item[4]

for item in interfaces_ip_dict.keys():
    if interfaces_ip_dict[item]!='':
        ip = interfaces_ip_dict[item].split("/")[0]
        interfaces_ip_dict[item] = ip
    else:
        interfaces_ip_dict[item] = None
print("Data structures populated")



print("Now, do you wish to search interfaces by \n1.IP\n2.MAC\n3.TYPE\n4.Display All Interfaces by IP\n5.Display All by MAC\n6.Display all by type. Please Enter your choice")

choice = int(input(">"))

if (choice==1):
    ip_address = input("Enter the IP Address of the Interface> ")
    try:
        interface_for_ip = list(interfaces_ip_dict.keys())[list(interfaces_ip_dict.values()).index(ip_address)]
        if interface_for_ip:
            print ("#############################")
            print ("Here is the interface" ,interface_for_ip)
            print ("Other Details..TYPE :" + interfaces_type_dict[interface_for_ip] + " ....MAC :" + interfaces_mac_dict[interface_for_ip])
    except ValueError:
        print ("#############################")
        print ("The IP does not exist on the box")


elif (choice==2):
    mac = input("Enter the mac of the interface> ")
    try:
        interface_for_mac = list(interfaces_mac_dict.keys())[list(interfaces_mac_dict.values()).index(mac)]
        print(interface_for_mac)
        print ("#############################")
        print ("Here is the interface", interface_for_mac)
        print ("Other Details..TYPE: " + interfaces_type_dict[interface_for_mac] + ".......IP: " + str(interfaces_ip_dict[interface_for_mac]))

    except ValueError:
        print("This mac does not exist on the box")

elif (choice==3):
    print("Some interface types \n1.loopback\n2.ether(ethernet)\n3.ieee802.11")
    type_interface = input("Enter the type of the interface> ")

    try:
        if type_interface in interfaces_type_dict.values():
            l = [k for k in interfaces_type_dict.keys() if interfaces_type_dict[k]==type_interface]
            for item in l:
                print("Interface : ", item)
                print("IP Details : ", interfaces_ip_dict[item])
                print("MAC Details : ", interfaces_mac_dict[item])
        else:
            raise ValueError
    except ValueError:
        print ("This interface does not exist on the box")
elif(choice==4):
    for k,v in interfaces_ip_dict.items():
        print(f"Interface {k} : {v}")
elif(choice==5):
    for k,v in interfaces_mac_dict.items():
        print(f"Interface {k} : {v}")
elif(choice==6):
    for k,v in interfaces_type_dict.items():
        print(f"Interface {k} : {v}")
else:
    print ("You are a rebel!. But since I am an amateur, could you please pick a value that is stated above ? Thank you!")

