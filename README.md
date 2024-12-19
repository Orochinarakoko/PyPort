# PyPortScanner
This is a simple , GUI-based python script that utilises the sockets module in order to scan ports

# How it works:
1) The tkinter module provides an interface for the user to enter or receive information
2) The user uses the GUI to enter the target IP , or URL , and selects the IP version
4) The user then chooses the "mode" that they will use in order to scan the port ( they can choose from a range , a list of common ports or the first 1024 ports )
5) If the user entered a url , the program will find th IP address associated with that url using socket.gethostbyaddr()
6) The program then creates the socket that it will use to connect to target. For layer 4 , all sockets use TCP (socket.SOCK_STREAM) , and for layer 3 , if the user entered a URL or IPv4 address , the socket will use IPv4 (socket.AF_INET) , else it will use IPv6 (socket.AF_INET6)
7) The program then runs through the list / range of specified ports , and tries to establish a connection over each port using the socket. If the connection is sucessfully established , then we know that the port is open , and  can use the GUI to tell the user
8) However , if the connection is not established , then we can determine that the port is most likely not open
