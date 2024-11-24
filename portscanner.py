import socket
import tkinter as tk
from tkinter.messagebox import showinfo
import queue
#-----------------------------------------------------------------------------------------------



#-----------------------------------------------------------------------------------------------

ports = queue.Queue()


foundPorts = []

firewalledPorts = []

errors = {
    "10060":"CONNECTION TIMEOUT  - COULD BE DUE T0 FIREWALL",
    "10061":"CONNECTION REFUSED",
    "10056":"ALREADY CONNECTED"
    }

common = [80,23,443,21,22,
          25,3389,110,445,139,
          143,53,135,3306,8080,
          1723,111,995,993,5900,
          1025,587,8888,199,1720,
          465,548,113,81,6001,
          10000,514,5060,179,1026,
          2000,8443,8000,32768,554,
          26,1433,49152,2001,515,
          8008,49154,1027,5666,646,
          5000,631,49153,8081,2049,
          88,79,5800,106,2121,
          1110,49155,6000,513,990,
          5357,427,49156,543,544,
          5101,144,7,389,8009,
          3128,444,9999,5009,7070,
          5190,3000,5432,1900,3986,
          13,1029,9,5051,6646,
          49157,1028,873,1755,2717,
          4899,9100,119,37,5631
         

          ]



#-----------------------------------------------------------------------------------------------

window = tk.Tk()

window.configure(bg="black")
window.title("TCP SYN SCANNER")
window.state("zoomed")
##-----------------------------------------------------------------------------------------------


def get_target():


    global target


    target = str(targetInput.get())

    if target == "":

        noTarget = showinfo("TARGET","NO TARGET INPUTTED")

    else:
        set_target.configure(bg = "red" , fg = "yellow")

        
        

#-----------------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------


def scan():

    if is_url == 1:
        global target
        target = socket.gethostbyname(target)
        print(target)

    print(is_ip4)

    scanResults = tk.Label(window,
                           bg = "white",
                           fg = "black",
                           text = "",
                           width = 120,
                           height =28)
    
    scanResults.place(relx = 0.6,rely=0.53 , anchor = "c")





    textOutput = "FOUND PORTS\n"

    textOutput = textOutput + "\n"

    window.update()        

    while not ports.empty():

        if is_ip4 == 1 or is_url == 1:

            connec = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        else:
            connec = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        
        port = ports.get()
        



        info = (str(target),port)

        
        try:
            sock = connec.connect_ex(info)

        except:
            continue
            
        if sock == 0:
                
            textOutput = textOutput + (f"PORT {port} OPEN\n")

            scanResults.configure(text = (f"{textOutput}"))

            window.update()




    finishedInfo = showinfo("SCANNING","FINISHED SCANNING PORTS")


    set_target.configure(fg= "black",bg = "#20C20E")
    
    url_format.configure(bg = "#20C20E",
                         fg = "black")
    ip4_format.configure(bg = "#20C20E",
                         fg = "black")
    ip6_format.configure(bg = "#20C20E",
                         fg = "black")

    port_range.configure(bg = "#20C20E",fg = "black")
    port_1024.configure(bg = "#20C20E",fg = "black")
    port_common.configure(bg="#20C20E",fg = "black")

    





                


#-----------------------------------------------------------------------------------------------

def set_url():
    url_format.configure(bg = "red",
                         fg = "yellow")
    ip4_format.configure(bg = "#20C20E",
                         fg = "black")
    ip6_format.configure(bg = "#20C20E",
                         fg = "black")

    global is_url
    global is_ip4
    global is_ip6

    is_url = 1
    is_ip4 = 0
    is_ip6 = 0

#---------------------------------------------------------------------------------------------

def set_ip4():
    url_format.configure(bg = "#20C20E",
                         fg = "black")
    ip4_format.configure(bg = "red",
                         fg = "yellow")
    ip6_format.configure(bg = "#20C20E",
                         fg = "black")

    global is_url
    global is_ip4
    global is_ip6

    is_url = 0
    is_ip4 = 1
    is_ip6 = 0


#---------------------------------------------------------------------------------------------

def set_ip6():
    url_format.configure(bg = "#20C20E",
                         fg = "black")
    ip4_format.configure(bg = "#20C20E",
                         fg = "black")
    ip6_format.configure(bg = "red",
                         fg = "yellow")


    global is_url
    global is_ip4
    global is_ip6

    is_url = 0
    is_ip4 = 0
    is_ip6 = 1

#---------------------------------------------------------------------------------------------

def set_range():

    ports.queue.clear()

    port_range.configure(bg="red",fg="yellow")

    port_1024.configure(bg = "#20C20E",fg = "black")
    port_common.configure(bg="#20C20E",fg = "black")
    
    rangeWindow = tk.Tk()
    rangeWindow.geometry("500x500")

    minPortText = tk.Label(rangeWindow,
                           bg = "white",
                           fg = "black",
                           font = ("Segoe",20),
                           width = 60,
                           text = "Enter Minimum Port")

    minPortText.place(relx = 0.5,rely = 0.2, anchor = "center")

    minPortInput = tk.Entry(rangeWindow,
                           bg = "white",
                           fg = "black",
                           width = 60,
                           highlightbackground = "black")



    

    minPortInput.place(relx = 0.5,rely=0.3 ,anchor = "center")


    maxPortText = tk.Label(rangeWindow,
                           bg = "white",
                           fg = "black",
                           font = ("Segoe",20),
                           width = 60,
                           text = "Enter Maximum Port")

    maxPortText.place(relx = 0.5,rely = 0.5, anchor = "center")

    maxPortInput = tk.Entry(rangeWindow,
                           bg = "white",
                           fg = "black",
                           width = 60,
                           highlightbackground = "black")



    

    maxPortInput.place(relx = 0.5,rely=0.7 ,anchor = "center")


    def get_ports():

        while True:

            try:
                minport = int(minPortInput.get())
                maxport = int(maxPortInput.get())

                if minport > maxport:
                    maxport = minport
                    minport = maxport

                                    
                    for i in range(minport , maxport+1):
                        ports.put(i)

                        
                    rangeWindow.destroy()
                    break

                
                elif minport == maxport:
                    
                    port_range.configure(bg = "#20C20E",fg="black")
                    invalidInput = showinfo("Range","INVALID INPUT")
                    rangeWindow.destory()
                    
                    break

                else:

                
                    for i in range(minport , maxport+1):
                        ports.put(i)

                    rangeWindow.destroy()
                        
                    break

            
            except:
                port_range.configure(bg = "#20C20E",fg = "black")
                invalidInput = showinfo("Range","INVALID INPUT")
                rangeWindow.destory()
                break

    

    


    enterRange = tk.Button(rangeWindow,
                           bg = "black",
                           fg = "white",
                           text = "ENTER RANGE",
                           font = ("Segoe","25"),
                           command = get_ports)

    enterRange.place(relx = 0.5,rely=0.9,anchor = "center")




        







   
def set_1024():

    ports.queue.clear()

    
    port_range.configure(bg = "#20C20E",fg = "black")
    port_1024.configure(bg = "red",fg = "yellow")
    port_common.configure(bg="#20C20E",fg = "black")


    
    for i in range(1025):
        ports.put(i)

def set_common():

    ports.queue.clear()
    
    port_range.configure(bg = "#20C20E",fg = "black")
    port_common.configure(bg = "red",fg = "yellow")
    port_1024.configure(bg="#20C20E",fg = "black")

    for i in common:
       ports.put(i)







#---------------------------------------------------------------------------------------------
title = tk.Label(window,
                 fg = "#20C20E",
                 bg = "black",
                 text="TCP SYN SCANNER",
                 font = ("Impact",35),
                 width = 50,
                 height = 2)

title.place(relx=0.5,rely=0.05,anchor = "center")

#-----------------------------------------------------------------------------------------------

target_prompt = tk.Label(window,
                         fg = "#20C20E",
                         bg = "black",
                         text="Enter target IP / URL : ",
                         font = ("Segoe",15),
                         width = 50,
                         height = 2)

target_prompt.place(relx = 0.2,rely = 0.15,anchor = "center")

#------------------------------------------------------------------------------------------------
                 
targetInput = tk.Entry(window,
                  fg = "black",
                  bg = "white",
                  width = 80)

targetInput.place(relx = 0.2,rely = 0.2,anchor = "center")

#--------------------------------------------------------------------------------------------------

set_target = tk.Button(fg = "black",
                       bg = "#20C20E",
                       width = 50,
                       text = "SET TARGET",
                       font = ("Segoe",10),
                       command = get_target)

set_target.place(relx = 0.2 , rely = 0.23,anchor = "center")


#----------------------------------------------------------------------------------------------------

input_format = tk.Label(window,
                        text = "Enter target info format : ",
                        width = 50,
                        height = 2,
                        fg = "#20C20E",
                        bg = "black",
                        font = ("Segoe",15))

input_format.place(relx = 0.7,rely = 0.15 , anchor = "center")

#--------------------------------------------------------------------------------------------------

url_format = tk.Button(window,
                       height = 1,
                       width = 10,
                       text = "URL",
                       font = ("Segoe",20),
                       fg = "black",
                       bg = "#20C20E",
                       command = set_url)

url_format.place(relx = 0.5,rely = 0.2,anchor = "center")
#-------------------------------------------------------------------------------------------------

ip4_format = tk.Button(window,
                       height = 1,
                       width = 10,
                       text = "IPv4",
                       fg = "black",
                       bg = "#20C20E",
                       font = ("Segoe",20),
                       command = set_ip4)

ip4_format.place(relx = 0.7,rely = 0.2,anchor = "center")

#---------------------------------------------------------------------------------------------

ip6_format = tk.Button(window,
                       height = 1,
                       width = 10,
                       text = "IPv6",
                       fg = "black",
                       bg = "#20C20E",
                       font = ("Segoe",20),
                       command = set_ip6)

ip6_format.place(relx=0.9,rely = 0.2,anchor = "center")
                       
#-----------------------------------------------------------------------------------------------

port_option = tk.Label(text = "Port option",
                       fg = "#20C20E",
                       bg = "black",
                       font = ("Segoe",20),
                       height = 2,
                       width = 50)

port_option.place(relx = 0.2,rely = 0.4, anchor = "center")
#----------------------------------------------------------------------------------------------

port_range = tk.Button(text = "Range",
                       fg = "black",
                       bg = "#20C20E",
                       font = ("Segoe",15),
                       command = set_range,
                       height = 1,
                       width = 10)

port_range.place(relx = 0.2,rely = 0.5,anchor = "center")
#---------------------------------------------------------------------------------------------

port_1024 = tk.Button(text = "1 -> 1024",
                      fg="black",
                      bg = "#20C20E",
                      command = set_1024,
                      height = 1,
                      width = 10,
                      font = ("Segoe",15))

port_1024.place(relx = 0.2,rely = 0.6 , anchor = "center")

#---------------------------------------------------------------------------------------------

port_common = tk.Button(bg = "#20C20E",
                        fg = "black",
                        width = 10,
                        height = 1,
                        font = ("Segoe",15),
                        command = set_common,
                        text = "Top 100")

port_common.place(relx = 0.2,rely = 0.7,anchor = "center")

#----------------------------------------------------------------------------------------------
begin_scan = tk.Button(window,
                       text = "Begin Scan",
                       fg = "black",
                       bg = "#20C20E",
                       font = ("Segoe",30),
                       width = 45,
                       height = 2,
                       command = scan)

begin_scan.place(relx = 0.5,rely = 0.9 , anchor = "center")

#-----------------------------------------------------------------------------------------------
window.mainloop()
