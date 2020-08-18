import socket
import select
import errno
import tkinter
from threading import Thread
from tkinter import *
HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
my_username = input("Username: ")

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
client_socket.connect((IP, PORT))
# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
# client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)
# info="$"

def receive():
    try:
    # Now we want to loop over received msgs (there might be more than one) and print them
        # l=client_socket.recv(HEADER_LENGTH).decode('utf-8')
        # l=int(l)
        # for i in range(l-2):
        # msgs=client_socket.recv(1024).decode('utf-8')
        # msg_list.insert(tkinter.END,msgs)

        while True:

            # Receive our "header" containing username length, it's size is defined and constant
            username_header = client_socket.recv(HEADER_LENGTH)

            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                # print('Connection closed by the server')
                sys.exit()

            # Convert header to int value
            username_length = int(username_header.decode('utf-8').strip())

            # Receive and decode username
            username = client_socket.recv(username_length).decode('utf-8')

            # Now do the same for msg (as we received username, we received whole msg, there's no need to check if it has any length)
            msg_header = client_socket.recv(HEADER_LENGTH)
            msg_length = int(msg_header.decode('utf-8').strip())
            msg = client_socket.recv(msg_length).decode('utf-8')
            print('*** ', msg)
            if msg[0]=='$':
                msg.replace('$','')
                msg=username+msg
                msg_list.insert(tkinter.END,msg)
            else:
                msg=username+"-->"+msg
                msg_list.insert(tkinter.END,msg)
            # Print msg
            # print(f'{username} > {msg}')


    # except IOError as e:
    #     # This is normal on non blocking connections - when there are no incoming data error is going to be raised
    #     # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
    #     # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
    #     # If we got different error code - something happened
    #     if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
    #         # print('Reading error: {}'.format(str(e)))
    #         sys.exit()
    #     # We just did not receive anything

    except Exception as e:
        # Any other exception - something happened, exit
        # print('Reading error: '.format(str(e)))
        sys.exit()

def send(event=None):
    msg = my_msg.get()
    # msg="you"+":"+msg
    msg2=msg
    msg=msg.encode('utf-8')
    my_msg.set("")  # Clears input field.
    msg_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(msg_header + msg)
    msg2="you-->"+msg2
    msg_list.insert(tkinter.END,msg2)
    # msg="you"+":"+msg
    # msg_list.insert(tkinter.END,msg)
    # client_socket.send(bytes(msg, "utf8"))
    if msg =='bye':
        client_socket.close()
        top.quit()

# while True:
#     msg = input(f'{my_username} > ')
#     # Wait for user to input a msg
#     if msg:

#     # Encode msg to bytes, prepare header and convert to bytes, like for username above, then send
#         msg = msg.encode('utf-8')
#         msg_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
#         client_socket.send(msg_header + msg)


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("bye")
    send()

top = tkinter.Tk()
top.title("RSD-CHATBOX")
f="                                 Welcome to the Group"
b="type bye to close the connection"
msgs_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the msgs to be sent.
my_msg.set("Type your msgs here.")
scrollbar = tkinter.Scrollbar(msgs_frame)  # To navigate through past msgs.
# Following will contain the msgs.
msg_list = tkinter.Listbox(msgs_frame, height=15, width=50,bg="black",fg="white",font="bold",yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
msgs_frame.pack()
msg_list.insert(tkinter.END,f)
msg_list.insert(tkinter.END,b)

entry_field = tkinter.Entry(top, textvariable=my_msg,font=("Times", "15", "bold italic"),bg="grey",fg="black" )
entry_field.bind("<Return>", send)
entry_field.pack(side=LEFT,expand=True,fill=BOTH)
send_button = tkinter.Button(top, text="SEND",bg="green",fg="white",font="bold",activeforeground="blue", command=send)
send_button.pack(side=LEFT,expand=True,fill=BOTH)

# print("fff")

top.protocol("WM_DELETE_WINDOW", on_closing)

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()