import socket
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import Tkinter as tk
import tkMessageBox
from cryptography import x509
from cryptography.x509.oid import NameOID

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print >> sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)

session_key = Fernet.generate_key()
# receiving certificate from server
cert_pem = sock.recv(2048)
certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
cer = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
host_name = cer[0].value
if host_name == 'healthcareprj':
    server_public_key = certificate.public_key()
    encrypted_session_key = server_public_key.encrypt(session_key,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))

    sock.send(encrypted_session_key)
else:
    print
    tkMessageBox.showinfo(title='Error', message='The certificate is untrusted!')
    sock.close()
try:

    f = Fernet(session_key)
    window = tk.Tk()
    window.title('Welcome to healthcare service system')
    window.geometry('450x300')


    # user information
    tk.Label(window, text='User name(ID Number): ').place(x=30, y=150)
    tk.Label(window, text='Password: ').place(x=30, y=190)

    var_usr_name = tk.StringVar()
    var_usr_name.set('')
    entry_usr_name = tk.Entry(window, textvariable=var_usr_name)
    entry_usr_name.place(x=190, y=150)
    var_usr_pwd = tk.StringVar()
    entry_usr_pwd = tk.Entry(window, textvariable=var_usr_pwd, show='*')
    entry_usr_pwd.place(x=190, y=190)


    def usr_login():
        usr_name = var_usr_name.get()
        usr_pwd = var_usr_pwd.get()
        usr_name_ = usr_name + '-'
        message = usr_name_ + usr_pwd
        print message
        token = f.encrypt(message)
        encrypted_message = token
        print >> sys.stderr, 'sending "%s"' % encrypted_message
        sock.sendall(encrypted_message)

        data = sock.recv(256)
        if data == 'timeout':
            print 'connection timeout!'
            tkMessageBox.showinfo(title='Error', message='Timeout!')
        plain = f.decrypt(data)
        print 'receive: ', data

        if plain != 'login successfully':

            tkMessageBox.showerror(message='Error, your username or password is wrong!')
        else:

            patients_data = list()
            while True:
                size = 1024
                en_patient_data = sock.recv(size)
                print 'receving en_info: ', en_patient_data
                patient_data = f.decrypt(en_patient_data)
                print 'info is: ', patient_data
                patients_data.append(patient_data)
                if len(patients_data) == 9: break
            window_data = tk.Tk()
            window_data.title('patient information')
            window_data.geometry('400x300')
            tk.Label(window_data, text='ID: ').place(x=10, y=10)
            tk.Label(window_data, text='Fname: ').place(x=10, y=40)
            tk.Label(window_data, text='Lname: ').place(x=10, y=70)
            tk.Label(window_data, text='sex: ').place(x=10, y=100)
            tk.Label(window_data, text='age: ').place(x=10, y=130)
            tk.Label(window_data, text='tel.: ').place(x=10, y=160)
            tk.Label(window_data, text='Blood type: ').place(x=10, y=190)
            tk.Label(window_data, text='Allergen: ').place(x=10, y=220)
            tk.Label(window_data, text='Remark: ').place(x=10, y=250)

            tk.Label(window_data, text=patients_data[0]).place(x=100, y=10)
            tk.Label(window_data, text=patients_data[1]).place(x=100, y=40)
            tk.Label(window_data, text=patients_data[2]).place(x=100, y=70)
            tk.Label(window_data, text=patients_data[3]).place(x=100, y=100)
            tk.Label(window_data, text=patients_data[4]).place(x=100, y=130)
            tk.Label(window_data, text=patients_data[5]).place(x=100, y=160)
            tk.Label(window_data, text=patients_data[6]).place(x=100, y=190)
            tk.Label(window_data, text=patients_data[7]).place(x=100, y=220)
            tk.Label(window_data, text=patients_data[8]).place(x=100, y=250)
            window_data.mainloop()

    btn_login = tk.Button(window, text='Login', command=usr_login)
    btn_login.place(x=200, y=230)

    window.mainloop()
    sock.close()


except:
    print 'Disconnect to server! '
