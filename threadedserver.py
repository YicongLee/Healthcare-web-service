import socket
import threading
import sys
import mysql.connector
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography import utils
import os
def random_serial_number():
    return utils.int_from_bytes(os.urandom(20), "big") >> 1

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            
            client, address = self.sock.accept()
            print >>sys.stderr, 'connection from', address
            client.settimeout(300)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        
        try:
            cert_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Amherst"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Group5"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"healthcareprj"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
                # Sign our certificate with our private key
            ).sign(cert_private_key, hashes.SHA256(), default_backend())
            cert_pem = cert.public_bytes(
                encoding=serialization.Encoding.PEM)
            # sending server certificate
            client.send(cert_pem)
            # receive session key
            encrypted_session_key = client.recv(2048)
            
            session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
             )
            )

            f = Fernet(session_key)
        
            patient_login = dict()
            patient_login['1'] = 111
            patient_login['2'] = 111
            patient_login['3'] = 111
            patient_login['4'] = 111
            patient_login['5'] = 111
            patient_login['6'] = 111
            patient_login['7'] = 111
            patient_login['8'] = 111
            patient_login['9'] = 111
            patient_login['10'] = 111
            patient_login['11'] = 111
            patient_login['12'] = 111
            patient_login['13'] = 111
            patient_login['14'] = 111
            patient_login['15'] = 111


            
            while True:
                try:
                    whole_message = str()
                    size = 2048
                    while True:
                        data = client.recv(size)
                        if len(data) == size :
                            print >>sys.stderr, 'received "%s"' % data
                            whole_message = whole_message + data
                        
                        elif len(data) < size: 
                            print >>sys.stderr, 'received "%s"' % data 
                            whole_message = whole_message + data
                            break                 
                        
                except:
                    client.close()
                    return False
            
                plaintext = f.decrypt(whole_message)
                print >>sys.stderr, 'decrypt to "%s"' % plaintext
                plaintext_ = plaintext.split('-')
                login_name = plaintext_[0]
                login_password = plaintext_[1]
                print 'username is',login_name
                print 'password is',login_password
                try:
                    if patient_login[login_name] == int(login_password) :

                        conn = mysql.connector.connect(host="localhost", user="patient", passwd="patientpassword", db="mytest")
                        cur = conn.cursor()
                        conn.commit()
                        print 'Login successfully'
                        message = f.encrypt('login successfully')
                        client.send(message)
                        role = 1
                        break

                    else:

                        print 'Password is wrong!'
                        message = f.encrypt('Password error!')
                        client.send(message)
                except:
                    try:
                        conn = mysql.connector.connect(host="localhost", user=login_name, passwd=login_password,
                                                       db="mytest")
                        cur = conn.cursor()
                        conn.commit()
                        print 'Login successfully'
                        message = f.encrypt('login successfully')
                        client.send(message)
                        role = 0
                        break
                    except:
                        print 'Username or password is wrong!'
                        message = f.encrypt('Username or password is wrong!')
                        client.send(message)

            if  role == 0 :

                while True:
                    en_patient_id = client.recv(256)
                    patient_id = f.decrypt(en_patient_id)

                    try:
                        sql = ("SELECT * FROM patients_info WHERE ID = '%s'") % patient_id
                        cur.execute(sql)
                        id = cur.fetchone()[0]
                        conn.commit
                        print id

                        print 'find selected patient ID'
                        id_result = 'correct'
                        en_id_result = f.encrypt(id_result)
                        client.send(en_id_result)
                        break
                    except:
                        id_result = 'wrong number! Please enter again.'
                        print 'wrong number!'
                        en_id_result = f.encrypt(id_result)

                        client.send(en_id_result)

                cur.execute(sql)

                for data in cur.fetchone():
                    patient_data = str(data)
                    en_patient_data = f.encrypt(patient_data)
                    print patient_data
                    print en_patient_data
                    client.send(en_patient_data)

                en_remark = client.recv(2048)
                remark = f.decrypt(en_remark)
                cur.execute("""UPDATE patients_info SET remarks=%s WHERE ID= %s""", (remark, patient_id))
            
                conn.commit()
                cur.close()
                conn.close()
            if role == 1 :

                sql = ("SELECT * FROM patients_info WHERE ID = '%s'") % login_name
                cur.execute(sql)

                for data in cur.fetchone():
                    patient_data = str(data)
                    en_patient_data = f.encrypt(patient_data)
                    print patient_data
                    print en_patient_data
                    client.send(en_patient_data)


                conn.commit()
                cur.close()
                conn.close()
        except:
            print ' Timeout!'
            client.send('timeout')
            client.close
            
        
    
if __name__ == "__main__":
    ThreadedServer('localhost',10000).listen()
