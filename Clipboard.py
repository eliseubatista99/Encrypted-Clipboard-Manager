import pyaes, pbkdf2, os,  secrets, binascii, numpy as np,time
from subprocess import *
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA512
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
import rsa
from Crypto.PublicKey import RSA
import pyperclip
from hashlib import sha512
from Crypto import Random
from Crypto.Cipher import AES
import base64
from struct import pack
from tkinter import *
from Crypto.PublicKey import RSA
from PyQt5 import QtWidgets, uic
import tkinter as tk
from threading import Thread
import sys
from PyQt5.Qt import QApplication, QClipboard
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QWidget, QPlainTextEdit, QListWidget, QMessageBox
from PyQt5.QtCore import QSize
from Crypto.Util.Padding import pad,unpad


username   = ""
password   = ""
master_key = b''
iv = b''
flag = 0
path = os.getcwd()

# Interface Inicial -------------------------------------------------------------------

def mainInterface():

	global main
	
	main = Tk()
	main.geometry("350x250")
	main.title("Clipboard Manager")
	
	Label(text="Login & Register", bg="green", width="300", height="2", font=("Calibri", 13)).pack()
	Label(text="").pack()

    # Login
	Button(text="Login", height="2", width="30", command=loginInterface).pack()
    
	Label(text="").pack()
    
    # Register
	Button(text="Register", height="2", width="30", command=registerInterface).pack()
    
	Label(text="").pack()

	Button(text="Help", height="1", width="10", command=help0).pack()

	main.mainloop()

# -------------------------------------------------------------------------------------


def help0():

	app1=QtWidgets.QApplication([])
	dlg0 = uic.loadUi("Inicial.ui")
	dlg0.show()
	app1.exec()

def help1():

	app1=QtWidgets.QApplication([])
	dlg0 = uic.loadUi("Login.ui")
	dlg0.show()
	app1.exec()

def help2():

	app1=QtWidgets.QApplication([])
	dlg0 = uic.loadUi("Registo.ui")
	dlg0.show()
	app1.exec()

# Interface Login ---------------------------------------------------------------------

def loginInterface():

	global login, username, password, master_key, editT_username, editT_password

	login = Toplevel(main)
	login.title("Login")
	login.geometry("350x250")

	Label(login, text="Enter the details below to login", bg="green").pack()
	Label(login, text="").pack()

	editT_username = StringVar()
	editT_password = StringVar()
	
	Label(login, text="Username").pack()
	tView_username = Entry(login, textvariable=editT_username)
	tView_username.pack()

	Label(login, text="").pack()
	Label(login, text="Password").pack()

	tView_password = Entry(login, textvariable=editT_password, show="*")
	tView_password.pack()

	Label(login, text="").pack()
	Button(login, text="Sign in", width=10, height=1, bg="green", command=test).pack()

	Label(login, text="").pack()

	Button(login, text="Help", height="1", width="10", command=help1).pack()
# ----------------------------------------------------------------------------------------------------

def hash512(x):
    hash_object = hashlib.sha512(x.encode('latin-1'))
    hex_dig = hash_object.hexdigest()
    return hex_dig

# ---------------------------------------------------------------------------------------------------


def putInFiles(clipboard):

	global username, master_key, iv,path

	f_hist = open(path+"/" + username + "/" + username+"_history.cipher","a+")
	f_hash = open(path+"/" + username + "/" + username+"_history_hash.sha512","a+")
	f_sign = open(path+"/" + username + "/" + username+"_sign.sig","rb")
	f_pkey = open(path+"/" + username + "/" + username+"_public.pem","rb")

	signature  = f_sign.read()
	public_key = RSA.importKey(f_pkey.read())
	f_sign.close()

	exact_time = time.asctime(time.localtime(time.time()))

	clipboard_ciph = binascii.hexlify(encrypt_AES_256Files(clipboard.encode('latin-1'))).decode('latin-1')

	mix = exact_time + ':' + clipboard_ciph

	if verify(path+"/" + username + "/" + username+"_history.cipher", signature, public_key):
		f_hist.writelines(mix+'\n')
		f_hash.writelines(hash512(mix+'\n')+'\n')
		f_sign = open(path+"/" + username + "/" + username+"_sign.sig","wb")
		f_privkey = open(path+"/" + username + "/" + username+"_private.pem","rb")

		f_hash.close()
		f_hist.close()

		priv_key = RSA.importKey(f_privkey.read())

		new_signature = sign(path+"/" + username + "/" + username+"_history.cipher",priv_key)
		f_sign.write(new_signature)


		f_sign.close()
		f_privkey.close()
		


		return mix+'\n'

	else:

		return 

def setHistoryOnWidgetList(listWidget):

	global username,path

	listWidget.clear()

	f = open(path+"/" + username + "/" + username+'_history.cipher','r')

	line = f.readlines()

	for i in line:
		listWidget.addItem(i)

	f.close()

# sucesso login --------------------------------------------------------------------------------------------
class ExampleWindows(QtWidgets.QMainWindow):
	
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		dlg = uic.loadUi("historyapp.ui",self)

		setHistoryOnWidgetList(dlg.listWidget)
		QApplication.clipboard().dataChanged.connect(self.clipboardChanged)
		#self.checkBox.toggled.connect(self.working)
		self.listWidget.itemDoubleClicked.connect(self.decrypt_function_UI)
		
	def decrypt_function_UI(self):

		global username,path

		index = [x.row() for x in self.listWidget.selectedIndexes()][0]

		f_ciph = open(path+"/" + username + "/" + username+'_history.cipher','r')
		f_hash = open(path+"/" + username + "/" + username+'_history_hash.sha512','r')

		lines_ciph = f_ciph.readlines() 
		lines_hash = f_hash.readlines()


		if hash512(lines_ciph[index])[:128] == lines_hash[index][:128]:
			
			sel_item = self.listWidget.selectedItems()
			for item in sel_item:
				cipher_txt = lines_ciph[index][25:(len(lines_ciph[index])-1)]
				
				binary_cipher_txt = binascii.unhexlify((cipher_txt.encode('latin-1')))
				
				padding_txt = decrypt_AES_256_login(binary_cipher_txt)
				item.setText(padding_txt)
				


		f_ciph.close()
		f_hash.close()

	def clipboardChanged(self):
	    
	    global username

	    text = QApplication.clipboard().text()
	    cript = putInFiles(text)
	    self.listWidget.addItem(cript)
	    self.listWidget.update()

	


# falha login ----------------------------------------------------------------------------------------------
def wrong_login():
    
	global wrong_login_screen
    
	wrong_login_screen=Toplevel(login)
	wrong_login_screen.title("Erro no login")
	wrong_login_screen.geometry("150x100")
    
	Label(wrong_login_screen, text="Erro no login").pack()
	
	Button(wrong_login_screen, text="OK",bg="green",command=delete_login).pack()


def delete_login():
	
	wrong_login_screen.destroy()

# ----------------------------------------------------------------------------------------------------------

def test():

	global username, password

	username = editT_username.get()
	password = editT_password.get()

	if not dataValidation(0):
		app = QtWidgets.QApplication(sys.argv)
		MainWin = ExampleWindows()
		MainWin.show()
		sys.exit(app.exec_())
	else:
		wrong_login()


# Interface Register -----------------------------------------------------------------

def registerInterface():

	global register, username, password, master_key, editT_username, editT_password

	register = Toplevel(main)
	register.title("Register")
	register.geometry("350x250")

	editT_username = StringVar()
	editT_password = StringVar()

	Label(register, text="Please enter details below", bg="green").pack()
	Label(register, text="").pack()

	tView_username = Label(register, text="Username")
	tView_username.pack()
    
	input_username = Entry(register, textvariable=editT_username)
	input_username.pack()
    
	tView_password = Label(register, text="Password")
	tView_password.pack()

	input_password = Entry(register, textvariable=editT_password, show='*')
	input_password.pack()

	Label(register, text="").pack()
	Button(register, text="Sign up", width=10, height=1, bg="green", command=main_register).pack()

	Label(register, text="").pack()

	Button(register, text="Help", height="1", width="10", command=help2).pack()


# --------------------------------------------------------------------------------------

# if the register fails, we move on to this function
def register_fail():

    
	global register_fail_screen

	register_fail_screen = Toplevel(register)
	register_fail_screen.title("Falha no registo")
	register_fail_screen.geometry("200x100")
    
	Label(register_fail_screen, text="Username ja utilizado", bg="red").pack()
	Button(register_fail_screen, text="OK",bg="red" ,command=delete_register_fail).pack()

# --------------------------------------------------------------------------------------

# we delete the view of register fail
def delete_register_fail():
	register_fail_screen.destroy()

# --------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------

def register_sucess():

	global register_success_screen

	register_success_screen = Toplevel(register)
	register_success_screen.title("Success")
	register_success_screen.geometry("200x100")
    
	Label(register_success_screen, text="Register Success", bg="green").pack()
	Button(register_success_screen, text="OK",bg="green" ,command=delete_register_success).pack()

# --------------------------------------------------------------------------------------

def delete_register_success():

	register_success_screen.destroy()

# --------------------------------------------------------------------------------------

def generator_key():

	global password

	passwordSalt = os.urandom(16)

	f = open("saltkeys.txt","r+")

	line = f.readline()

	while(len(line) > 0):
		if f.readline() == binascii.hexlify(passwordSalt).decode('latin-1'):
			generator_key()
		line = f.readline()

	key = pbkdf2.PBKDF2(password, passwordSalt).read(16)

	s = passwordSalt
	f.writelines((binascii.hexlify(passwordSalt).decode('latin-1'))+"\n")

	return key

# --------------------------------------------------------------------------------------

def encrypt_AES_256(message, message2):

	global master_key, iv

	iv = Random.new().read(16)
	aes = AES.new(master_key, AES.MODE_CBC, iv)
	return aes.encrypt(pad(message,16)),aes.encrypt(pad(message2,16))

def encrypt_AES_256Files(message):

	global master_key,iv

	aes = AES.new(master_key, AES.MODE_CBC, iv)
	return aes.encrypt(pad(message,16))

def decrypt_AES_256(crypto, crypto2):

	global master_key,iv

	aes = AES.new(master_key, AES.MODE_CBC, iv)
	decd = aes.decrypt(crypto)
	decd2 = aes.decrypt(crypto2)
	return decd,decd2

def decrypt_AES_256_login(crypto):

	global master_key, iv

	aes = AES.new(master_key, AES.MODE_CBC, iv)
	decd = unpad(aes.decrypt(crypto),16)
	return decd.decode('latin-1')

def decrypt_AES_256(crypto, crypto2):

	global master_key, iv

	aes = AES.new(master_key, AES.MODE_CBC, iv)
	decd = unpad(aes.decrypt(crypto),16)
	decd2 = unpad(aes.decrypt(crypto2),16)
	return decd.decode('latin-1'),decd2.decode('latin-1')

# --------------------------------------------------------------------------------------

# Add padding to a certain string.

def get_near_multiple_aux(value):

	c = 16
	while(True):
		if c > value:
			return c
		else:
			c = c + 16

def getNearMultiple(message):

	if len(message)%16 == 0:
		return message
	else:
		new_username = message
		for i in range(get_near_multiple_aux(len(new_username))-len(message)):
			new_username = new_username + '*'
		return new_username

# -------------------------------------------------------------------------------------

#verify a signature
def verify(file_name, signature, pub_key):

	f = open(file_name,"r")
	message = f.read()
	signer = PKCS1_v1_5.new(pub_key)
	digest = SHA512.new()
	digest.update(message.encode('latin-1'))
	f.close()
	return signer.verify(digest, signature)

#sign a file!
def sign(file_name, priv_key):

	f = open(file_name,'r')
	message = f.read()

	hash = "SHA-512"
	signer = PKCS1_v1_5.new(priv_key)
	digest = SHA512.new()
	digest.update(message.encode('latin-1'))
	f.close()
	return signer.sign(digest)


# key generator 2048bits size!
def newkeys():

	global username,path

	file_public  = open(path + "/" + username + "/" + username +'_public.pem',"wb")
	file_private = open(path + "/" + username + "/" + username +'_private.pem',"wb")


	random_generator = Random.new().read
	key = RSA.generate(2048, random_generator)
	private, public = key, key.publickey()



	file_public.write(public.exportKey("PEM"))
	file_private.write(private.exportKey("PEM"))

	file_public.close()
	file_private.close()

	return public, private



def registFullUser():

	global username, password, master_key, iv, path

	os.mkdir(username)

	# history file created.
	fb = open(   path + "/" + username + "/" + username +'_history.cipher',"w+")
	wb = open(   path + "/" + username + "/" + username +'_history_hash.sha512',"w+")
	
	fb.close()
	wb.close()

	pub_key,priv_key = newkeys()


	signature = sign(path + "/" + username + "/" + username +'_history.cipher',priv_key)

	sw = open(path+"/" + username + "/" + username +'_sign.sig',"wb")
	sw.write(signature)
	sw.close()

	#generate the master key
	#Bytes
	master_key = generator_key()
	#encrypt username and password, returning the iv (generated random)
	ciph_username, ciph_password = encrypt_AES_256(username.encode('latin-1'), password.encode('latin-1'))

	f = open('users.cipher','a')
	f.writelines(binascii.hexlify(ciph_username).decode('latin-1') + ',' + binascii.hexlify(ciph_password).decode('latin-1') + ',' + binascii.hexlify(master_key).decode('latin-1') + ',' + binascii.hexlify(iv).decode('latin-1') + '\n')
	f.close()

# --------------------------------------------------------------------------------------

# 1. Function that verifies if an user is in the users.cipher;
# 2. False -> is not in  |  True -> is in.


def dataValidation(flag):

	global username, passsword, master_key,iv


	f = open('users.cipher','r')
	lines = f.readlines()
	f.close()

	for x in lines:
		array = x.split(',')
		
		ciph_username = binascii.unhexlify((array[0]).encode('latin-1'))
		ciph_password = binascii.unhexlify((array[1]).encode('latin-1'))
		iv = binascii.unhexlify((array[3][:32]).encode('latin-1'))
		master_key = binascii.unhexlify((array[2]).encode('latin-1'))
		test_username,test_password = decrypt_AES_256(ciph_username, ciph_password)



		if test_username == username and flag == 1:
			return False
		elif test_username == username and flag != 1 and test_password == password:
			return False
	
	return True

# ----------------------------------------------------------------------------------------


def main_register():

	global username, password

	username = editT_username.get()
	password = editT_password.get()

	f = open('users.cipher','r')
	lines = f.readlines()

	# if the file has no users.
	# if the file has users, let's check...
	if len(lines) == 0 or dataValidation(1):
		# 1. This function creates the file history of this current user;
		# 2. Generates the master key of the user;
		# 3. Cipher the username and password;
		# 4. Introduce all of this items, and also the IV in the file.
		registFullUser()
		register_sucess()
	else:
		register_fail()


mainInterface()


