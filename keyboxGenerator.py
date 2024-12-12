import os
try:
	os.chdir(os.path.abspath(os.path.dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)
keyboxFormatter = """<?xml version="1.0"?>
<AndroidAttestation>
<NumberOfKeyboxes>1</NumberOfKeyboxes>
<Keybox DeviceID="YourDeviceID">
<Key algorithm="ecdsa">
<PrivateKey format="pem">
{0}</PrivateKey>
<CertificateChain>
<NumberOfCertificates>1</NumberOfCertificates>
<Certificate format="pem">
{1}</Certificate>
</CertificateChain>
</Key>
<Key algorithm="rsa">
<PrivateKey format="pem">
{2}</PrivateKey>
</Key>
</Keybox>
</AndroidAttestation>"""


def execute(commandline:str) -> int|None:
	if isinstance(commandline, str):
		print("$ " + commandline)
		return os.system(commandline)
	else:
		return None

def handleOpenSSL(flag:bool = True) -> bool|None:
	if isinstance(flag, bool):
		errorLevel = execute("openssl version")
		if EXIT_SUCCESS == errorLevel:
			return True
		elif flag: # can try again
			execute("sudo apt-get install openssl libssl-dev")
			return handleOpenSSL(False)
		else:
			return False
	else:
		return None

def pressTheEnterKeyToExit(errorLevel:int|None = None):
	try:
		print("Please press the enter key to exit ({0}). ".format(errorLevel) if isinstance(errorLevel, int) else "Please press the enter key to exit. ")
		input()
	except:
		pass

def main() -> int:
	# Parameters #
	failureCount = 0
	ecPrivateKeyFilePath = "ecPrivateKey.pem"
	certificateFilePath = "certificate.pem"
	rsaPrivateKeyFilePath = "rsaPrivateKey.pem"
	oldRsaPrivateKeyFilePath = "oldRsaPrivateKey.pem"
	keyboxFilePath = "keybox.xml"
	
	# First-phase Generation #
	failureCount += execute("openssl ecparam -name prime256v1 -genkey -noout -out \"{0}\"".format(ecPrivateKeyFilePath)) != 0
	failureCount += execute("openssl req -new -x509 -key \"{0}\" -out {1} -days 3650 -subj \"/CN=Keybox\"".format(ecPrivateKeyFilePath, certificateFilePath)) != 0
	failureCount += execute("openssl genrsa -out \"{0}\" 2048".format(rsaPrivateKeyFilePath)) != 0
	if failureCount > 0:
		print("Cannot generate a sample ``keybox.xml`` file since {0} PEM file{1} not generated successfully. ".format(failureCount, ("s were" if failureCount > 1 else " was")))
		pressTheEnterKeyToExit(EOF)
		return EOF
	
	# First-phase Reading #
	try:
		with open(ecPrivateKeyFilePath, "r", encoding = "utf-8") as f:
			ecPrivateKey = f.read()
		with open(certificateFilePath, "r", encoding = "utf-8") as f:
			certificate = f.read()
		with open(rsaPrivateKeyFilePath, "r", encoding = "utf-8") as f:
			rsaPrivateKey = f.read()
	except BaseException as e:
		print("Failed to read one or more of the PEM files. Details are as follows. \n{0}".format(e))
		pressTheEnterKeyToExit(EOF)
		return EOF
	
	# Second-phase Generation #
	if rsaPrivateKey.startswith("-----BEGIN PRIVATE KEY-----"):
		print("A newer openssl version is used. The RSA private key in the PKCS8 format will be converted to that in the PKCS1 format soon. ")
		failureCount += execute("openssl rsa -in \"{0}\" -out \"{1}\" -traditional".format(rsaPrivateKeyFilePath, oldRsaPrivateKeyFilePath))
		if failureCount > 0:
			print("Cannot convert the RSA private key in the PKCS8 format to that in the PKCS1 format. ")
			pressTheEnterKeyToExit(EOF)
			return EOF
		else:
			print("Finished converting the RSA private key in the PKCS8 format to that in the PKCS1 format. ")
			try:
				with open(oldRsaPrivateKeyFilePath, "r", encoding = "utf-8") as f:
					rsaPrivateKey = f.read()
			except BaseException as e:
				print("Failed to update the RSA private key from \"{0}\". Details are as follows. \n{1}".format(oldRsaPrivateKeyFilePath, e))
				pressTheEnterKeyToExit(EOF)
				return EOF
	
	# Keybox Generation #
	keybox = keyboxFormatter.format(ecPrivateKey, certificate, rsaPrivateKey)
	print(keybox)
	try:
		with open(keyboxFilePath, "w", encoding = "utf-8") as f:
			f.write(keybox)
		print("Successfully wrote the keybox to \"{0}\". ".format(keyboxFilePath))
		pressTheEnterKeyToExit(EXIT_SUCCESS)
		return EXIT_SUCCESS
	except BaseException as e:
		print("Failed to write the keybox to \"{0}\". Details are as follows. \n{1}".format(keyboxFilePath, e))
		pressTheEnterKeyToExit(EXIT_FAILURE)
		return EXIT_FAILURE



if "__main__" == __name__:
	exit(main())