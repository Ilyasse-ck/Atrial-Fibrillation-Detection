import xmltodict
import os
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


class AlreadyAnonymizedException(Exception):
    def __init__(self, msg="", *args, **kwargs):
        msg = msg or "Le fichier est déjà anonymisé et ne peut pas l'être à nouveau."
        super().__init__(msg, *args, **kwargs)


class NeverAnonymizedException(Exception):
    def __init__(self, msg="", *args, **kwargs):
        msg = msg or "Le fichier n'a jamais été anonymisé et ne peut donc pas être décrypté"
        super().__init__(msg, *args, **kwargs)


def encrypt_before(msg, password):
    """
    Function used in the v9 and before
    Main flaw : doesn't allow us to track a patient historic since
    it doesn't encrypt two same IDs the same way
    param pwd: password or passphrase (type: str)
    param msg: message to encrypt (type: str or bytes)
    return: base64 encoded encrypted message
    """
    salt = b'\xf3\x90\x1dWU\xe3\xd6\xc0'
    msg = msg.encode()
    key = PBKDF2(password, salt, 32)
    key = base64.urlsafe_b64encode(key)
    cipher = AES.new(key[:32], AES.MODE_EAX)
    nonce = cipher.nonce
    e, tag = cipher.encrypt_and_digest(msg)
    r = tag + nonce + e
    return str(base64.b64encode(r), 'utf-8')


def decrypt_before(msg, password):
    """
    Function used in the v9 and before
    Main flaw : doesn't allow us to track a patient historic since
    it doesn't encrypt two same IDs the same way
    param msg: message to uncrypt (type: bytes)
    return: uncrypted decoded message (str)
    """
    salt = b'\xf3\x90\x1dWU\xe3\xd6\xc0'
    msg = base64.b64decode(msg)
    tag = msg[:16]
    nonce = msg[16:32]
    e = msg[32:]
    key = PBKDF2(password, salt, 32)
    key = base64.urlsafe_b64encode(key)
    cipher = AES.new(key[:32], AES.MODE_EAX, nonce=nonce)
    d = cipher.decrypt(e)
    cipher.verify(tag)
    return d.decode()


def encrypt_aes(message, password):
    """
    New encrypting function, used in v10
    Encrypts a message with the given password.
    Encrypts two similar IDs the same way to allow us to track a patient's history.
    :param message: message to encrypt (type: str)
    :param password: password or passphrase (type: str)
    :return: base64 encoded encrypted message (str)
    """
    padded_message = message + (16 - len(message) % 16) * chr(16 - len(message) % 16)
    password_bytes = password.encode()
    password_bytes = password_bytes + (32 - len(password_bytes)) * b'\x00'
    password_bytes = password_bytes[:32]
    # On crée le vecteur d'initialisation avec une valeur constante
    iv = b'This is an IV456'
    # On crée un objet AES en mode CBC
    aes = AES.new(password_bytes, AES.MODE_CBC, iv)
    # On encrypte le message
    encrypted_message = aes.encrypt(padded_message.encode('ISO-8859-1'))
    return str(base64.b64encode(encrypted_message), 'ISO-8859-1')


def decrypt_aes(encrypted_message, password):
    """
    New decrypting function, used in v10
    Decrypts a message with the given password.
    :param encrypted_message: base64 encoded message to decrypt (type: str)
    :param password: password or passphrase (type: str)
    :return: decrypted decoded message (str)
    """
    encrypted_message = base64.b64decode(encrypted_message)
    # On vérifie que la longueur de la clé est de 16 bytes (128 bits)
    password_bytes = password.encode()
    password_bytes = password_bytes + (32 - len(password_bytes)) * b'\x00'
    password_bytes = password_bytes[:32]
    # On crée le vecteur d'initialisation avec la même valeur constante utilisée pour l'encryptage
    iv = b'This is an IV456'
    # On crée un objet AES en mode CBC
    aes = AES.new(password_bytes, AES.MODE_CBC, iv)
    # On décrypte le message encrypté en enlevant le padding
    decrypted_message = aes.decrypt(encrypted_message).decode('ISO-8859-1')
    padding_length = ord(decrypted_message[-1])
    decrypted_message = decrypted_message[:-padding_length]
    return decrypted_message


def create_encrypted_xml(data, new_folder, password):
    """
    Creates a new xml where the patient's ID, name and DOB have been encrypted
    as well as all the doctor's names.
    :param data: original xml.
    :param new_folder: created folder where we'll put the anonymized files.
    :param password: (str)
    :return: new anonymized xml
    """

    if '!DOCTYPE RestingECG SYSTEM "restecg.dtd"' not in data:
        # This first line is in the real xml files that come from the ECG but not in the encrypted ones.
        # We'll use it to determine if a file has already been anonymized or not.
        # If it is not present, it means the file has already been anonymized.
        os.rmdir(new_folder)
        raise AlreadyAnonymizedException()
    else:
        dict_data = xmltodict.parse(data)
        if 'PatientDemographics' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['PatientDemographics']:
                if 'LastName' in key or 'FirstName' in key or 'DateofBirth' in key or 'PatientID' in key:
                    dict_data['RestingECG']['PatientDemographics'][key] = \
                        encrypt_aes(str(dict_data['RestingECG']['PatientDemographics'][key]), password)

        if 'Order' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['Order']:
                if 'LastName' in key or 'FirstName' in key:
                    dict_data['RestingECG']['Order'][key] = \
                        encrypt_aes(str(dict_data['RestingECG']['Order'][key]), password)
        if 'TestDemographics' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['TestDemographics']:
                if 'LastName' in key or 'FirstName' in key:
                    dict_data['RestingECG']['TestDemographics'][key] = \
                        encrypt_aes(str(dict_data['RestingECG']['TestDemographics'][key]), password)
        if 'Diagnosis' in dict_data['RestingECG'] and 'DiagnosisStatement' in dict_data['RestingECG']['Diagnosis']:
            if type(dict_data['RestingECG']['Diagnosis']['DiagnosisStatement']) == list:
                for statement in dict_data['RestingECG']['Diagnosis']['DiagnosisStatement']:
                    if 'StmtText' in statement and statement['StmtText'] is not None and \
                            ('ValidÃ© par' in statement['StmtText'] or 'Validï¿½ par' in statement['StmtText'] or
                             ('valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                             ('Valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                             ('Dr' in statement['StmtText']) or ('dr' in statement['StmtText']) or
                             ('DR' in statement['StmtText'])):
                        statement['StmtText'] = 'Validé par le cardiologue'
            else:
                statement = dict_data['RestingECG']['Diagnosis']['DiagnosisStatement']
                if 'StmtText' in statement and statement['StmtText'] is not None and \
                        ('ValidÃ© par' in statement['StmtText'] or 'Validï¿½ par' in statement['StmtText'] or
                         ('valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                         ('Valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                         ('Dr' in statement['StmtText']) or ('dr' in statement['StmtText']) or
                         ('DR' in statement['StmtText'])):
                    statement['StmtText'] = 'Validé par le cardiologue'
        return xmltodict.unparse(dict_data, pretty=True)


def create_decrypted_xml(data, new_folder, password):
    """
    Creates a new xml where all the encrypted patient's info has been decrypted
    :param password: (str)
    :param data: anonymized xml
    :param new_folder: created folder where we'll put the decrypted files
    :return: new decrypted xml
    """

    if '!DOCTYPE RestingECG SYSTEM "restecg.dtd"' in data:
        # This first line is in the real xml files that come from the ECG but not in the encrypted ones.
        # We'll use it to determine if a file has already been anonymized or not.
        # If it is present, it means the file has not been anonymized, and we can't decrypt it.
        os.rmdir(new_folder)
        raise NeverAnonymizedException()
    else:
        dict_data = xmltodict.parse(data)
        if 'PatientDemographics' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['PatientDemographics']:
                if 'LastName' in key or 'FirstName' in key or 'DateofBirth' in key or 'PatientID' in key:
                    dict_data['RestingECG']['PatientDemographics'][key] = \
                        decrypt_aes(dict_data['RestingECG']['PatientDemographics'][key], password)

        if 'Order' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['Order']:
                if 'LastName' in key or 'FirstName' in key:
                    dict_data['RestingECG']['Order'][key] = \
                        decrypt_aes(dict_data['RestingECG']['Order'][key], password)
        if 'TestDemographics' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['TestDemographics']:
                if 'LastName' in key or 'FirstName' in key:
                    dict_data['RestingECG']['TestDemographics'][key] = \
                        decrypt_aes(dict_data['RestingECG']['TestDemographics'][key], password)
        return xmltodict.unparse(dict_data, pretty=True)


def create_rectification_xml(data, new_folder, password):
    """
    Takes an xml that has been anonymized with v9 (can't track patient's history)
    decrypts it with the old decrypting function (v9)
    and re encrypts it with the newer encrypting function
    :param password: (str)
    :param data: xml that has been anonymized with v9
    :param new_folder: created folder where we'll put the decrypted files
    :return: new properly encrypted xml
    """
    if '!DOCTYPE RestingECG SYSTEM "restecg.dtd"' in data:
        # This first line is in the real xml files that come from the ECG but not in the encrypted ones.
        # We'll use it to determine if a file has already been anonymized or not.
        # If it is present, it means the file has not been anonymized, and we can't decrypt it.
        os.rmdir(new_folder)
        raise NeverAnonymizedException()
    else:
        dict_data = xmltodict.parse(data)
        if 'PatientDemographics' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['PatientDemographics']:
                if 'LastName' in key or 'FirstName' in key or 'DateofBirth' in key or 'PatientID' in key:
                    dict_data['RestingECG']['PatientDemographics'][key] = \
                        encrypt_aes(decrypt_before(dict_data['RestingECG']['PatientDemographics'][key], password), password)

        if 'Order' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['Order']:
                if 'LastName' in key or 'FirstName' in key:
                    dict_data['RestingECG']['Order'][key] = \
                        encrypt_aes(decrypt_before(dict_data['RestingECG']['Order'][key], password), password)
        if 'TestDemographics' in dict_data['RestingECG']:
            for key in dict_data['RestingECG']['TestDemographics']:
                if 'LastName' in key or 'FirstName' in key:
                    dict_data['RestingECG']['TestDemographics'][key] = \
                        encrypt_aes(decrypt_before(dict_data['RestingECG']['TestDemographics'][key], password),
                                    password)
        if 'Diagnosis' in dict_data['RestingECG'] and 'DiagnosisStatement' in dict_data['RestingECG']['Diagnosis']:
            if type(dict_data['RestingECG']['Diagnosis']['DiagnosisStatement']) == list:
                for statement in dict_data['RestingECG']['Diagnosis']['DiagnosisStatement']:
                    if 'StmtText' in statement and statement['StmtText'] is not None and \
                            ('ValidÃ© par' in statement['StmtText'] or 'Validï¿½ par' in statement['StmtText'] or
                             ('valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                             ('Valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                             ('Dr' in statement['StmtText']) or ('dr' in statement['StmtText']) or
                             ('DR' in statement['StmtText'])):
                        statement['StmtText'] = 'Validé par le cardiologue'
            else:
                statement = dict_data['RestingECG']['Diagnosis']['DiagnosisStatement']
                if 'StmtText' in statement and statement['StmtText'] is not None and \
                        ('ValidÃ© par' in statement['StmtText'] or 'Validï¿½ par' in statement['StmtText'] or
                         ('valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                         ('Valid' in statement['StmtText'] and ' par' in statement['StmtText']) or
                         ('Dr' in statement['StmtText']) or ('dr' in statement['StmtText']) or
                         ('DR' in statement['StmtText'])):
                    statement['StmtText'] = 'Validé par le cardiologue'
        return xmltodict.unparse(dict_data, pretty=True)
