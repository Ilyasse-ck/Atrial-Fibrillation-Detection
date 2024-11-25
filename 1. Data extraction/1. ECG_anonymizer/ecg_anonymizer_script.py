import tkinter as tk
import os
from tkinter import filedialog
from encrypt import create_encrypted_xml, create_decrypted_xml, create_rectification_xml


def create_new_folder(folder, function, suffix):
    """
    If folder isn't empty, creates a new folder and create all the needed files
    :param folder: selected folder that contains the xml files to encrypt/decrypt
    :param function: encrypt_data or decrypt_data
    :param suffix: 'encrypted' or 'decrypted'
    :return: None
    """
    files = os.listdir(folder)
    if len(files) != 0:
        new_folder = folder + '_' + suffix
        os.mkdir(new_folder)
        for file in files:
            password = open('password.txt', 'r').read()
            file_path = folder + '/' + file
            fob = open(file_path, 'r')
            new_xml = function(fob.read(), new_folder, password)
            if new_xml:
                new_file_path = new_folder + '/' + suffix + '_' + file
                with open(new_file_path, "w") as f:
                    f.write(new_xml)
            else:
                os.rmdir(new_folder)
    return None


def open_files(window):
    """
    Displays the 3 buttons to encrypt or decrypt the selected folder.
    :param window:
    :return:
    """
    folder = filedialog.askdirectory()
    if folder:
        l1 = tk.Label(window, text=folder, foreground='red', font=('times', 10))
        l1.grid(row=3, column=1, pady=2)
        button_encrypt = tk.Button(window, text='Encrypter les fichiers',
                                   width=20,
                                   command=lambda: create_new_folder(folder, create_encrypted_xml, 'encrypted'))

        button_decrypt = tk.Button(window, text='Décrypter les fichiers',
                                   width=20,
                                   command=lambda: create_new_folder(folder, create_decrypted_xml, 'decrypted'))
        button_rectification = tk.Button(window, text='Rectification',
                                         width=20,
                                         command=lambda: create_new_folder(folder, create_rectification_xml,
                                                                           'rectifie'))
        button_decrypt.grid(row=5, column=1, pady=3)
        button_encrypt.grid(row=4, column=1, pady=5)
        button_rectification.grid(row=6, column=1, pady=5)
        explication = tk.Label(window, text='Rectification : décrypter les fichiers encryptés',
                               foreground='blue', font=('times', 7))
        explication.grid(row=7, column=1)
        explication2 = tk.Label(window, text='avec la v9 puis les encrypter avec la v11',
                                foreground='blue', font=('times', 7))
        explication2.grid(row=8, column=1)
        return None


def main():
    """
    Initialize the tkinter window with a button to select a folder.
    """
    my_w = tk.Tk()
    my_w.geometry("400x300")
    my_w.title('Anonymisation des ECG - version 11')
    l1 = tk.Label(my_w, text='Anonymisation d\'ECG', width=30, font=('times', 18, 'bold'))
    l1.grid(row=1, column=1)
    b1 = tk.Button(my_w, text='Sélectionner un dossier',
                   width=20, command=lambda: open_files(my_w))

    b1.grid(row=2, column=1)
    my_w.mainloop()
    return None


main()
