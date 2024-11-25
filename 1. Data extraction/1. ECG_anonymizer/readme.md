ANONYMISATION DES ECG

Deux fichiers : 
- Interface en deux temps : 
  - Sélection d'un dossier
  - Trois boutons action :
    - Encrypter : pour anonymiser un dossier
    - Décrypter : pour décrypter un dossier anonymisé
    - Rectification : pour rectifier un dossier anonymisé avec la version 9 (sans pouvoir identifier les patients), et le ré encrypter avec la version 10.
  - Correspond au fichier ecg_anonymizer_script
    - 3 fonctions :
      - main(): Initialize the tkinter window with a button to select a folder.
      - open_files(window): Displays the 3 buttons to encrypt or decrypt the selected folder.
      - create_new_folder(folder, function, suffix): If folder isn't empty, creates a new folder and create all the encrypted or decrypted files corresponding.
- Anonymisation
  - On encrypte toutes les infos perso du patients et des médecins:
    - Id patient
    - Noms et prénoms
    - Date de naissance
    - Et on enlève les noms de médecins qui apparaissent dans les commentaires
    
  - Une fonction pour chaque boutton :
    - create_encrypted_xml(data, new_folder, password): Creates a new xml where the patient's ID, name and DOB have been encrypted as well as all the doctor's names.
    - create_decrypted_xml(data, new_folder, password): Creates a new xml where all the encrypted patient's info has been decrypted
    - create_rectification_xml(data, new_folder, password): Takes an xml that has been anonymized with v9 (can't track patient's history) decrypts it with the old decrypting function (v9) and re encrypts it with the newer encrypting function
  - Des fonctions auxiliaires d'encryption:
    - V9 et avant : l'encyption ne permettait pas de retracer l'historique des patients
      - encrypt_before(msg, password)
      - decrypt_before(msg, password)
    - V10 : Changement de méthode pour rectifier ce problème 
      - encrypt_aes(message, password)
      - decrypt_aes(encrypted_message, password)
    - V11 : Correction des bugs de la V10
      - create_encrypted_xml(data, new_folder, password): Modification de la lecture et de la modification de la case 'PatientDemographics'
      - create_decrypted_xml(data, new_folder, password): Modification de la lecture et de la modification de la case 'PatientDemographics'
      - create_rectification_xml(data, new_folder, password): Modification de la lecture et de la modification de la case 'PatientDemographics'
      - Création du nouveau executable: anonymizer_v11.exe
      - Mise à jour de l'interface graphique