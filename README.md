# Atrial Fibrillation Detection Project

This project focuses on detecting atrial fibrillation (AF) using ECG data coming from raw XML files. The implementation is organized into four main directories, each serving a distinct purpose within the workflow, from data preparation to model training.

---

## Project Structure

### 1. **Data Processing**
This directory contains functions for handling the raw XML data files from Muse GE machines and preparing them for analysis.
- **`1. ECG_anonymizer/anonymizer_v11.exe`**: An executable file to anonymize the ECG data of patients, ensuring compliance with data privacy standards.
- **`2. ECG Muse decrypt/ECG_MUSE_DECRYPT.py`**: A function to decrypt the XML data files based on the work of A. Ricke.


### 2. **Training Data**
This directory contains the training and data set. The data is already prepared for any further inquries about the data preparation contact me at ilyassechaouki16@gmail.com.

### 3. **Model**
This directory houses the ResNet50 model architecture used for training. ResNet50 is chosen for its efficiency and identifying patterns indicative of atrial fibrillation.

### 4. **Spectrogram Conversion**
This directory contains the code to convert ECG signals into spectrograms. Spectrograms are a visual representation of the signal’s frequency content over time.

- **`Spectro function.ipynb`**: A notebook to transform ECG data into spectrograms suitable for input into the model.

---

## Workflow Overview
1. **Data Decryption and Anonymization**:
   - Use the scripts in the **Data Processing** directory to decrypt and anonymize raw ECG data files.

2. **Model Training**:
   - Utilize the prepared training data and the **ResNet50 Model** for training to classify atrial fibrillation.

3. **Spectrogram Generation**:
   - Run the **Spectrogram Conversion** scripts to transform the ECG data into spectrograms and train the **ResNet50 Model**.

---

## Requirements
- Python (version >= 3.8)
- TensorFlow / Keras
- NumPy
- Matplotlib (for spectrogram visualization)
- Any additional libraries are specified in `requirements.txt`.

---

## How to Run
1. Clone this repository.
2. Install the dependencies using:
   ```bash
   pip install -r requirements.txt
   ```
3. Follow the workflow steps described above.
4. Run the respective scripts as needed for each step.

---

## Credits
This project was developed as part of a study in analyzing and detecting atrial fibrillation using ECG data and machine learning models.
