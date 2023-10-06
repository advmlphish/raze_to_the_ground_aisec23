# Raze to the Ground: Query-Efficient Adversarial HTML Attacks on Machine-Learning Phishing Webpage Detectors (AISec '23)

This repository contains the source code of the paper _Raze to the Ground: Query-Efficient Adversarial HTML Attacks on Machine-Learning Phishing Webpage Detectors_ accepted
at the 16th ACM Workshop on Artificial Intelligence and Security (AISec '23), co-located with [ACM CCS 2023](https://www.sigsac.org/ccs/CCS2023/).

## Organization
The source code is organized as follows. The `src/` directory includes the following files:
* `extract_features_html.py` includes the same source code that has been refactored using the [Black formatter](https://black.readthedocs.io/en/stable/) and improved to make it more pythonic.
   Moreover, we also added the following functions:
   - `extract_features_phishing()` to extract the features as a Numpy array. The user can choose the type of features: html, url or all (html + url).
   - `build_phishing_test_data_info()` to prepare the test set (based on [DeltaPhish](https://link.springer.com/chapter/10.1007/978-3-319-66402-6_22)) to be used for the experiments.

* `manipulations.py` contains the source code of the proposed HTML adversarial manipulations.

* `optimizer.py` contains the source code of the proposed black-box optimizer.

* `model.py` implements a wrapper for Tensorflow and Scikit-learn models.

Moreover, the root directory of the repository includes the scripts to run the adversarial attacks. Specifically, it contains:
* `run_adv_attacks.py` contains the source code to generate adversarial phishing webpage against a taget machine-learning model.

* `run_experiments.py` contains the source code to run the experiments. It is based on the source code of [SpacePhish](https://github.com/hihey54/acsac22_spacephish/tree/main).

## Instructions
To quickly experiment with our project, we have released the pre-trained models in the `models` directory of this repository.  
They have been trained on the _DeltaPhish_ dataset using the source code provided in the [SpacePhish repository](https://github.com/hihey54/acsac22_spacephish/tree/main).  
Then, you need to create a Python virtual environment (venv) and install the required packages using the following commands (adjust the path of the venv according to your setup):
```
python3 -m venv $HOME/venv_adv_phishing
source $HOME/venv_adv_phishing activate
python -m pip install -r requirements.txt
```
The next step is to download the _DeltaPhish_ dataset used in _SpacePhish_.
As described in the _SpacePhish_ repository see [get_data.md](https://github.com/hihey54/acsac22_spacephish/blob/main/get_data.md), you can dowload it using [this link](https://drive.google.com/drive/folders/1k_aqmk5CTlhxlGfrg4jRSG5RxyX0NB9w?usp=sharing).
The password is "yy123" (without quotes).  
The last step to complete the setup is to set the `data_base_path` and `models_path` configuration variables in the `run_experiments.py` file according to your environment.  
They should point to the dataset used in _SpacePhish_ and the folder with the trained ML models, respectively.  
At this point you are ready to run the HTML adversarial attacks against the pre-trained models:
```
python run_experiments.py
```

Finally, if you want to train them on your own, we recommend to follow the instructions provided in the [SpacePhish repository](https://github.com/hihey54/acsac22_spacephish/tree/main).  
Once you have trained the ML models using the Jupyter notebooks provided in the _ml\_folder_ of the [SpacePhish repository](https://github.com/hihey54/acsac22_spacephish/tree/main), save them according to the naming convention used in this project (refer to the `models_info` dict in `run_experiments.py`).  