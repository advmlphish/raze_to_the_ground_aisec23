# Raze to the Ground: Query-Efficient Adversarial HTML Attacks on Machine-Learning Phishing Webpage Detectors (AISec '23)

This repository contains the source code of the paper _Raze to the Ground: Query-Efficient Adversarial HTML Attacks on Machine-Learning Phishing Webpage Detectors_ accepted
at the 16th ACM Workshop on Artificial Intelligence and Security (AISec '23), co-located with [ACM CCS 2023](https://www.sigsac.org/ccs/CCS2023/).  

The related pre-print is available on ArXiv: [https://arxiv.org/abs/2310.03166](https://arxiv.org/abs/2310.03166).


## Abstract
Machine-learning phishing webpage detectors (ML-PWD) have been shown to be vulnerable to adversarial attacks that manipulate the HTML code of the input webpage.  
Nevertheless, the attacks recently proposed in the literature are characterized by two main limitations:
* The adopted manipulations do not fully leverage domain knowledge about phishing webpage.
* They often do not optimize the usage of the manipulations on the target ML-PWD.

To overcome such limitations, we propose the following contributions:
* We devise a novel set of 14 fine-grained adversarial manipulations that modify the HTML code of the input phishing webpage without compromising its maliciousness and visual appearance, i.e., the manipulations are functionality- and rendering-preserving by design.
* We design a novel black-box optimization algorithm to optimally select which manipulations should be applied to evade the target detector.

Our experiments show that our attacks are able to raze to the ground the performance of current state-of-the-art ML-PWD using just 30 queries.  
To foster reproducibility and enable a much fairer robustness evaluation of ML-PWD, we publicly release the source code of the proposed manipulations, the optimization algorithm, as well as the results of the experimental evaluation.


## Organization
This repository is organized as follows.

**`src/` folder**  
It includes the source code of the HTML adversarial manipulations and optimization algorithm.
Specifically, we provide the following files:  
* `extract_features_html.py`: it includes the same source code used in _SpacePhish_ (see [`extractor.py`](https://github.com/hihey54/acsac22_spacephish/blob/99fe25e4dca1bdc7ccebece78db325955f5f532f/preprocessing_folder/extractor.py)), which has been refactored using the [Black formatter](https://black.readthedocs.io/en/stable/) and improved to make it more pythonic. Moreover, we also added the following functions:
   * `extract_features_phishing()`: it is used to extract the features as a Numpy array. The user can choose the type of features: HTML (`html`), URL (`url`) or the combination of both HTML and URL (`all`).
   * `build_phishing_test_data_info()`: used to prepare the test set for the experiments, whhich is based on the [DeltaPhish](https://link.springer.com/chapter/10.1007/978-3-319-66402-6_22) dataset.

* `manipulations.py`: it contains the source code of the proposed HTML adversarial manipulations.

* `optimizer.py`: it contains the source code of the proposed black-box optimization algorithm.

* `model.py`: it implements a wrapper for [Tensorflow](https://www.tensorflow.org) and [Scikit-learn](https://scikit-learn.org/stable/) models.

**`experiments/` folder**  
It includes the output files of the experiments in JSON format for each target machine-learning model.  
Specifically, the output files include, for each sample, the full trace of the confidence score w.r.t. the number of queries, which can be used to plot the security evaluation curves (refer to the plots in `experiments_analysis.ipynb`).  
Please note that, even though we do not provide the adversarial phishing webpages, they can be easily generated using the steps described below.

**`models/` folder**  
It includes the pre-trained machine-learning models used in the experiments.  
As described in our paper, we evaluated the same algorithms considered in [SpacePhish](https://dl.acm.org/doi/abs/10.1145/3564625.3567980): Logistic Regression ($LR$), Random Forest ($RF$), and Convolutional Neural Network ($CNN$).  
They have been trained on the _DeltaPhish_ dataset using the source code provided in the [SpacePhish GitHub repository](https://github.com/hihey54/acsac22_spacephish/tree/99fe25e4dca1bdc7ccebece78db325955f5f532f).  
As for the feature set, we considered the HTML features ($F^r$) and the whole feature set ($F^c$) that consists in the combination of both HTML and URL features.

**`samples/` folder**  
It includes 5 samples of phishing webpages along with their corresponding optimized adversarial examples (marked with names ending with `_adv`) optimized on the Random Forest model trained on the full set of features, i.e., $RF$  $F^c$.

**repository root folder**  
It includes the main code to run the experiments and visualize the results:

* `run_experiments.py`: main Python script to run the experiments.
* `run_adv_attacks.py`: Python script that contains the source code to generate adversarial phishing webpages against a target machine-learning model.
* `check_rendering.py`: Python script to verify whether the generated adversarial phishing webpages have the same rendering of their respective phishing samples.
  This script renders a phishing webpage and its corresponding adversarial example in the Google Chrome browser, captures their screenshots, and computes their SHA-256 checksum to check if they are the same.
  This can be run on the samples included in the `samples/` folder.
* `experiments_analysis.ipynb`: Jupyter notebook to visualize and interpret the results. It reports the security evaluation curves showing how the detection rate at 1% False Positive Rate (FPR) changes w.r.t. the number of queries, considering the best sequence of manipulations.


## Requirements

### Hardware dependencies
We conducted our experimental evaluation on a server equipped with an Intel Xeon E7-8880 CPU (16 cores) and 64 GB of RAM.  
No GPU is needed to train the evaluated machine-learning models.

### Software dependencies
The experiments have been validated on a server based on Ubuntu 18.04.6 LTS.  
The source code is written in Python 3.10.6. All the required packages are provided in the `requirements.txt` file included in the root folder of this repository.  
Finally, to visualize the generated adversarial phishing webpages and the respective phishing samples, as well as to verify if they have the same rending, we recommend to install the [Google Chrome browser](https://www.google.com/chrome/).


## Instructions

1. Retrive the artifact:  
`git clone https://github.com/advmlphish/raze_to_the_ground_aisec23`.

2. Move into the artifact root folder:  
`cd raze_to_the_ground_aisec23`.

3. Select the current stable release:  
`git checkout v1.0`.

4. Create a Python virtual environment (venv) if not already done:  
`python3 -m venv $HOME/venv_adv_phishing`.

5. Activate the created venv:  
`source $HOME/venv_adv_phishing/bin/activate`.

6. Install the required Python packages:  
`python -m pip install -r requirements.txt`.

7. Download the data used in _SpaecPhish_, including the _DeltaPhish_ dataset, using this link: [https://drive.google.com/drive/folders/1k_aqmk5CTlhxlGfrg4jRSG5RxyX0NB9w?usp=sharing](https://drive.google.com/drive/folders/1k_aqmk5CTlhxlGfrg4jRSG5RxyX0NB9w?usp=sharing).  
The password is `yy123`.

8. Set the `data_base_path` and `models_path` configuration variables in the `run_experiments.py` file according to your environment.  
They should point to the _DeltaPhish_ dataset and the folder with the trained models, respectively.

9. At this point you are ready to run the HTML adversarial attacks against the pre-trained models:  
`python run_experiments.py`.  
The results will be saved by default in the `experiments/` folder.

Finally, if you want to train the machine-learning models on your own, we recommend to follow the instructions provided in the [SpacePhish repository](https://github.com/hihey54/acsac22_spacephish/tree/99fe25e4dca1bdc7ccebece78db325955f5f532f), and then save them according to the naming convention used in this project (refer to the `models_info` dict in `run_experiments.py`).
