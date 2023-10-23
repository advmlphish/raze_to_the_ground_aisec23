import pickle
from bs4 import BeautifulSoup
from src.model import SklearnModel, KerasModel
from src.optimizer import Optimizer
import os
import json
import re
import html
import argparse
from run_experiments import data_base_path

output_path_default = os.path.join(os.getcwd(), 'out_adv_phishing')
data_path_default = os.path.join(data_base_path, 'raw/normal/HTML')
samples_info_filepath = os.path.join(data_base_path, 'samples_info.pkl')
num_rounds_default = 5


def preproc(html_str):
    updated = False
    # preproc_xhtml if needed
    if re.search('xhtml', html_str, re.IGNORECASE):
        html_str = re.sub(r'<(\w)+:', '<', html_str)
        html_str = re.sub(r'</(\w)+:', '</', html_str)
        updated = True

    if len(re.findall(r'&(#?)(\d{1,5}|\w{1,8});', html_str)) > 0:
        html_str = html.unescape(html_str)
        updated = True

    return html_str, updated


def run_attack(
    model_path,
    model_type,
    feat_type,
    data_path=data_path_default,
    samples_info_path=samples_info_filepath,
    num_rounds=num_rounds_default,
    output_path=output_path_default,
    overwrite=False
):
    if model_type == "sklearn":
        model = SklearnModel(model_path, feat_type)
    elif model_type == "keras":
        model = KerasModel(model_path, feat_type)
    else:
        raise Exception("Unsupported model type: {}".format(model_type))

    if not os.path.isdir(output_path):
        os.mkdir(output_path)

    try:
        with open(samples_info_path, 'rb') as fp:
            samples_info = pickle.load(fp)
    except OSError:
        raise Exception("Cannot load samples info from {}".format(samples_info_path))
    # print(samples_info)

    for sample_info in samples_info:
        file_id = str(sample_info['id'])
        file_path = os.path.join(data_path, file_id)
        adv_html_filepath = os.path.join(output_path, file_id)

        if not os.path.isfile(adv_html_filepath) or overwrite:
            print("Analyzing input sample #{}".format(file_id))
            url = sample_info['url']
            try:
                with open(file_path, 'r', encoding="utf-8") as fp:
                    # html_obj = str(BeautifulSoup(fp, "html.parser"))
                    # html_obj = "".join(line.strip() for line in html_obj.split("\n"))
                    # html_obj = html_obj.replace("'", "\"")
                    # html_obj = BeautifulSoup(fp, "html.parser")
                    html_str, updated = preproc(fp.read())
                    html_obj = BeautifulSoup(html_str, "html.parser")

                    if updated:
                        file_path = os.path.join(data_path, file_id + '_new')
                    try:
                        with open(file_path, 'w', encoding="utf-8") as fp:
                            fp.write(html_str)
                    except OSError:
                        print("Unable to write the updated HTML page")
            except OSError:
                print('Unable to read {}'.format(file_path))
                continue

            input_sample = (html_obj, url)

            optimizer = Optimizer(model, num_rounds)
            best_score, adv_example, num_queries, run_time, scores_trace = optimizer.optimize(input_sample)
            html_adv_obj, adv_url = adv_example
            print("Reached confidence {}, runtime: {:.4f} s\n".format(best_score, run_time))

            info = {'sample_id': file_id, 'best_score': float(best_score), 'adv_url': adv_url,
                    'num_queries': num_queries, 'run_time': run_time, 'scores_trace': str(scores_trace)}
            out_info_filepath = os.path.join(output_path, 'results.json')
            with open(out_info_filepath, 'a+') as out_file:
                out_file.write(json.dumps(info) + '\n')

            adv_html_filepath = os.path.join(output_path, file_id)
            with open(adv_html_filepath, 'w', encoding='utf-8') as fp:
                fp.write(str(html_adv_obj.prettify()))

        else:
            print("Skipping sample #{}, already analyzed\n".format(file_id))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run HTML adversarial attacks agsint a ML-based phishing webpage detector (ML-PWD).')
    parser.add_argument('model_path', type=str, help='Path of the ML-PWD')
    parser.add_argument('model_type', type=str, help='Type of the ML-PWD')
    parser.add_argument('feat_type', type=str, help='Type of features of the ML-PWD. Supported values: html or all (html + url)')
    parser.add_argument('num_rounds', type=int, help='Number of mutational rounds for the MR manipulations.')
    parser.add_argument('output_path', type=str, help='Output path')
    parser.add_argument('--model-feat-path', default=None, type=str, help='Path of the feature extractor for the ML-PWD')

    args = parser.parse_args()

    if args.model_feat_path is not None:
        model_path = [args.model_path, args.model_feat_path]
    else:
        model_path = args.model_path

    run_attack(model_path, args.model_type, args.feat_type, num_rounds=args.num_rounds, output_path=args.output_path, overwrite=False)
