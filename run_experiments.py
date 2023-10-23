from src.extract_features_html import build_phishing_test_data_info
import shlex
import subprocess
import os

# config options:
data_base_path = '/adv_phishing_workspace/data_folder/deltaphish'   # NOTE: change according to your setup
models_path = os.path.join(os.getcwd(), 'models')   # NOTE: change according to your setup
out_base_path = os.path.join(os.getcwd(), 'experiments_test')
num_rounds_default = 5

models_info = [
    ('model_cnn_combined.h5', 'keras', 'all'),
    ('model_cnn_html.h5', 'keras', 'html'),
    (('model_lr_combined.joblib', 'model_lr_combined_rfe_selector.joblib'), 'sklearn', 'all'),
    (('model_lr_html.joblib', 'model_lr_html_rfe_selector.joblib'), 'sklearn', 'html'),
    (('model_rf_combined.joblib', 'model_rf_combined_rfe_selector.joblib'), 'sklearn', 'all'),
    (('model_rf_html.joblib', 'model_rf_html_rfe_selector.joblib'), 'sklearn', 'html')
]


if __name__ == "__main__":
    build_phishing_test_data_info(
        main_filepath=os.path.join(data_base_path, 'raw/normal/deltaphish_data.json'),
        test_samples_path=os.path.join(data_base_path, 'preprocessed/phish_sub_test_x_100.pkl'),
        out_file_path=os.path.join(data_base_path, 'samples_info.pkl')
    )

    if not os.path.isdir(out_base_path):
        os.mkdir(out_base_path)

    cmd_base = "python run_adv_attack.py {model_path} {model_type} {feat_type} {max_rounds} {out_path}"

    for model_name, model_type, feat_type in models_info:
        if isinstance(model_name, tuple):
            model_path = os.path.join(models_path, model_name[0])
            model_feat_path = os.path.join(models_path, model_name[1])
            model_label = model_name[0].split('.')[0]
        else:
            model_path = os.path.join(models_path, model_name)
            model_feat_path = None
            model_label = model_name.split('.')[0]

        model_out_path = os.path.join(out_base_path, 'out_{}'.format(model_label))

        cmd = cmd_base.format(model_path=model_path, model_type=model_type, feat_type=feat_type, max_rounds=num_rounds_default, out_path=model_out_path)
        if model_feat_path is not None:
            cmd += " --model-feat-path {}".format(model_feat_path)

        if not os.path.isdir(model_out_path):
            os.mkdir(model_out_path)

        with open(os.path.join(model_out_path, "output.log"), "w") as out_file:
            p = subprocess.Popen(shlex.split(cmd), stdout=out_file)
        # subprocess.run(shlex.split(cmd), check=True)  # stdout=log_file
