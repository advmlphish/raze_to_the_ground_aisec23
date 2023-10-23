import os
import hashlib
from PIL import Image
from html2image import Html2Image
import shutil

phishing_samples_path = os.path.abspath(os.path.join(os.getcwd(), 'samples'))
adversarial_samples_path = os.path.abspath(os.path.join(os.getcwd(), 'samples'))
out_path = os.path.join(os.getcwd(), 'out')


def check_rendering(phishing_samples, adv_samples, remove_screenshots=False):
    if not os.path.isdir(out_path):
        os.makedirs(out_path)

    hti = Html2Image(browser='chrome', output_path=out_path)

    for phishing_sample, adv_sample in zip(phishing_samples, adv_samples):
        phishing_sample_img_path = phishing_sample.split('.html')[0] + '.png' if phishing_sample.endswith('.html') else phishing_sample + '.png'
        adv_sample_img_path = adv_sample.split('.html')[0] + '.png' if adv_sample.endswith('.html') else adv_sample + '.png'

        hti.screenshot(html_file=os.path.join(phishing_samples_path, phishing_sample), save_as=phishing_sample_img_path)
        hti.screenshot(html_file=os.path.join(adversarial_samples_path, adv_sample), save_as=adv_sample_img_path)

        # compute the SHA-256 hashes
        hash_phishing = hashlib.sha256(Image.open(os.path.join(out_path, phishing_sample_img_path)).tobytes()).hexdigest()
        hash_adv = hashlib.sha256(Image.open(os.path.join(out_path, adv_sample_img_path)).tobytes()).hexdigest()

        if hash_phishing == hash_adv:
            print("Analyzing sample {}: The phishing sample and the corresponding adversarial example have the same rendering!\n".format(phishing_sample))
        else:
            print("Analyzing sample {}: The phishing sample and the corresponding adversarial example have NOT the same rendering!\n"
                  "Different SHA256 hashes: {}\n{}\n".format(phishing_sample, hash_phishing, hash_adv))

    if remove_screenshots:
        shutil.rmtree(out_path)


if __name__ == "__main__":
    phishing_samples = ['1461', '11755', '15894', '33903', '33910']
    adversarial_samples = ['1461_adv', '11755_adv', '15894_adv', '33903_adv', '33910_adv']
    check_rendering(phishing_samples, adversarial_samples)
