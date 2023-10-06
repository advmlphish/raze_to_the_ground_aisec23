from contextlib import redirect_stderr
import abc
import os
import joblib
from .extract_features_html import extract_features_phishing
with redirect_stderr(open(os.devnull, "w")):
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    import tensorflow as tf


class Model(metaclass=abc.ABCMeta):
    """Abstract machine learning model wrapper."""

    @abc.abstractmethod
    def extract_features(self, in_object):
        """
        Extracts a feature vector from the input object.

        Arguments:
            in_object : An input point that belongs to the input space of the wrapped model.

        Returns:
            feature_vector (numpy ndarray) : array containing the feature vector of the input value.

        Raises:
            NotImplementedError: this method needs to be implemented
        """
        raise NotImplementedError("extract_features not implemented in abstract class")

    @abc.abstractmethod
    def classify(self, in_object):
        """
        Returns the probability of belonging to a particular class.
        It calls the extract_features function on the input value to produce a feature vector.

        Arguments:
            in_object : Input object

        Returns:
            float : the probability of belonging to the malicious class
        """
        raise NotImplementedError("classify not implemented in abstract class")


class SklearnModel(Model):
    """Scikit learn classifier wrapper class"""

    def __init__(self, model_path, feat_type):
        """
        Constructs a wrapper around an scikit-learn classifier, or equivalent.
        It must implement predict_proba function.

        Arguments:
            model_path: path of the ML model
            feat_tye: type of features used by the model. Supported values are html or all (HTML + URL)

        Raises:
            Exception:
                - not implement predict_proba
                - cannot load the ML model
        """
        if isinstance(model_path, list):
            clf_path = model_path[0]
            rfe_path = model_path[1]
            try:
                sklearn_classifier = joblib.load(clf_path)
            except Exception:
                raise Exception("Error in loading model.")
            try:
                rfe_selector = joblib.load(rfe_path)
            except Exception:
                raise Exception("Error in loading the RFE selector.")
        else:
            try:
                sklearn_classifier = joblib.load(model_path)
            except Exception:
                raise Exception("Error in loading model.")
            rfe_selector = None

        if getattr(sklearn_classifier, "predict_proba", None) is None:
            raise Exception("object does not implement predict_proba function")

        self._model = sklearn_classifier
        self._rfe_selector = rfe_selector
        self._feat_type = feat_type

    def classify(self, in_object):
        """
        Returns the probability of belonging to the positive class (i.e., phishing).
        It calls the extract_features function on the input value to produce a feature vector.

        Arguments:
            in_object: an input sample represented by the tuple (HTML, URL), where
                       HTML is a BeutifulSoup object, while URL is a string.

        Returns:
            float: the confidence score of the input sample.

        """
        feature_vector = self.extract_features(in_object)
        # y_pred = self._model.predict_proba([feature_vector])
        if self._rfe_selector is not None:
            feature_vector = self._rfe_selector.transform(feature_vector.reshape(1, -1))
        else:
            feature_vector = feature_vector.reshape(1, -1)
        y_pred = self._model.predict_proba(feature_vector)
        return y_pred[0, 1]

    def extract_features(self, in_object):
        """
        Returns the feature representation of the input.

        Arguments:
            in_object: a sample represented by the tuple (HTML, URL), where
                       HTML is a BeutifulSoup object, while URL is a string.

        Returns:
            numpy ndarray: the vector representation of the input sample.
        """
        html, url = in_object
        return extract_features_phishing(html, url, self._feat_type)


class KerasModel(Model):
    """Keras model wrapper"""

    def __init__(self, model_path, feat_type):
        """
        Constructs a wrapper around an TensorFlow/Keras classifier.

        Arguments:
            model_path: path of the ML model
            feat_tye: type of features used by the model. Supported values are html or all (HTML + URL)

        Raises:
            Exception:
                - not implement predict() method needed to compute the output score
                - cannot load the ML model
        """
        try:
            keras_classifier = tf.keras.models.load_model(model_path)
        except Exception:
            raise Exception("Error in loading model.")

        if getattr(keras_classifier, "predict", None) is None:
            raise Exception("object does not implement predict function")
        self._model = keras_classifier
        self._feat_type = feat_type

    def classify(self, input_obj):
        """
        Returns the probability of belonging to the positive class (i.e., phishing).
        It calls the extract_features function on the input value to produce a feature vector.

        Arguments:
            input_obj: an input sample represented by the tuple (HTML, URL), where
                       HTML is a BeutifulSoup object, while URL is a string.

        Returns:
            float: the confidence for each class of the problem.
        """
        feature_vector = self.extract_features(input_obj)
        feature_vector = feature_vector.reshape((1, feature_vector.shape[0], 1))
        y_pred = self._model.predict(feature_vector)
        try:
            assert len(y_pred.shape) == 2
        except AssertionError:
            raise Exception("Only binary classifiers are supported")
        return y_pred[0, 1]

    def extract_features(self, input_obj):
        """
        Returns the feature representation of the input.

        Arguments:
            input_obj: an input sample represented by the tuple (HTML, URL), where
                       HTML is a BeutifulSoup object, while URL is a string.

        Returns:
            numpy ndarray: the vector representation of the input sample.
        """
        html, url = input_obj
        return extract_features_phishing(html, url, self._feat_type)
