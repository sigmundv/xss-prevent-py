import pickle
import h5py
import logging
import numpy as np
from keras.models import load_model


class Classifier:

    def __init__(self):
        """
        Load CountVectorizer and classifier
        """
        with open("models/finalized_vectorizer.sav", "rb") as saved_vectorizer:
            self.vectorizer = pickle.load(saved_vectorizer)
        self.classifier = load_model("models/finalized_classifier.h5")
        logging.debug("CountVectorizer and classifier loaded")

    def classify(self, data):
        """

        :param data:
        :return:
        """
        x_new_counts = self.vectorizer.transform(data)
        logging.debug("Predicting category for %s", data)
        return np.round(self.classifier.predict(x_new_counts.toarray())).astype(int)
