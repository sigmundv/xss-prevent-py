from sklearn.feature_extraction.text import CountVectorizer
import re
import numpy as np
import pickle
import pathlib
import pandas as pd
from keras.models import Sequential
from keras.layers import Dense
from urllib.parse import unquote
import html


vocabulary_file = "vocabulary.txt"


def preprocess_data(filename):
    """

    :param filename:
    :return:
    """
    with open(filename, 'r') as fd:
        blocks = re.split("\n\s*\n", fd.read())
        blocks = [block.split() for block in blocks[:-1]]
        gets = []
        posts = []
        for i in range(len(blocks) - 1):
            if blocks[i][0] == "GET":
                get = html.escape(unquote(unquote(blocks[i][1])))
                gets.append(get)
            else:
                post = html.escape(unquote(unquote(blocks[i][0])))
                posts.append(post)

    data = np.array([get.split('?')[1] for get in gets if '?' in get] + posts)

    target = np.zeros(data.shape, dtype=int)

    with open(vocabulary_file, 'r') as vocabulary:
        for string in vocabulary.read().splitlines():
            target[[i for i in range(len(target)) if string in data[i]]] = 1

    return data, target


def vectorize_data(data):
    """

    :param data: The data to vectorize; it should be a list of strings, one per line.
    :return: The CountVectorizer, which we need later in order to transform incoming requests to a feature vector
            The feature matrix based on the given vocabulary.

    """
    vocabulary = open(vocabulary_file, 'r').read().splitlines()

    vocabulary_lengths = list(map(len, vocabulary))
    min_length = np.min(vocabulary_lengths)
    max_length = np.max(vocabulary_lengths)

    count_vect = CountVectorizer(ngram_range=(min_length, max_length),
                                 analyzer='char',
                                 token_pattern=r'(?u).*\w.*\w+.',
                                 vocabulary=vocabulary)
    x_train_counts = count_vect.fit_transform(data).toarray()

    return count_vect, x_train_counts


def store_data(data, target, filename):
    """

    :param data:
    :param target:
    :param filename:
    :return:
    """
    dataset = np.concatenate((data, target.reshape(-1, 1)), axis=1)
    pd.DataFrame(dataset).to_csv(filename, header=False, index=False)


def train_data(fname):
    """

    :param fname: Filename that we stored the feature matrix to.
    :return: The model trained by Keras.
    """
    dataset = np.loadtxt(fname, delimiter=',')
    nrows, ncols = dataset.shape
    X = dataset[:, :(ncols-1)]
    Y = dataset[:, (ncols-1)]
    model = Sequential()
    model.add(Dense(12, input_dim=(ncols-1), activation='relu'))
    model.add(Dense(ncols-1, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(X, Y, validation_split=0.33, epochs=10, batch_size=10)
    return model


if __name__ == "__main__":

    dataset_filename = "dataset.csv"
    model_filename = "finalized_classifier.h5"
    vectorizer_filename = "finalized_vectorizer.sav"
    pastebin_datafile = "/home/sigmund/Documents/HDCBIBM/final-project/pastebin-data/data/pastebin_data.sav"

    if not pathlib.Path(dataset_filename).exists() and pathlib.Path(pastebin_datafile).exists():
        with open(pastebin_datafile, 'rb') as pastebin_file:
            pastebin_paths, pastebin_categories = pickle.load(pastebin_file)
        datapath = pathlib.Path("/home/sigmund/Documents/HDCBIBM/final-project/HTTP-DATASET-CSIC-2010/")
        datafiles = datapath.glob("*.txt")
        paths_dict = {}
        categories_dict = {}
        for datafile in datafiles:
            paths_dict[datafile.name], categories_dict[datafile.name] = preprocess_data(str(datafile))
        paths = np.concatenate(list(paths_dict.values()))
        paths = np.concatenate((paths, pastebin_paths))
        categories = np.concatenate(list(categories_dict.values()))
        categories = np.concatenate((categories, pastebin_categories))

        vectorizer, path_counts = vectorize_data(paths)

        store_data(path_counts, categories, dataset_filename)

        with open(vectorizer_filename, "wb") as sav_file:
            pickle.dump(vectorizer, sav_file)

    xss_classifier = train_data(dataset_filename)
    xss_classifier.save(model_filename)
