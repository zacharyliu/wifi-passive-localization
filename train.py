import argparse
import pickle
import random
import matplotlib.pyplot as plt
import numpy as np
from sklearn.cross_validation import train_test_split
from sklearn.decomposition import PCA
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif, chi2
from sklearn.grid_search import GridSearchCV
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import Imputer, StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from mpl_toolkits.mplot3d import Axes3D
from sklearn.svm import SVC, LinearSVC


def plot_pca(X, y):
    from sklearn.feature_selection import SelectKBest
    from sklearn.feature_selection import f_classif

    model = Pipeline([
        ('imp', Imputer(missing_values='NaN', strategy='median', axis=0)),
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=10)),
        ('select', SelectKBest(f_classif, k=3)),
    ])

    X_pca = model.fit_transform(X, y)

    # Randomly perturb points so they aren't overlapping
    # for x in X_pca:
    #     for i in range(len(x)):
    #         x[i] += random.random() - 0.5

    plot_xs = [i[0] for i in X_pca]
    plot_ys = [i[1] for i in X_pca]
    plot_zs = [i[2] for i in X_pca]
    colors = ['b', 'y', 'r', 'g']
    plot_colors = [colors[i] for i in y]

    fig = plt.figure()
    ax = fig.add_subplot(121, projection='3d')
    ax.scatter(plot_xs, plot_ys, plot_zs, c=plot_colors)

    ax2 = fig.add_subplot(122)
    ax2.scatter(plot_xs, plot_ys, c=plot_colors, marker='o')

    plt.show()


def train(X, y, grid_search=False):
    imp = Imputer(missing_values='NaN', strategy='median', axis=0)
    X = imp.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15)

    # Initialize pipeline
    pipeline = Pipeline([
        # ('select', SelectKBest(mutual_info_classif, k=6)),
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=30)),
        # ('select', SelectKBest(f_classif, k=20)),
        # ('nb', GaussianNB()),
        # ('svc', SVC(probability=True, C=10, kernel='linear')),
        ('linearsvc', LinearSVC(C=10)),
        # ('knn', KNeighborsClassifier(n_neighbors=3)),
    ])

    if grid_search:
        print 'Initializing grid search'
        parameters = {
            'select__k': range(10, 40),
            # 'pca__n_components': range(2, 20),
            # 'svc__C': (0.1, 1, 10, 100),
            # 'knn__n_neighbors': range(2, 7),
        }
        model = GridSearchCV(pipeline, parameters)
    else:
        model = pipeline

    # Train the model
    print 'Number of training samples: %d' % len(X_train)
    model.fit(X_train, y_train)

    # Compute test score
    print "Score (trained on %d, tested on %d): %.6f" % (len(X_train), len(X_test), model.score(X_test, y_test))

    if grid_search:
        # Print parameters
        print model.best_params_

    return model, imp


def main():
    parser = argparse.ArgumentParser(description='Train an SVM on the labeled data and display its accuracy.')
    parser.add_argument('-l', '--label', help='output model label')
    parser.add_argument('--grid-search', action='store_true', help='use grid search to tweak parameters')
    parser.add_argument('--plot', action='store_true', help='show PCA plot')
    parser.add_argument('file', help='training data file')
    args = parser.parse_args()

    with open(args.file) as f:
        data = pickle.load(f)
        X = data['xs']
        y = data['ys']
        access_points = data['addrs']

    if args.plot:
        plot_pca(X, y)
        return

    if args.label:
        model_filename = 'models/model-%s.pkl' % args.label
        print 'Saving model to %s...' % model_filename
        with open(model_filename, 'wb') as f:
            model, imp = train(X, y, grid_search=args.grid_search)
            pickle.dump({'model': model, 'imp': imp, 'access_points': access_points}, f)
    else:
        train(X, y, grid_search=args.grid_search)

if __name__ == '__main__':
    main()
