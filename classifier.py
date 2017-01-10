import pickle
from sample_to_x import sample_to_x
from sample_stream import SampleStreamPair

class ClassifierPair:
    def __init__(self, model, imp, access_points, print_results=True, predict_handler=None):
        self.model = model
        self.imp = imp
        self.access_points = access_points
        self.print_results = print_results
        self.predict_handler = predict_handler

        self.sample_stream = SampleStreamPair(sample_handler=self.predict_from_data)

    @classmethod
    def from_file(cls, filename, **kwargs):
        with open(filename) as f:
            model = pickle.load(f)
            return cls(model['model'], model['imp'], model['access_points'], **kwargs)

    def add_packet(self, p, source):
        self.sample_stream.add_packet(p, source)

    def predict(self, x):
        x = self.imp.transform(x)
        prediction = self.model.predict(x)[0]

        if self.print_results:
            print 'Predicted: %d' % prediction

        if self.predict_handler:
            self.predict_handler(prediction)

        return prediction

    def predict_from_data(self, sample):
        x = sample_to_x(sample, self.access_points)

        if self.print_results:
            for addr, count in self.sample_stream.access_points_counts.iteritems():
                if addr in self.access_points:
                    print '%s: %d %d' % (addr, count['a'], count['b'])
            print x

        return self.predict(x)
