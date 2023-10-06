from time import perf_counter
from .manipulations import InjectIntElem, InjectIntElemFoot, InjectIntLinkElem, InjectExtElem, InjectExtElemFoot, \
    UpdateForm, ObfuscateExtLinks, ObfuscateJS, InjectFakeCopyright, UpdateIntAnchors, UpdateHiddenDivs, \
    UpdateHiddenButtons, UpdateHiddenInputs, UpdateTitle, UpdateIFrames, InjectFakeFavicon


class Optimizer:

    multi_round_manipulations = [InjectIntElem(), InjectIntElemFoot(), InjectIntLinkElem(), InjectExtElem(), InjectExtElemFoot()]

    single_round_manipulations = [
        UpdateForm(), ObfuscateExtLinks(), ObfuscateJS(), InjectFakeCopyright(), UpdateIntAnchors(), UpdateHiddenDivs(),
        UpdateHiddenButtons(), UpdateHiddenInputs(), UpdateTitle(), UpdateIFrames(), InjectFakeFavicon()
    ]

    def __init__(self, ml_model, num_rounds, save_only_best=False, debug=False):
        """Initialize an optimizer object.
        Arguments:
            ml_model: the input model to evaluate
            num_rounds (int): number of mutation rounds for the multi-round (MR) manipulations.
            save_only_best (bool): flag to save the score only when it decreases.
            debug (bool): flag to enable verbose mode.

        Raises:
            AssertionError: num_rounds is not an integer
        """
        assert isinstance(num_rounds, int) and num_rounds > 0
        assert isinstance(save_only_best, bool)
        assert isinstance(debug, bool)

        self.model = ml_model
        self.num_rounds = num_rounds
        self.debug = debug
        self.save_only_best = save_only_best

        self.best_score = None
        self.best_sample = None
        self.num_queries = 0
        self.traces = []

    def _evaluate(self, candidates):
        """
        Evaluate a set of candidates (the mutated phishing webpages generated from the current best adversarial example),
        and uodate the best adversarial example found so far each time we found a better candidate.

        Arguments:
            candidates: a list of tuples having the following format: (html, url, manipulation), where:
                        * html is a BeutifulSoup object
                        * url is the URL of the phishing webpage
                        * manipulation is a string representing the used manipulation
        """
        for html, url, manipulation in candidates:
            candidate = (html, url)
            score = self.model.classify(candidate)
            self.num_queries += 1

            if score <= self.best_score:
                self.best_score = score
                self.best_sample = candidate
                if self.save_only_best:
                    self.traces.append((self.num_queries, self.best_score))
                if self.debug:
                    print("Score after {} queries: {:.3f} using {}".format(self.num_queries, self.best_score, manipulation))

            if not self.save_only_best:
                self.traces.append((self.num_queries, score, manipulation))

    def optimize(self, html_url):
        """
        Generates an optimized adversarial phishing webpage (example)

        Arguments:
            html_url: an input sample represented by the tuple (HTML, URL), where
                      HTML is a BeutifulSoup object, while URL is a string.

        Returns:
            tuple: a tuple representing the reult of the optimization:
                   * self.best_score: the best score
                   * self.best_sample: the final adversarial phishing webpage
                   * self.num_queries: the number of used queries
                   * run_time: the run time in seconds
                   * self.traces: the optimization traces representing which manipulation has been used in each query
        """
        start_time = perf_counter()
        self.num_queries = 0
        self.best_score = self.model.classify(html_url)
        print("Initial score: {:.3f}".format(self.best_score))
        self.best_sample = html_url
        self.traces.append((0, self.best_score, ""))

        for manipulation in Optimizer.single_round_manipulations:
            best_html, best_url = self.best_sample
            mutated_html = manipulation(best_html, best_url)
            candidates = [(mutated_html, best_url, str(manipulation))]
            self._evaluate(candidates)
        if self.debug:
            print("Score after single-round manipulations: {:.3f}".format(self.best_score))

        for _ in range(self.num_rounds):
            best_html, best_url = self.best_sample

            candidates = []
            for manipulation in Optimizer.multi_round_manipulations:
                mutated_html = manipulation(best_html, best_url)
                candidates.append((mutated_html, best_url, str(manipulation)))

            self._evaluate(candidates)

        run_time = perf_counter() - start_time

        return self.best_score, self.best_sample, self.num_queries, run_time, self.traces
