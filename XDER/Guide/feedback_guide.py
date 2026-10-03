# XDER/Guide/feedback_guide.py
import random


class FeedbackGuide:
    def __init__(self, initial_weights=None):
        # weight dict per paper Algorithm 3; each mutation op weight, init 1
        if initial_weights is None:
            self.weights = {
                'add': 1, 'repalce_value': 1, 'change_value': 1,
                'dele': 1, 'del_leaf': 1, 'replace_node': 1,
                'change_tag': 1, 'change_length': 1,
                'del_inner': 1, 'addinner_toinner': 1
            }
        else:
            self.weights = initial_weights

    def weighted_choice(self, mutat_func):
        """
        Roulette-wheel selection (paper Algorithm 3, lines 8-18):
        pick one operation by weight and return its function object directly.
        mutat_func is the dict passed from X-DER.py: keys are function objects, values are argument tuples.
        """
        total = sum(self.weights.values())
        r = random.uniform(0, total)
        cumulative = 0
        for op_name, w in self.weights.items():
            cumulative += w
            if r <= cumulative:
                # find the matching function object by name
                for f in mutat_func.keys():
                    if f.__name__ == op_name:
                        return f
        # fallback: return the last one
        return list(mutat_func.keys())[-1]

    def update(self, op, found_discrepancy):
        """
        Feedback update (strictly per paper Algorithm 3):
        - on discrepancy found, weight += 1
        - otherwise, no change
        """
        if found_discrepancy:
            self.weights[op] += 1