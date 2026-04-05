#!/usr/bin/env python3
"""Text Classifier - TF-IDF + Naive Bayes from scratch (no sklearn needed)."""

import math
import re
from collections import defaultdict, Counter
import json


class TFIDFNaiveBayes:
    """Text classifier using TF-IDF features with Naive Bayes."""

    def __init__(self):
        self.class_word_counts = defaultdict(Counter)
        self.class_doc_counts = Counter()
        self.vocab = set()
        self.doc_freq = Counter()
        self.total_docs = 0

    def tokenize(self, text: str) -> list[str]:
        text = text.lower()
        text = re.sub(r"[^a-z0-9\s]", " ", text)
        tokens = text.split()
        stopwords = {"the", "a", "an", "is", "are", "was", "were", "be", "been",
                     "being", "have", "has", "had", "do", "does", "did", "will",
                     "would", "could", "should", "may", "might", "can", "shall",
                     "to", "of", "in", "for", "on", "with", "at", "by", "from",
                     "it", "this", "that", "and", "or", "not", "but", "if"}
        return [t for t in tokens if t not in stopwords and len(t) > 1]

    def train(self, documents: list[tuple[str, str]]):
        """Train on list of (text, label) tuples."""
        self.total_docs = len(documents)
        for text, label in documents:
            tokens = self.tokenize(text)
            self.class_doc_counts[label] += 1
            unique_tokens = set(tokens)
            for token in unique_tokens:
                self.doc_freq[token] += 1
            for token in tokens:
                self.class_word_counts[label][token] += 1
                self.vocab.add(token)

    def _tfidf(self, token: str, token_count: int, doc_length: int) -> float:
        tf = token_count / doc_length if doc_length > 0 else 0
        idf = math.log(self.total_docs / (1 + self.doc_freq.get(token, 0)))
        return tf * idf

    def predict(self, text: str) -> dict:
        """Predict class for text with confidence scores."""
        tokens = self.tokenize(text)
        token_counts = Counter(tokens)
        doc_length = len(tokens)
        scores = {}

        for label in self.class_doc_counts:
            prior = math.log(self.class_doc_counts[label] / self.total_docs)
            likelihood = 0
            total_words = sum(self.class_word_counts[label].values())

            for token, count in token_counts.items():
                word_count = self.class_word_counts[label].get(token, 0)
                prob = (word_count + 1) / (total_words + len(self.vocab))
                tfidf_weight = self._tfidf(token, count, doc_length)
                likelihood += math.log(prob) * (1 + tfidf_weight)

            scores[label] = prior + likelihood

        max_score = max(scores.values())
        exp_scores = {k: math.exp(v - max_score) for k, v in scores.items()}
        total = sum(exp_scores.values())
        probs = {k: round(v / total, 4) for k, v in exp_scores.items()}

        predicted = max(probs, key=probs.get)
        return {"prediction": predicted, "confidence": probs[predicted], "probabilities": probs}


# Demo: Spam detector
TRAINING_DATA = [
    ("Win a free iPhone now click here", "spam"),
    ("Congratulations you won $1000 cash prize", "spam"),
    ("Buy cheap medications online discount", "spam"),
    ("Free credit score check limited offer", "spam"),
    ("Make money fast work from home easy", "spam"),
    ("Urgent: your account has been compromised act now", "spam"),
    ("Best deals on electronics sale happening now", "spam"),
    ("You have been selected for a special reward", "spam"),
    ("Hey can we meet for lunch tomorrow", "ham"),
    ("The project deadline has been moved to Friday", "ham"),
    ("Please review the attached document and provide feedback", "ham"),
    ("Team meeting scheduled for 3pm in conference room B", "ham"),
    ("I pushed the code changes to the dev branch", "ham"),
    ("Can you help me debug this API endpoint", "ham"),
    ("The quarterly report looks good nice work", "ham"),
    ("Remember to submit your timesheet by end of day", "ham"),
]

TEST_DATA = [
    "Claim your free gift card worth $500 today",
    "Can we reschedule the meeting to next week",
    "You won a lottery prize click to claim now",
    "The deployment pipeline is failing on staging",
    "Limited time offer buy one get one free",
]


if __name__ == "__main__":
    clf = TFIDFNaiveBayes()
    clf.train(TRAINING_DATA)

    print("Text Classifier (Spam Detection Demo)")
    print("=" * 50)
    print(f"Training samples: {len(TRAINING_DATA)}")
    print(f"Vocabulary size: {len(clf.vocab)}")

    print("\nPredictions:")
    for text in TEST_DATA:
        result = clf.predict(text)
        icon = "[SPAM]" if result["prediction"] == "spam" else "[OK]  "
        print(f"  {icon} ({result['confidence']:.0%}) {text[:60]}")

    print("\nTry your own text as argument: python text_classifier.py \"your text here\"")
    if len(import_sys := sys.argv) > 1:
        custom_text = " ".join(import_sys[1:])
        result = clf.predict(custom_text)
        print(f"\nCustom: {result['prediction']} ({result['confidence']:.0%})")
        print(json.dumps(result, indent=2))
