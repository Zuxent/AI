import os
import pandas as pd
from scapy.all import rdpcap
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

class UserPCAPModel:
    def __init__(self, model_dir='models'):
        self.model_dir = model_dir
        os.makedirs(self.model_dir, exist_ok=True)
        self.models = {}

    def extract_features(self, pcap_path):
        packets = rdpcap(pcap_path)
        features = []
        for pkt in packets:
            pkt_len = len(pkt)
            proto = pkt.proto if hasattr(pkt, 'proto') else 0
            features.append({'length': pkt_len, 'proto': proto})
        return pd.DataFrame(features)

    def add_user_data(self, user_id, pcap_path, label):
        user_data_path = os.path.join(self.model_dir, f"{user_id}_data.csv")
        features = self.extract_features(pcap_path)
        features['label'] = label
        if os.path.exists(user_data_path):
            old = pd.read_csv(user_data_path)
            features = pd.concat([old, features], ignore_index=True)
        features.to_csv(user_data_path, index=False)

    def train_user_model(self, user_id):
        user_data_path = os.path.join(self.model_dir, f"{user_id}_data.csv")
        if not os.path.exists(user_data_path):
            raise FileNotFoundError("No data for this user.")
        df = pd.read_csv(user_data_path)
        X = df[['length', 'proto']]
        y = df['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        clf = RandomForestClassifier()
        clf.fit(X_train, y_train)
        joblib.dump(clf, os.path.join(self.model_dir, f"{user_id}_model.pkl"))
        self.models[user_id] = clf
        return clf.score(X_test, y_test)

    def predict(self, user_id, pcap_path):
        model_path = os.path.join(self.model_dir, f"{user_id}_model.pkl")
        if user_id not in self.models:
            if not os.path.exists(model_path):
                raise FileNotFoundError("Model not trained for this user.")
            self.models[user_id] = joblib.load(model_path)
        features = self.extract_features(pcap_path)
        return self.models[user_id].predict(features[['length', 'proto']])

# Example usage:
# model = UserPCAPModel()
# model.add_user_data('user1', 'user1_upload.pcap', label=1)
# acc = model.train_user_model('user1')
# preds = model.predict('user1', 'user1_test.pcap')