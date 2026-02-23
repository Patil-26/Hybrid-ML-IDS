from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, accuracy_score
import joblib

from preprocessing import load_and_preprocess_data


def train_models(filepath):

    # Load data
    X, y = load_and_preprocess_data(filepath)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100),
        "SVM": SVC(),
        "Logistic Regression": LogisticRegression(max_iter=500)
    }

    best_model = None
    best_accuracy = 0

    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

        print(f"Accuracy: {acc:.4f}")
        print(f"True Positives: {tp}")
        print(f"True Negatives: {tn}")
        print(f"False Positives: {fp}")
        print(f"False Negatives: {fn}")

        # Alarm logic
        if tp > 0:
            print("⚠ Intrusion Alarm Triggered!")

        if acc > best_accuracy:
            best_accuracy = acc
            best_model = model

    print("\nSaving best model...")
    joblib.dump(best_model, "models/best_model.pkl")
    print("Model saved successfully.")


if __name__ == "__main__":
    train_models("dataset/KDDTrain+.txt")