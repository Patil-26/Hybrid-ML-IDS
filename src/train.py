from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score
import numpy as np
import joblib

from preprocessing import load_and_preprocess_data


def evaluate_model(name, model, X_train, X_test, y_train, y_test):
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

    if tp > 0:
        print("⚠ Intrusion Alarm Triggered!")

    return acc, model


def train_models(filepath):

    # Load data
    X, y = load_and_preprocess_data(filepath)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Define individual models
    rf = RandomForestClassifier(n_estimators=100)

    svm = Pipeline([
        ("scaler", StandardScaler()),
        ("svm", SVC(probability=True))
    ])

    lr = Pipeline([
        ("scaler", StandardScaler()),
        ("logistic", LogisticRegression(max_iter=500))
    ])

    # Evaluate individual models
    best_model = None
    best_accuracy = 0

    for name, model in [
        ("Random Forest", rf),
        ("SVM (Scaled)", svm),
        ("Logistic Regression (Scaled)", lr)
    ]:
        acc, trained_model = evaluate_model(
            name, model, X_train, X_test, y_train, y_test
        )

        if acc > best_accuracy:
            best_accuracy = acc
            best_model = trained_model

    # 🔥 Weighted Soft Voting Hybrid
    print("\nTraining Weighted Hybrid Ensemble...")

    hybrid = VotingClassifier(
        estimators=[
            ("rf", rf),
            ("svm", svm),
            ("lr", lr)
        ],
        voting="soft",
        weights=[0.6, 0.2, 0.2]  # RF gets higher weight
    )

    acc, trained_model = evaluate_model(
        "Weighted Hybrid Ensemble",
        hybrid,
        X_train,
        X_test,
        y_train,
        y_test
    )

    # Cross-validation
    print("\nPerforming 5-Fold Cross Validation on Hybrid...")
    cv_scores = cross_val_score(hybrid, X, y, cv=5)
    print(f"Cross-Validation Accuracy: {np.mean(cv_scores):.4f}")
    print(f"Standard Deviation: {np.std(cv_scores):.4f}")

    # Save best model
    if acc > best_accuracy:
        best_model = trained_model

    print("\nSaving best model...")
    joblib.dump(best_model, "models/best_model.pkl")
    print("Model saved successfully.")


if __name__ == "__main__":
    train_models("dataset/KDDTrain+.txt")