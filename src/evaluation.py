import numpy as np
import json
import os
import joblib
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.utils import resample

from preprocessing import load_and_preprocess_data


# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "KDDTrain+.txt")
MODEL_PATH   = os.path.join(BASE_DIR, "models", "best_model.pkl")
RESULTS_PATH = os.path.join(BASE_DIR, "logs", "evaluation_results.json")


# ─── Evaluate a single model ──────────────────────────────────────────
def evaluate_model(name, model, X_train, X_test, y_train, y_test):
    """
    Train the model and compute all evaluation metrics.
    Returns a dictionary of results and the trained model.
    """

    print(f"\n{'='*45}")
    print(f"  Evaluating: {name}")
    print(f"{'='*45}")

    # Train
    model.fit(X_train, y_train)

    # Predict
    y_pred = model.predict(X_test)

    # Metrics
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred).tolist()

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Normal', 'Attack'])}")

    return {
        "model":            name,
        "accuracy":         round(acc, 4),
        "precision":        round(prec, 4),
        "recall":           round(rec, 4),
        "f1_score":         round(f1, 4),
        "confusion_matrix": cm,
        "tp":               int(tp),
        "tn":               int(tn),
        "fp":               int(fp),
        "fn":               int(fn)
    }, model


# ─── Cross Validation ─────────────────────────────────────────────────
def cross_validate_model(name, model, X, y, cv=5):
    """
    Run k-fold cross validation on a sampled subset for speed.
    """
    print(f"\nRunning {cv}-Fold Cross Validation on {name}...")

    # Sample 30k rows for CV — representative but fast
    X_cv, y_cv = resample(X, y, n_samples=30000, random_state=42)

    scores = cross_val_score(model, X_cv, y_cv, cv=cv, scoring="accuracy")
    print(f"  CV Accuracy : {np.mean(scores):.4f}")
    print(f"  Std Dev     : {np.std(scores):.4f}")
    return round(np.mean(scores), 4), round(np.std(scores), 4)


# ─── Save results ─────────────────────────────────────────────────────
def save_results(results):
    """
    Save all evaluation results to JSON so the dashboard can read them.
    """
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\nResults saved to {RESULTS_PATH}")


# ─── Main ─────────────────────────────────────────────────────────────
def run_evaluation():

    print("\nLoading dataset...")
    X, y = load_and_preprocess_data(DATASET_PATH)

    # Split into train and test — 80% train, 20% test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print(f"Training samples : {len(X_train)}")
    print(f"Testing samples  : {len(X_test)}")

    # SVM and LR are slow on 100k+ rows
    # Sample 20k rows — still representative, trains in reasonable time
    X_train_small, y_train_small = resample(
        X_train, y_train,
        n_samples=20000,
        random_state=42
    )
    print(f"Sampled training set for SVM/LR : {len(X_train_small)} rows")

    # ── Define models ──────────────────────────────────────────────────

    rf = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    # LinearSVC is much faster than SVC kernel=linear
    # CalibratedClassifierCV wraps it to support predict_proba
    # needed for soft voting in the ensemble
    svm = Pipeline([
        ("scaler", StandardScaler()),
        ("svm", CalibratedClassifierCV(
            LinearSVC(max_iter=2000, random_state=42),
            cv=3
        ))
    ])

    lr = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(
            max_iter=1000,
            random_state=42
        ))
    ])

    ensemble = VotingClassifier(
        estimators=[
            ("rf", rf),
            ("svm", svm),
            ("lr", lr)
        ],
        voting="soft",
        weights=[0.6, 0.2, 0.2]
    )

    # ── Evaluate all models ────────────────────────────────────────────
    all_results = []

    for name, model in [
        ("Random Forest",       rf),
        ("SVM",                 svm),
        ("Logistic Regression", lr),
        ("Weighted Ensemble",   ensemble)
    ]:
        # RF and Ensemble train on full data
        # SVM and LR train on sampled data for speed
        if name in ["SVM", "Logistic Regression"]:
            result, trained_model = evaluate_model(
                name, model,
                X_train_small, X_test,
                y_train_small, y_test
            )
        else:
            result, trained_model = evaluate_model(
                name, model,
                X_train, X_test,
                y_train, y_test
            )

        # Cross validate only the final ensemble
        if name == "Weighted Ensemble":
            cv_mean, cv_std = cross_validate_model(
                name, trained_model, X, y
            )
            result["cv_accuracy"] = cv_mean
            result["cv_std"]      = cv_std

            # Save ensemble as the deployed model
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            joblib.dump(trained_model, MODEL_PATH)
            print(f"\nEnsemble model saved to {MODEL_PATH}")

        all_results.append(result)

    # ── Save all results ───────────────────────────────────────────────
    save_results(all_results)
    print("\nEvaluation complete.")


if __name__ == "__main__":
    run_evaluation()