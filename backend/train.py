import pandas as pd
path = r"C:\Users\DELL\Desktop\Phishing_Detection\dataset\phishing.csv"
df = pd.read_csv(path)
print(df.head())
print(df.columns)
df.shape

df.dtypes
df.isnull().sum()
df.duplicated()
df.describe()

label_counts = df.columns.value_counts()
print(label_counts)
import plotly.express as px
fig = px.bar(label_counts, x=label_counts.index, y=label_counts.values, title="Distribution of Labels")
#fig.show()
counts_class = df['class'].value_counts()
print(counts_class)
fig = px.pie(
    values=counts_class.values,
    names=counts_class.index,
    title="Class Distribution"
)

#fig.show()
class_counts = df['class'].value_counts()

fig = px.bar(
    x=class_counts.index,
    y=class_counts.values,
    labels={'x': 'Class', 'y': 'Count'},
    title="Class Distribution"
)

#fig.show()
import numpy as np
mean_counts = np.mean(df)
print(mean_counts)
median_counts = np.median(df)
print(median_counts)
standard_deviation_counts = np.std(df)
print(standard_deviation_counts)
minimum_counts = np.min(df)
print(minimum_counts)
maximum_counts = np.max(df)
print(maximum_counts)
df.columns.tolist()
print(len(df['LongURL'].unique()))
print(len(df['LongURL'].unique()))
print(len(df['ShortURL'].unique()))
print(df['ShortURL'].unique())
print(df['SubDomains'].value_counts())
import matplotlib.pyplot as plt
import seaborn as sns
plt.figure(figsize=(8, 5))
sns.kdeplot(df)
plt.axvline(mean_counts, label="Mean")
plt.axvline(median_counts, color="black", label="Median")
plt.title("Distribution of Class Counts (Skewness)")
plt.xlabel("class")
plt.legend()
#plt.show()
#here we dont need index
df = df.drop(columns=["Index"])
#compute correlation matrix
corr_matrix = df.corr()
import seaborn as sns
import matplotlib.pyplot as plt

plt.figure(figsize=(14,10))
sns.heatmap(corr_matrix, annot=False, cmap="coolwarm")
plt.title("Correlation Heatmap")
#plt.show()
target_corr = df.corr()["class"].sort_values(ascending=False)

plt.figure(figsize=(6,10))
sns.heatmap(target_corr.to_frame(), annot=True, cmap="coolwarm")
plt.title("Feature Correlation with Target")
#plt.show()
correlation = df.corr()["class"].drop("class")

# Select important features
selected_features = correlation[correlation.abs() > 0.1].index

print(selected_features)
X = df[selected_features]
y = df["class"]
#Train-test split
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y   # 👈 important since classes are slightly imbalanced
)
print(X_train.shape, X_test.shape)
print(y_train.shape, y_test.shape)
#scale features
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = LogisticRegression(max_iter=1000)
model.fit(X_train_scaled, y_train)

y_pred = model.predict(X_test_scaled)
from sklearn.linear_model import LogisticRegression

model = LogisticRegression(max_iter=1000)  # increase iterations to avoid convergence issues
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
#evaluate model
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))
#understanding feature importance
import pandas as pd

coefficients = pd.Series(model.coef_[0], index=X.columns)
print(coefficients.sort_values(ascending=False))
#Reduce phishing misses (VERY important
y_prob = model.predict_proba(X_test)[:, 1]

# Change threshold (default is 0.5)
y_pred_custom = (y_prob > 0.4).astype(int)

# Convert 0 → -1 if needed
y_pred_custom = [1 if i == 1 else -1 for i in y_pred_custom]
#Tune regularization (
model = LogisticRegression(C=0.5, max_iter=1000)
#handle class importance
model = LogisticRegression(class_weight='balanced', max_iter=1000)
#conpare strong models
from sklearn.ensemble import RandomForestClassifier

rf = RandomForestClassifier(random_state=42)
rf.fit(X_train, y_train)
#save the model 
import joblib

joblib.dump(model, "phishing_logistic_regression_model.pkl")
joblib.dump(scaler, "scaler.pkl")
from sklearn.pipeline import Pipeline

pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("model", LogisticRegression(class_weight='balanced', max_iter=1000))
])

pipeline.fit(X_train, y_train)

joblib.dump(pipeline, "phishing_pipeline.pkl")
#using svc algorithm
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train SVM
model = SVC(kernel='rbf', C=1, gamma='scale')
model.fit(X_train_scaled, y_train)
y_pred = model.predict(X_test_scaled)
#evaluate model svc model
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))
#Linear kernel (faster)
model = SVC(kernel='linear', C=1)
#RBF tuning (more powerful)
model = SVC(kernel='rbf', C=10, gamma=0.1)
#Handle imbalance
model = SVC(kernel='rbf', class_weight='balanced')

model = SVC(kernel='rbf', probability=True)
from sklearn.pipeline import Pipeline

pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("svc", SVC(kernel='rbf', C=1, gamma='scale'))
])

pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
import joblib

# Load model
# Save
joblib.dump(pipeline, "svm_phishing_model.pkl")
#we load  the model later
import joblib

# Load model
model = joblib.load("svm_phishing_model.pkl")

# Predict
predictions = model.predict(X_test)
#decision tree 
from sklearn.tree import DecisionTreeClassifier

# Create model
dt_model = DecisionTreeClassifier(
    criterion='gini',  # you can also try 'entropy'
    max_depth=None,    # let it grow fully, or tune later
    random_state=42
)

# Train
dt_model.fit(X_train, y_train)
y_pred = dt_model.predict(X_test)
#evaluate model of decision tree
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))
#feature importance of decision tree
import pandas as pd

importance = pd.Series(dt_model.feature_importances_, index=X.columns)
print(importance.sort_values(ascending=False))
#save decision tree model
import joblib

joblib.dump(dt_model, "decision_tree_phishing_model.pkl")
# Logistic Regression
# If you used scaling
from sklearn.preprocessing import StandardScaler

scaler_logreg = StandardScaler()
X_train_scaled_logreg = scaler_logreg.fit_transform(X_train)
X_test_scaled_logreg = scaler_logreg.transform(X_test)

# Train Logistic Regression (if not trained yet)
from sklearn.linear_model import LogisticRegression
logreg_model = LogisticRegression(class_weight='balanced', max_iter=1000)
logreg_model.fit(X_train_scaled_logreg, y_train)

# Make predictions
y_pred_logreg = logreg_model.predict(X_test_scaled_logreg)
# SVM (if not predicted yet)
scaler_svm = StandardScaler()
X_train_scaled_svm = scaler_svm.fit_transform(X_train)
X_test_scaled_svm = scaler_svm.transform(X_test)

from sklearn.svm import SVC
svm_pipeline = SVC(kernel='rbf', C=1, gamma='scale')
svm_pipeline.fit(X_train_scaled_svm, y_train)
y_pred_svm = svm_pipeline.predict(X_test_scaled_svm)
# Decision Tree
from sklearn.tree import DecisionTreeClassifier
dt_model = DecisionTreeClassifier(random_state=42)
dt_model.fit(X_train, y_train)
y_pred_dt = dt_model.predict(X_test)  # no scaling needed
from sklearn.metrics import accuracy_score

acc_logreg = accuracy_score(y_test, y_pred_logreg)
acc_svm    = accuracy_score(y_test, y_pred_svm)
acc_dt     = accuracy_score(y_test, y_pred_dt)

print("Accuracies:")
print(f"Logistic Regression: {acc_logreg:.4f}")
print(f"SVM: {acc_svm:.4f}")
print(f"Decision Tree: {acc_dt:.4f}")
import matplotlib.pyplot as plt

model_acc = {
    "Logistic Regression": acc_logreg,
    "SVM": acc_svm,
    "Decision Tree": acc_dt
}

plt.figure(figsize=(8,5))
plt.bar(model_acc.keys(), model_acc.values(), color=['skyblue','orange','green'])
plt.ylim(0, 1)
plt.ylabel("Accuracy")
plt.title("Model Accuracy Comparison")
for i, v in enumerate(model_acc.values()):
    plt.text(i, v + 0.01, f"{v:.2f}", ha='center', fontweight='bold')
#plt.show()
import matplotlib.pyplot as plt

accuracy_logreg = 0.9289914066033469
f1_logreg = 0.94   
# Create dictionary for plotting
metrics = {
    "Logistic Regression": {"Accuracy": accuracy_logreg, "F1-Score": f1_logreg},
    # Add SVM / Decision Tree later
}

# Convert to two lists
models = list(metrics.keys())
accuracy = [metrics[m]["Accuracy"] for m in models]
f1score  = [metrics[m]["F1-Score"] for m in models]

# Plot
import numpy as np
x = np.arange(len(models))
width = 0.35

fig, ax = plt.subplots(figsize=(8,5))
rects1 = ax.bar(x - width/2, accuracy, width, label='Accuracy', color='skyblue')
rects2 = ax.bar(x + width/2, f1score, width, label='F1-Score', color='orange')

ax.set_ylabel('Score')
ax.set_ylim(0, 1)
ax.set_title('Logistic Regression Metrics')
ax.set_xticks(x)
ax.set_xticklabels(models)
ax.legend()

# Add text labels on top of bars
for rects in [rects1, rects2]:
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height:.2f}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0,3),
                    textcoords="offset points",
                    ha='center', va='bottom')

#plt.show()
import matplotlib.pyplot as plt

# Metrics for SVM
metrics = {
    "Accuracy": 0.9507,
    "Precision (-1)": 0.96,
    "Recall (-1)": 0.93,
    "F1-Score (-1)": 0.94,
    "Precision (1)": 0.94,
    "Recall (1)": 0.97,
    "F1-Score (1)": 0.96,
    "False Positives": 36/1500,  # scaled to 0-1 for line graph
    "False Negatives": 73/1500   # scaled to 0-1 for line graph
}

labels = list(metrics.keys())
values = list(metrics.values())
plt.figure(figsize=(12,6))
plt.plot(labels, values, marker='o', linestyle='-', color='blue', linewidth=2)

plt.title("SVM Model Metrics Overview (scaled)")
plt.ylabel("Score / Scaled Count")
plt.ylim(0, 1.05)
plt.xticks(rotation=45, ha='right')

# Add values on top of points
for i, v in enumerate(values):
    plt.text(i, v + 0.02, f"{v:.2f}", ha='center', fontweight='bold')

plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
#plt.show()
import matplotlib.pyplot as plt

# SVM metrics
svm_metrics = {
    "Accuracy": 0.9507,
    "Precision (-1)": 0.96,
    "Recall (-1)": 0.93,
    "F1-Score (-1)": 0.94,
    "Precision (1)": 0.94,
    "Recall (1)": 0.97,
    "F1-Score (1)": 0.96,
    "False Positives": 36/1500,  # scaled for line plot
    "False Negatives": 73/1500
}

# Decision Tree metrics
dt_metrics = {
    "Accuracy": 0.9516,
    "Precision (-1)": 0.95,
    "Recall (-1)": 0.94,
    "F1-Score (-1)": 0.95,
    "Precision (1)": 0.96,
    "Recall (1)": 0.96,
    "F1-Score (1)": 0.96,
    "False Positives": 52/1500,
    "False Negatives": 55/1500
}

labels = list(svm_metrics.keys())
plt.figure(figsize=(12,6))

# SVM line
#plt.plot(labels, list(svm_metrics.values()), marker='o', linestyle='-', color='blue', linewidth=2, label='SVM')

# Decision Tree line
plt.plot(labels, list(dt_metrics.values()), marker='o', linestyle='-', color='green', linewidth=2, label='Decision Tree')

plt.title("Decision Tree Metrics")
plt.ylabel("Score / Scaled Count")
plt.ylim(0, 1.05)
plt.xticks(rotation=45, ha='right')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()

# Add value labels on top of points
for i, label in enumerate(labels):
    #plt.text(i, svm_metrics[label]+0.02, f"{svm_metrics[label]:.2f}", color='blue', ha='center', fontweight='bold')
    plt.text(i, dt_metrics[label]+0.02, f"{dt_metrics[label]:.2f}", color='green', ha='center', fontweight='bold')

plt.tight_layout()
#plt.show()
from sklearn.ensemble import VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

# Logistic Regression pipeline (with scaling)
logreg_pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("logreg", LogisticRegression(class_weight='balanced', max_iter=1000))
])

# SVM pipeline (with scaling)
svm_pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("svc", SVC(kernel='rbf', C=1, gamma='scale', probability=True))
])

# Decision Tree (no scaling needed)
dt_model = DecisionTreeClassifier(random_state=42)

# Create ensemble voting classifier
ensemble_model = VotingClassifier(
    estimators=[
        ('logreg', logreg_pipeline),
        ('svm', svm_pipeline),
        ('dt', dt_model)
    ],
    voting='soft'  # use 'soft' to use predicted probabilities, better for balanced datasets
)
ensemble_model.fit(X_train, y_train)
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Predict
y_pred_ensemble = ensemble_model.predict(X_test)

# Accuracy
acc_ensemble = accuracy_score(y_test, y_pred_ensemble)
print("Ensemble Accuracy:", acc_ensemble)

# Full classification report
print(classification_report(y_test, y_pred_ensemble))

# Confusion matrix
print(confusion_matrix(y_test, y_pred_ensemble))
import joblib

joblib.dump(ensemble_model, "ensemble_phishing_model.pkl")
import pandas as pd
path = r"C:\Users\DELL\Desktop\Phishing_Detection\dataset\phishing.csv"
df = pd.read_csv(path)
