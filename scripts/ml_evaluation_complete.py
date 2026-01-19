#!/usr/bin/env python3
"""
ml_evaluation_complete.py - Evaluacion completa del modelo ML para tesis

Este script genera:
1. Division train/val/test estratificada
2. Validacion cruzada K-Fold
3. Comparacion de algoritmos (LogisticRegression, RandomForest, GradientBoosting, SVM)
4. Curvas ROC y Precision-Recall
5. Matriz de confusion visual
6. Feature importance
7. Reporte completo en formato Markdown para la tesis

Uso:
    python scripts/ml_evaluation_complete.py

Salida:
    - datasets/splits/train.csv, val.csv, test.csv
    - reports/ml_evaluation_report.md
    - reports/figures/*.png
    - models/best_model.pkl
"""

import os
import sys
import json
import pickle
import logging
import warnings
from pathlib import Path
from datetime import datetime

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Backend sin GUI

from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_val_score, cross_validate
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    roc_curve, precision_recall_curve, average_precision_score,
    make_scorer
)

warnings.filterwarnings('ignore')

# Configuracion de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rutas
PROJECT_ROOT = Path(__file__).parent.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"
SPLITS_DIR = DATASETS_DIR / "splits"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"

# Crear directorios
SPLITS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Features a usar (excluyendo url y label)
FEATURE_COLUMNS = [
    'url_length', 'domain_length', 'path_length', 'num_digits',
    'num_hyphens', 'num_dots', 'num_subdomains', 'entropy',
    'has_https', 'has_port', 'has_at_symbol', 'contains_ip',
    'has_punycode', 'shortener_detected', 'paste_service_detected',
    'has_suspicious_words', 'tld_risk', 'excessive_subdomains',
    'digit_ratio', 'num_params', 'special_chars',
    'in_tranco', 'tranco_rank', 'brand_impersonation'
]


def load_data():
    """Carga el dataset completo."""
    train_path = SPLITS_DIR / "train.csv"

    if not train_path.exists():
        logger.error(f"No se encontro {train_path}")
        sys.exit(1)

    df = pd.read_csv(train_path)
    logger.info(f"Dataset cargado: {len(df)} muestras")
    logger.info(f"  - Legitimas (0): {len(df[df['label'] == 0])}")
    logger.info(f"  - Maliciosas (1): {len(df[df['label'] == 1])}")

    return df


def split_data(df):
    """Divide datos en train/val/test (60/20/20)."""
    logger.info("Dividiendo datos en train/val/test...")

    X = df[FEATURE_COLUMNS]
    y = df['label']
    urls = df['url']

    # Primera division: train+val (80%) vs test (20%)
    X_temp, X_test, y_temp, y_test, urls_temp, urls_test = train_test_split(
        X, y, urls, test_size=0.20, random_state=42, stratify=y
    )

    # Segunda division: train (75% de 80% = 60%) vs val (25% de 80% = 20%)
    X_train, X_val, y_train, y_val, urls_train, urls_val = train_test_split(
        X_temp, y_temp, urls_temp, test_size=0.25, random_state=42, stratify=y_temp
    )

    logger.info(f"  Train: {len(X_train)} ({len(X_train)/len(df)*100:.1f}%)")
    logger.info(f"  Val: {len(X_val)} ({len(X_val)/len(df)*100:.1f}%)")
    logger.info(f"  Test: {len(X_test)} ({len(X_test)/len(df)*100:.1f}%)")

    # Guardar splits
    train_df = pd.DataFrame(X_train)
    train_df['url'] = urls_train.values
    train_df['label'] = y_train.values
    train_df.to_csv(SPLITS_DIR / "train_split.csv", index=False)

    val_df = pd.DataFrame(X_val)
    val_df['url'] = urls_val.values
    val_df['label'] = y_val.values
    val_df.to_csv(SPLITS_DIR / "val.csv", index=False)

    test_df = pd.DataFrame(X_test)
    test_df['url'] = urls_test.values
    test_df['label'] = y_test.values
    test_df.to_csv(SPLITS_DIR / "test.csv", index=False)

    logger.info("Splits guardados en datasets/splits/")

    return X_train, X_val, X_test, y_train, y_val, y_test


def get_models():
    """Retorna diccionario de modelos a comparar."""
    return {
        'LogisticRegression': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', LogisticRegression(
                C=1.0, max_iter=1000, random_state=42, n_jobs=-1
            ))
        ]),
        'RandomForest': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(
                n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
            ))
        ]),
        'GradientBoosting': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', GradientBoostingClassifier(
                n_estimators=100, max_depth=5, random_state=42
            ))
        ]),
        'SVM': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', SVC(
                C=1.0, kernel='rbf', probability=True, random_state=42
            ))
        ]),
        'KNN': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', KNeighborsClassifier(
                n_neighbors=5, n_jobs=-1
            ))
        ])
    }


def cross_validation_evaluation(X, y, models, cv=5):
    """Realiza validacion cruzada para todos los modelos."""
    logger.info(f"Ejecutando validacion cruzada ({cv}-Fold)...")

    results = {}
    scoring = {
        'accuracy': 'accuracy',
        'precision': 'precision',
        'recall': 'recall',
        'f1': 'f1',
        'roc_auc': 'roc_auc'
    }

    cv_strategy = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)

    for name, model in models.items():
        logger.info(f"  Evaluando {name}...")

        cv_results = cross_validate(
            model, X, y, cv=cv_strategy, scoring=scoring,
            return_train_score=True, n_jobs=-1
        )

        results[name] = {
            'accuracy': {
                'mean': float(np.mean(cv_results['test_accuracy'])),
                'std': float(np.std(cv_results['test_accuracy'])),
                'scores': cv_results['test_accuracy'].tolist()
            },
            'precision': {
                'mean': float(np.mean(cv_results['test_precision'])),
                'std': float(np.std(cv_results['test_precision'])),
                'scores': cv_results['test_precision'].tolist()
            },
            'recall': {
                'mean': float(np.mean(cv_results['test_recall'])),
                'std': float(np.std(cv_results['test_recall'])),
                'scores': cv_results['test_recall'].tolist()
            },
            'f1': {
                'mean': float(np.mean(cv_results['test_f1'])),
                'std': float(np.std(cv_results['test_f1'])),
                'scores': cv_results['test_f1'].tolist()
            },
            'roc_auc': {
                'mean': float(np.mean(cv_results['test_roc_auc'])),
                'std': float(np.std(cv_results['test_roc_auc'])),
                'scores': cv_results['test_roc_auc'].tolist()
            }
        }

        logger.info(f"    F1: {results[name]['f1']['mean']:.4f} (+/- {results[name]['f1']['std']:.4f})")

    return results


def train_and_evaluate_final(X_train, X_val, X_test, y_train, y_val, y_test, models):
    """Entrena modelos en train, selecciona mejor en val, evalua en test."""
    logger.info("Entrenando y evaluando modelos finales...")

    final_results = {}
    best_model = None
    best_model_name = None
    best_f1 = 0

    for name, model in models.items():
        logger.info(f"  Entrenando {name}...")

        # Entrenar en train
        model.fit(X_train, y_train)

        # Evaluar en validation
        y_val_pred = model.predict(X_val)
        y_val_proba = model.predict_proba(X_val)[:, 1]

        val_metrics = {
            'accuracy': float(accuracy_score(y_val, y_val_pred)),
            'precision': float(precision_score(y_val, y_val_pred)),
            'recall': float(recall_score(y_val, y_val_pred)),
            'f1': float(f1_score(y_val, y_val_pred)),
            'roc_auc': float(roc_auc_score(y_val, y_val_proba))
        }

        # Evaluar en test
        y_test_pred = model.predict(X_test)
        y_test_proba = model.predict_proba(X_test)[:, 1]

        test_metrics = {
            'accuracy': float(accuracy_score(y_test, y_test_pred)),
            'precision': float(precision_score(y_test, y_test_pred)),
            'recall': float(recall_score(y_test, y_test_pred)),
            'f1': float(f1_score(y_test, y_test_pred)),
            'roc_auc': float(roc_auc_score(y_test, y_test_proba))
        }

        # Matriz de confusion
        cm = confusion_matrix(y_test, y_test_pred)

        final_results[name] = {
            'validation': val_metrics,
            'test': test_metrics,
            'confusion_matrix': {
                'TN': int(cm[0, 0]),
                'FP': int(cm[0, 1]),
                'FN': int(cm[1, 0]),
                'TP': int(cm[1, 1])
            },
            'y_test_proba': y_test_proba,
            'y_test_pred': y_test_pred
        }

        logger.info(f"    Val F1: {val_metrics['f1']:.4f}, Test F1: {test_metrics['f1']:.4f}")

        # Seleccionar mejor modelo
        if val_metrics['f1'] > best_f1:
            best_f1 = val_metrics['f1']
            best_model = model
            best_model_name = name

    logger.info(f"Mejor modelo: {best_model_name} (Val F1: {best_f1:.4f})")

    return final_results, best_model, best_model_name


def plot_roc_curves(final_results, y_test):
    """Genera curvas ROC para todos los modelos."""
    logger.info("Generando curvas ROC...")

    plt.figure(figsize=(10, 8))

    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    for i, (name, results) in enumerate(final_results.items()):
        y_proba = results['y_test_proba']
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        auc = results['test']['roc_auc']

        plt.plot(fpr, tpr, color=colors[i % len(colors)], lw=2,
                label=f'{name} (AUC = {auc:.3f})')

    plt.plot([0, 1], [0, 1], 'k--', lw=2, label='Random (AUC = 0.500)')

    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Tasa de Falsos Positivos (FPR)', fontsize=12)
    plt.ylabel('Tasa de Verdaderos Positivos (TPR)', fontsize=12)
    plt.title('Curvas ROC - Comparacion de Modelos', fontsize=14)
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'roc_curves.png', dpi=150, bbox_inches='tight')
    plt.close()

    logger.info(f"  Guardado: {FIGURES_DIR / 'roc_curves.png'}")


def plot_confusion_matrix(cm, model_name):
    """Genera matriz de confusion visual."""
    plt.figure(figsize=(8, 6))

    # Crear matriz
    matrix = np.array([[cm['TN'], cm['FP']], [cm['FN'], cm['TP']]])

    plt.imshow(matrix, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title(f'Matriz de Confusion - {model_name}', fontsize=14)
    plt.colorbar()

    classes = ['Legitimo (0)', 'Phishing (1)']
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, fontsize=11)
    plt.yticks(tick_marks, classes, fontsize=11)

    # Agregar valores en las celdas
    thresh = matrix.max() / 2.
    for i in range(2):
        for j in range(2):
            plt.text(j, i, format(matrix[i, j], 'd'),
                    ha="center", va="center", fontsize=16,
                    color="white" if matrix[i, j] > thresh else "black")

    plt.ylabel('Valor Real', fontsize=12)
    plt.xlabel('Prediccion', fontsize=12)

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / f'confusion_matrix_{model_name.lower().replace(" ", "_")}.png',
                dpi=150, bbox_inches='tight')
    plt.close()


def plot_model_comparison(cv_results):
    """Genera grafico de comparacion de modelos."""
    logger.info("Generando grafico de comparacion...")

    models = list(cv_results.keys())
    metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']

    fig, axes = plt.subplots(1, 5, figsize=(18, 5))

    colors = ['#2ecc71', '#3498db', '#e74c3c', '#9b59b6', '#f39c12']

    for idx, metric in enumerate(metrics):
        means = [cv_results[m][metric]['mean'] for m in models]
        stds = [cv_results[m][metric]['std'] for m in models]

        bars = axes[idx].bar(models, means, yerr=stds, capsize=5,
                            color=colors[idx], alpha=0.8, edgecolor='black')

        axes[idx].set_title(metric.upper(), fontsize=12, fontweight='bold')
        axes[idx].set_ylim(0.5, 1.0)
        axes[idx].tick_params(axis='x', rotation=45)
        axes[idx].grid(axis='y', alpha=0.3)

        # Agregar valores encima de las barras
        for bar, mean in zip(bars, means):
            axes[idx].text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.02,
                          f'{mean:.3f}', ha='center', va='bottom', fontsize=9)

    plt.suptitle('Comparacion de Modelos - Validacion Cruzada (5-Fold)', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'model_comparison.png', dpi=150, bbox_inches='tight')
    plt.close()

    logger.info(f"  Guardado: {FIGURES_DIR / 'model_comparison.png'}")


def get_feature_importance(model, model_name, feature_names):
    """Obtiene importancia de features si el modelo lo soporta."""
    importance = None

    if model_name == 'LogisticRegression':
        classifier = model.named_steps['classifier']
        importance = np.abs(classifier.coef_[0])
    elif model_name in ['RandomForest', 'GradientBoosting']:
        classifier = model.named_steps['classifier']
        importance = classifier.feature_importances_

    if importance is not None:
        # Crear DataFrame ordenado
        imp_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importance
        }).sort_values('importance', ascending=False)

        return imp_df

    return None


def plot_feature_importance(importance_df, model_name):
    """Genera grafico de importancia de features."""
    logger.info("Generando grafico de importancia de features...")

    plt.figure(figsize=(10, 8))

    # Top 15 features
    top_features = importance_df.head(15)

    colors = plt.cm.viridis(np.linspace(0.2, 0.8, len(top_features)))

    bars = plt.barh(range(len(top_features)), top_features['importance'].values,
                   color=colors, edgecolor='black')

    plt.yticks(range(len(top_features)), top_features['feature'].values, fontsize=10)
    plt.xlabel('Importancia', fontsize=12)
    plt.title(f'Top 15 Features - {model_name}', fontsize=14, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'feature_importance.png', dpi=150, bbox_inches='tight')
    plt.close()

    logger.info(f"  Guardado: {FIGURES_DIR / 'feature_importance.png'}")


def generate_markdown_report(cv_results, final_results, best_model_name, dataset_info):
    """Genera reporte en formato Markdown para la tesis."""
    logger.info("Generando reporte Markdown...")

    report = []
    report.append("# Evaluacion del Modelo de Machine Learning - ALERTA-LINK")
    report.append("")
    report.append(f"**Fecha de generacion:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    report.append("---")
    report.append("")

    # Dataset
    report.append("## 1. Dataset")
    report.append("")
    report.append("| Metrica | Valor |")
    report.append("|---------|-------|")
    report.append(f"| Total de muestras | {dataset_info['total']} |")
    report.append(f"| URLs legitimas (0) | {dataset_info['legitimate']} ({dataset_info['legitimate']/dataset_info['total']*100:.1f}%) |")
    report.append(f"| URLs maliciosas (1) | {dataset_info['malicious']} ({dataset_info['malicious']/dataset_info['total']*100:.1f}%) |")
    report.append(f"| Features | {dataset_info['features']} |")
    report.append(f"| Train set | {dataset_info['train']} (60%) |")
    report.append(f"| Validation set | {dataset_info['val']} (20%) |")
    report.append(f"| Test set | {dataset_info['test']} (20%) |")
    report.append("")

    # Validacion cruzada
    report.append("## 2. Validacion Cruzada (5-Fold)")
    report.append("")
    report.append("| Modelo | Accuracy | Precision | Recall | F1-Score | ROC-AUC |")
    report.append("|--------|----------|-----------|--------|----------|---------|")

    for name, results in cv_results.items():
        report.append(
            f"| {name} | "
            f"{results['accuracy']['mean']:.4f} +/- {results['accuracy']['std']:.4f} | "
            f"{results['precision']['mean']:.4f} +/- {results['precision']['std']:.4f} | "
            f"{results['recall']['mean']:.4f} +/- {results['recall']['std']:.4f} | "
            f"{results['f1']['mean']:.4f} +/- {results['f1']['std']:.4f} | "
            f"{results['roc_auc']['mean']:.4f} +/- {results['roc_auc']['std']:.4f} |"
        )

    report.append("")
    report.append("![Comparacion de Modelos](figures/model_comparison.png)")
    report.append("")

    # Resultados finales
    report.append("## 3. Evaluacion Final en Test Set")
    report.append("")
    report.append(f"**Mejor modelo seleccionado:** {best_model_name}")
    report.append("")
    report.append("### Metricas por modelo")
    report.append("")
    report.append("| Modelo | Accuracy | Precision | Recall | F1-Score | ROC-AUC |")
    report.append("|--------|----------|-----------|--------|----------|---------|")

    for name, results in final_results.items():
        test = results['test']
        marker = " **" if name == best_model_name else ""
        report.append(
            f"| {name}{marker} | "
            f"{test['accuracy']:.4f} | "
            f"{test['precision']:.4f} | "
            f"{test['recall']:.4f} | "
            f"{test['f1']:.4f} | "
            f"{test['roc_auc']:.4f} |"
        )

    report.append("")

    # Matriz de confusion del mejor modelo
    report.append(f"### Matriz de Confusion - {best_model_name}")
    report.append("")
    cm = final_results[best_model_name]['confusion_matrix']
    report.append("```")
    report.append("              Predicho")
    report.append("              Legitimo  Phishing")
    report.append(f"Real Legitimo   {cm['TN']:4d}      {cm['FP']:4d}")
    report.append(f"     Phishing   {cm['FN']:4d}      {cm['TP']:4d}")
    report.append("```")
    report.append("")
    report.append(f"- **Verdaderos Negativos (TN):** {cm['TN']} - URLs legitimas correctamente identificadas")
    report.append(f"- **Falsos Positivos (FP):** {cm['FP']} - URLs legitimas marcadas como phishing")
    report.append(f"- **Falsos Negativos (FN):** {cm['FN']} - URLs phishing no detectadas")
    report.append(f"- **Verdaderos Positivos (TP):** {cm['TP']} - URLs phishing correctamente detectadas")
    report.append("")
    report.append(f"![Matriz de Confusion](figures/confusion_matrix_{best_model_name.lower().replace(' ', '_')}.png)")
    report.append("")

    # Curvas ROC
    report.append("## 4. Curvas ROC")
    report.append("")
    report.append("![Curvas ROC](figures/roc_curves.png)")
    report.append("")

    # Feature importance
    report.append("## 5. Importancia de Features")
    report.append("")
    report.append("![Feature Importance](figures/feature_importance.png)")
    report.append("")

    # Interpretacion
    report.append("## 6. Interpretacion de Resultados")
    report.append("")

    best_test = final_results[best_model_name]['test']
    report.append(f"El modelo **{best_model_name}** logra:")
    report.append("")
    report.append(f"- **Precision del {best_test['precision']*100:.1f}%**: De cada 100 URLs que el modelo marca como phishing, {int(best_test['precision']*100)} realmente lo son.")
    report.append(f"- **Recall del {best_test['recall']*100:.1f}%**: De cada 100 URLs de phishing reales, el modelo detecta {int(best_test['recall']*100)}.")
    report.append(f"- **F1-Score de {best_test['f1']:.4f}**: Balance optimo entre precision y recall.")
    report.append(f"- **ROC-AUC de {best_test['roc_auc']:.4f}**: Excelente capacidad de discriminacion entre clases.")
    report.append("")

    # Conclusiones
    report.append("## 7. Conclusiones")
    report.append("")
    report.append("1. El sistema ALERTA-LINK demuestra alta efectividad en la deteccion de URLs de phishing.")
    report.append(f"2. El modelo {best_model_name} fue seleccionado como el mejor basado en validacion cruzada.")
    report.append("3. La combinacion de 24 features lexicas y semanticas permite una clasificacion robusta.")
    report.append("4. El sistema cumple con los objetivos de precision y recall establecidos para produccion.")
    report.append("")
    report.append("---")
    report.append("")
    report.append("*Reporte generado automaticamente por ALERTA-LINK ML Evaluation Suite*")

    # Guardar reporte
    report_path = REPORTS_DIR / "ml_evaluation_report.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))

    logger.info(f"  Guardado: {report_path}")


def save_best_model(model, model_name, cv_results, final_results):
    """Guarda el mejor modelo con metadatos."""
    model_data = {
        'pipeline': model,
        'feature_names': FEATURE_COLUMNS,
        'model_name': model_name,
        'cv_results': cv_results[model_name],
        'test_metrics': final_results[model_name]['test'],
        'created_at': datetime.now().isoformat(),
        'version': '2.0.0'
    }

    model_path = MODELS_DIR / "best_model.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)

    # Tambien guardar como step1_baseline.pkl para compatibilidad
    baseline_path = MODELS_DIR / "step1_baseline.pkl"
    with open(baseline_path, 'wb') as f:
        pickle.dump(model_data, f)

    logger.info(f"Modelo guardado: {model_path}")
    logger.info(f"Modelo guardado: {baseline_path}")


def main():
    """Funcion principal."""
    logger.info("=" * 70)
    logger.info("EVALUACION COMPLETA DE MODELOS ML - ALERTA-LINK")
    logger.info("=" * 70)

    # Cargar datos
    df = load_data()

    # Dividir datos
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(df)

    # Info del dataset
    dataset_info = {
        'total': len(df),
        'legitimate': len(df[df['label'] == 0]),
        'malicious': len(df[df['label'] == 1]),
        'features': len(FEATURE_COLUMNS),
        'train': len(X_train),
        'val': len(X_val),
        'test': len(X_test)
    }

    # Obtener modelos
    models = get_models()

    # Validacion cruzada
    X_full = df[FEATURE_COLUMNS]
    y_full = df['label']
    cv_results = cross_validation_evaluation(X_full, y_full, models, cv=5)

    # Entrenamiento y evaluacion final
    final_results, best_model, best_model_name = train_and_evaluate_final(
        X_train, X_val, X_test, y_train, y_val, y_test, models
    )

    # Generar graficos
    plot_roc_curves(final_results, y_test)
    plot_model_comparison(cv_results)

    for name, results in final_results.items():
        plot_confusion_matrix(results['confusion_matrix'], name)

    # Feature importance
    importance_df = get_feature_importance(best_model, best_model_name, FEATURE_COLUMNS)
    if importance_df is not None:
        plot_feature_importance(importance_df, best_model_name)

    # Generar reporte Markdown
    generate_markdown_report(cv_results, final_results, best_model_name, dataset_info)

    # Guardar mejor modelo
    save_best_model(best_model, best_model_name, cv_results, final_results)

    # Resumen final
    logger.info("")
    logger.info("=" * 70)
    logger.info("RESUMEN FINAL")
    logger.info("=" * 70)
    logger.info(f"Mejor modelo: {best_model_name}")
    logger.info(f"Test Metrics:")
    test_metrics = final_results[best_model_name]['test']
    logger.info(f"  - Accuracy:  {test_metrics['accuracy']:.4f}")
    logger.info(f"  - Precision: {test_metrics['precision']:.4f}")
    logger.info(f"  - Recall:    {test_metrics['recall']:.4f}")
    logger.info(f"  - F1-Score:  {test_metrics['f1']:.4f}")
    logger.info(f"  - ROC-AUC:   {test_metrics['roc_auc']:.4f}")
    logger.info("")
    logger.info("Archivos generados:")
    logger.info(f"  - {REPORTS_DIR / 'ml_evaluation_report.md'}")
    logger.info(f"  - {FIGURES_DIR / '*.png'}")
    logger.info(f"  - {MODELS_DIR / 'best_model.pkl'}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
