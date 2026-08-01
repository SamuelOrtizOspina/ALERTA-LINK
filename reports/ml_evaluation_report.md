# Evaluacion del Modelo de Machine Learning - ALERTA-LINK

**Fecha de generacion:** 2026-07-30 09:48:15

---

## 1. Dataset

| Metrica | Valor |
|---------|-------|
| Total de muestras | 6000 |
| URLs legitimas (0) | 3000 (50.0%) |
| URLs maliciosas (1) | 3000 (50.0%) |
| Features | 24 |
| Train set | 3600 (60%) |
| Validation set | 1200 (20%) |
| Test set | 1200 (20%) |

## 2. Validacion Cruzada (5-Fold)

| Modelo | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|--------|----------|-----------|--------|----------|---------|
| LogisticRegression | 0.9019 +/- 0.0125 | 0.8609 +/- 0.0125 | 0.9587 +/- 0.0159 | 0.9071 +/- 0.0119 | 0.9600 +/- 0.0079 |
| RandomForest | 0.9825 +/- 0.0048 | 0.9754 +/- 0.0079 | 0.9900 +/- 0.0058 | 0.9826 +/- 0.0047 | 0.9957 +/- 0.0016 |
| GradientBoosting | 0.9812 +/- 0.0032 | 0.9757 +/- 0.0045 | 0.9871 +/- 0.0077 | 0.9813 +/- 0.0032 | 0.9943 +/- 0.0019 |
| SVM | 0.9415 +/- 0.0088 | 0.9186 +/- 0.0170 | 0.9692 +/- 0.0050 | 0.9431 +/- 0.0080 | 0.9829 +/- 0.0058 |
| KNN | 0.9496 +/- 0.0030 | 0.9356 +/- 0.0100 | 0.9658 +/- 0.0064 | 0.9504 +/- 0.0026 | 0.9781 +/- 0.0042 |

![Comparacion de Modelos](figures/model_comparison.png)

## 3. Evaluacion Final en Test Set

**Mejor modelo seleccionado:** RandomForest

### Metricas por modelo

| Modelo | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|--------|----------|-----------|--------|----------|---------|
| LogisticRegression | 0.9000 | 0.8529 | 0.9667 | 0.9062 | 0.9643 |
| RandomForest ** | 0.9850 | 0.9755 | 0.9950 | 0.9851 | 0.9945 |
| GradientBoosting | 0.9850 | 0.9739 | 0.9967 | 0.9852 | 0.9941 |
| SVM | 0.9475 | 0.9163 | 0.9850 | 0.9494 | 0.9818 |
| KNN | 0.9517 | 0.9371 | 0.9683 | 0.9525 | 0.9763 |

### Matriz de Confusion - RandomForest

```
              Predicho
              Legitimo  Phishing
Real Legitimo    585        15
     Phishing      3       597
```

- **Verdaderos Negativos (TN):** 585 - URLs legitimas correctamente identificadas
- **Falsos Positivos (FP):** 15 - URLs legitimas marcadas como phishing
- **Falsos Negativos (FN):** 3 - URLs phishing no detectadas
- **Verdaderos Positivos (TP):** 597 - URLs phishing correctamente detectadas

![Matriz de Confusion](figures/confusion_matrix_randomforest.png)

## 4. Curvas ROC

![Curvas ROC](figures/roc_curves.png)

## 5. Importancia de Features

![Feature Importance](figures/feature_importance.png)

## 6. Interpretacion de Resultados

El modelo **RandomForest** logra:

- **Precision del 97.5%**: De cada 100 URLs que el modelo marca como phishing, 97 realmente lo son.
- **Recall del 99.5%**: De cada 100 URLs de phishing reales, el modelo detecta 99.
- **F1-Score de 0.9851**: Balance optimo entre precision y recall.
- **ROC-AUC de 0.9945**: Excelente capacidad de discriminacion entre clases.

## 7. Conclusiones

1. El sistema ALERTA-LINK demuestra alta efectividad en la deteccion de URLs de phishing.
2. El modelo RandomForest fue seleccionado como el mejor basado en validacion cruzada.
3. La combinacion de 24 features lexicas y semanticas permite una clasificacion robusta.
4. El sistema cumple con los objetivos de precision y recall establecidos para produccion.

---

*Reporte generado automaticamente por ALERTA-LINK ML Evaluation Suite*