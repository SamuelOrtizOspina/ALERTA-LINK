# Entrenamiento Step 1 - Baseline

> Pipeline de entrenamiento del modelo LogisticRegression para deteccion de phishing

---

## Estado Actual del Modelo

| Metrica | Valor |
|---------|-------|
| **Accuracy** | 1.0000 |
| **Precision** | 1.0000 |
| **Recall** | 1.0000 |
| **F1-Score** | 1.0000 |
| **ROC-AUC** | 1.0000 |
| **Dataset** | 5,000 URLs |

---

## Objetivo

Entrenar un modelo baseline simple y explicable que:
1. Clasifique URLs como legitimas (0) o maliciosas (1)
2. Genere un score de riesgo 0-100
3. Proporcione senales explicables
4. Funcione en tiempo real (<100ms)

---

## Features del Modelo (24 total)

### Features Lexicas (8)

| Feature | Descripcion | Tipo |
|---------|-------------|------|
| `url_length` | Longitud total de la URL | int |
| `domain_length` | Longitud del dominio | int |
| `path_length` | Longitud del path | int |
| `num_digits` | Cantidad de digitos | int |
| `num_hyphens` | Cantidad de guiones | int |
| `num_dots` | Cantidad de puntos | int |
| `num_subdomains` | Cantidad de subdominios | int |
| `entropy` | Entropia de Shannon de la URL | float |

### Features Binarias (10)

| Feature | Descripcion | Tipo |
|---------|-------------|------|
| `has_https` | Usa HTTPS | 0/1 |
| `has_port` | Tiene puerto explicito | 0/1 |
| `has_at_symbol` | Contiene @ | 0/1 |
| `contains_ip` | Host es IP (no dominio) | 0/1 |
| `has_punycode` | Tiene xn-- (punycode) | 0/1 |
| `shortener_detected` | Es URL shortener | 0/1 |
| `paste_service_detected` | Es paste service | 0/1 |
| `tld_risk` | TLD de alto riesgo | 0/1 |
| `excessive_subdomains` | Mas de 3 subdominios | 0/1 |
| `in_tranco` | Dominio en Tranco Top 1M | 0/1 |

### Features Numericas (5)

| Feature | Descripcion | Tipo |
|---------|-------------|------|
| `has_suspicious_words` | Palabras sospechosas | int 0-10 |
| `digit_ratio` | Ratio de digitos en URL | float |
| `num_params` | Parametros en query string | int |
| `special_chars` | Caracteres especiales | int |
| `tranco_rank` | Ranking Tranco normalizado | float |

### Feature de Deteccion (1)

| Feature | Descripcion | Tipo |
|---------|-------------|------|
| `brand_impersonation` | Suplanta marca conocida | 0/1 |

---

## Modelo

### Algoritmo
**LogisticRegression** de scikit-learn con StandardScaler

### Hiperparametros
```python
LogisticRegression(
    C=0.5,
    max_iter=1000,
    random_state=42,
    solver='lbfgs',
    verbose=1,
    n_jobs=-1
)
```

### Pipeline
```python
Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', LogisticRegression(...))
])
```

---

## Entrenamiento

### Comando
```bash
python scripts/train_step1.py
```

### Requisitos Previos
1. Dataset en `datasets/splits/train.csv` (5,000 URLs)
2. Entorno virtual activado con dependencias

### Salida
- `models/step1_baseline.pkl` - Modelo serializado
- `models/best_model.pkl` - Copia como modelo principal

El archivo .pkl contiene:
```python
{
    'pipeline': Pipeline,        # scaler + classifier
    'feature_names': list,       # 24 nombres
    'created_at': str,           # Timestamp
    'version': '1.0.0'
}
```

---

## Evaluacion

### Comando
```bash
python scripts/evaluate_step1.py
```

### Resultados Actuales

**Confusion Matrix (Test set - 800 URLs):**
```
         Predicho
          0    1
Real 0  400    0   (TN=400, FP=0)
     1    0  400   (FN=0, TP=400)
```

**Features Mas Importantes:**
| Feature | Coeficiente | Interpretacion |
|---------|-------------|----------------|
| digit_ratio | +4.20 | Muchos digitos = sospechoso |
| has_https | -3.01 | HTTPS = seguro |
| domain_length | +2.83 | Dominio largo = sospechoso |
| num_hyphens | +1.76 | Guiones = sospechoso |
| num_dots | +1.72 | Puntos = sospechoso |

### Salida
- `reports/step1_metrics.json` - Metricas completas

---

## Senales Explicables

El modelo genera senales basadas en features y heuristicas:

| ID | Severidad | Peso | Descripcion |
|----|-----------|------|-------------|
| BRAND_IMPERSONATION | HIGH | 40 | Suplanta marca conocida |
| IP_AS_HOST | HIGH | 25 | URL usa IP en lugar de dominio |
| PUNYCODE_DETECTED | HIGH | 20 | Dominio con punycode |
| PASTE_SERVICE | MEDIUM | 20 | Servicio de paste |
| AT_SYMBOL | MEDIUM | 15 | Contiene @ |
| URL_SHORTENER | MEDIUM | 15 | Servicio de acortamiento |
| DOMAIN_NOT_IN_TRANCO | MEDIUM | 15 | Dominio no verificado |
| RISKY_TLD | MEDIUM | 10-15 | TLD sospechoso |
| EXCESSIVE_SUBDOMAINS | MEDIUM | 10 | Muchos subdominios |
| SUSPICIOUS_WORDS | MEDIUM | 7-25 | Palabras de phishing |
| LONG_URL | LOW | 5 | URL muy larga |
| NO_HTTPS | LOW | 5 | Sin conexion segura |
| HIGH_DIGIT_RATIO | LOW | 5 | Muchos numeros |

---

## Score de Riesgo

El score 0-100 se calcula combinando ML y heuristicas:

### Algoritmo
```
1. score_ml = probabilidad_clase_1 * 100
2. score_heuristic = suma(peso_senales)
3. score_base = max(score_ml, score_heuristic)
4. Si senal critica: score += critical_boost
5. Si dominio en Tranco: score -= 30
6. Si score 30-70: consultar VirusTotal
7. score_final = clamp(score, 0, 100)
```

### Niveles de Riesgo

| Score | Nivel | Color | Accion |
|-------|-------|-------|--------|
| 0-30 | LOW | Verde | Seguro |
| 31-70 | MEDIUM | Amarillo | Precaucion |
| 71-100 | HIGH | Rojo | Peligroso |

---

## Umbrales de Decision

Analizados con el dataset de test:

| Umbral | Precision | Recall | Predichos Positivos |
|--------|-----------|--------|---------------------|
| 30% | 99.75% | 100% | 401 |
| 50% | 100% | 100% | 400 |
| 70% | 100% | 100% | 400 |

El modelo tiene excelente rendimiento en todos los umbrales.

---

## Reproducibilidad

Para resultados reproducibles:
- `random_state=42` en todos los splits y modelos
- Usar exactamente el mismo dataset
- Ejecutar scripts en orden:
  1. `build_large_dataset.py`
  2. `train_step1.py`
  3. `evaluate_step1.py`

---

## Proximas Mejoras

1. **Opcional**: Probar XGBoost/LightGBM para comparar
2. **Opcional**: Agregar features de contenido (HTML)
3. **Opcional**: Expandir dataset a 10,000+ URLs

---

**Ultima actualizacion:** 2026-01-09
