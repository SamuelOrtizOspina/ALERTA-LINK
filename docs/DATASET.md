# Dataset - ALERTA-LINK

> Documentacion de las fuentes de datos y construccion del dataset

---

## Estado Actual del Dataset

| Metrica | Valor |
|---------|-------|
| **Total URLs** | 5,000 |
| **Legitimas (0)** | 2,500 (50%) |
| **Maliciosas (1)** | 2,500 (50%) |
| **Verificacion VirusTotal** | 75/75 (100%) |

---

## Fuentes de Datos

### 1. Phishing.Database

| Atributo | Valor |
|----------|-------|
| **Tipo** | Threat intelligence |
| **Formato** | TXT (una URL por linea) |
| **Tamano** | ~789,000+ URLs |
| **Label** | Todas son phishing (1) |
| **Ubicacion** | `Buenos_Datos/Phishing.Database-master/phishing-links-ACTIVE.txt` |

> **Nota**: A pesar del nombre de la carpeta "Buenos_Datos", este archivo contiene URLs de phishing (maliciosas).

### 2. Tranco Top 1 Million

| Atributo | Valor |
|----------|-------|
| **Tipo** | Lista de sitios legitimos |
| **Formato** | Generado dinamicamente via API |
| **Tamano** | Top 100 dominios |
| **Label** | Todas son legitimas (0) |

### 3. VirusTotal API

| Atributo | Valor |
|----------|-------|
| **Tipo** | Verificacion en tiempo real |
| **Uso** | Validar muestras aleatorias |
| **Threshold** | 3+ detecciones = malicioso |

---

## Label Mapping

```json
{
  "0": "legitimo - URL segura",
  "1": "malicioso - phishing/malware/scam"
}
```

### Mapeo por Fuente

| Fuente | Label |
|--------|-------|
| Tranco Top 100 | 0 (legitimo) |
| Phishing.Database | 1 (phishing) |
| URLs verificadas VirusTotal | 1 (confirmado) |

---

## Schema del Dataset de Entrenamiento

El archivo `datasets/splits/train.csv` contiene:

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `url` | string | URL original |
| `label` | int | 0=legitimo, 1=malicioso |
| `url_length` | int | Longitud total |
| `domain_length` | int | Longitud del dominio |
| `path_length` | int | Longitud del path |
| `num_digits` | int | Cantidad de digitos |
| `num_hyphens` | int | Cantidad de guiones |
| `num_dots` | int | Cantidad de puntos |
| `num_subdomains` | int | Subdominios |
| `entropy` | float | Entropia de Shannon |
| `has_https` | binary | Usa HTTPS |
| `has_port` | binary | Puerto custom |
| `has_at_symbol` | binary | Contiene @ |
| `contains_ip` | binary | IP como host |
| `has_punycode` | binary | Caracteres unicode |
| `shortener_detected` | binary | URL acortada |
| `paste_service_detected` | binary | Servicio paste |
| `has_suspicious_words` | int | Palabras sospechosas |
| `tld_risk` | binary | TLD riesgoso |
| `excessive_subdomains` | binary | >3 subdominios |
| `digit_ratio` | float | Proporcion digitos |
| `num_params` | int | Parametros query |
| `special_chars` | int | Caracteres especiales |
| `in_tranco` | binary | En Tranco Top 1M |
| `tranco_rank` | float | Ranking normalizado |
| `brand_impersonation` | binary | Suplanta marca |

**Total: 24 features + url + label = 26 columnas**

---

## Construccion del Dataset

### Comando Principal
```bash
python scripts/build_large_dataset.py
```

### Script de Expansion
```bash
python scripts/expand_dataset_500.py
```

### Proceso
1. Selecciona URLs aleatorias de Phishing.Database
2. Verifica muestra con VirusTotal (100% confirmadas)
3. Genera URLs legitimas de Tranco Top 100
4. Extrae 24 features de cada URL
5. Balancea clases (50/50)
6. Genera train.csv

### Archivos Generados
- `datasets/splits/train.csv` - Dataset de entrenamiento (5,000 URLs)
- `datasets/splits/val.csv` - Set de validacion (800 URLs)
- `datasets/splits/test.csv` - Set de prueba (800 URLs)

---

## Historial de Expansiones

| Fecha | URLs Iniciales | URLs Finales | Verificacion VT |
|-------|----------------|--------------|-----------------|
| 2026-01-08 | 0 | 4,000 | 15/15 (100%) |
| 2026-01-09 | 4,000 | 4,500 | 25/25 (100%) |
| 2026-01-09 | 4,500 | 5,000 | 25/25 (100%) |

---

## Balance de Clases

```
Clase 0 (legitimas):  2,500 URLs (50%)
Clase 1 (phishing):   2,500 URLs (50%)
                      ================
Total:                5,000 URLs (100%)
```

El dataset esta perfectamente balanceado, no requiere oversampling/undersampling.

---

## Verificacion de Calidad

### VirusTotal
- Se verifico una muestra aleatoria de 75 URLs de phishing
- 100% fueron confirmadas como maliciosas por VirusTotal
- Threshold: 3+ detecciones de antivirus

### Tranco
- URLs legitimas provienen del Top 100 global
- Sitios verificados: google.com, facebook.com, youtube.com, etc.
- No se incluyen paste services ni URL shorteners

---

## Regenerar Dataset

Para regenerar desde cero:

```bash
# 1. Construir dataset base (4,000 URLs)
python scripts/build_large_dataset.py

# 2. Expandir con 500 URLs adicionales (3 veces)
python scripts/expand_dataset_500.py
python scripts/expand_dataset_500.py
python scripts/expand_dataset_500.py

# 3. Reentrenar modelo
python scripts/train_step1.py

# 4. Evaluar
python scripts/evaluate_step1.py
```

---

**Ultima actualizacion:** 2026-01-09
