# ALERTA-LINK - Prueba Piloto con Usuarios (Fase 5)

**Fecha de creacion:** 2026-01-09
**Version:** 1.0

---

## 1. Objetivo de la Prueba

Validar la usabilidad y efectividad del sistema ALERTA-LINK con usuarios reales antes de su despliegue final.

### Objetivos Especificos
1. Evaluar la facilidad de uso de la interfaz
2. Medir la comprension de los resultados (semaforo + senales)
3. Identificar problemas de usabilidad
4. Recopilar sugerencias de mejora
5. Validar el tiempo de respuesta percibido

---

## 2. Criterios de Seleccion de Participantes

### Perfil Ideal (5-10 participantes)
| Criterio | Descripcion |
|----------|-------------|
| Edad | 18-65 anos |
| Dispositivo | Android 8.0 o superior |
| Experiencia tecnica | Variada (basica a avanzada) |
| Uso de mensajeria | Activo en WhatsApp/SMS |

### Grupos Objetivo
- 2-3 usuarios con conocimiento tecnico basico
- 2-3 usuarios con conocimiento tecnico medio
- 2-3 usuarios con conocimiento tecnico avanzado

---

## 3. Materiales Necesarios

### 3.1 APK de la Aplicacion
```bash
# Compilar APK de Flutter
cd alerta_link_flutter
flutter build apk --release

# APK generado en:
# build/app/outputs/flutter-apk/app-release.apk
```

### 3.2 URLs de Prueba

| URL | Tipo | Score Esperado |
|-----|------|----------------|
| google.com | Legitima | 0-10 (BAJO) |
| facebook.com | Legitima | 0-10 (BAJO) |
| paypal.com | Legitima | 0-10 (BAJO) |
| secure-paypal-verify.xyz | Phishing | 90-100 (ALTO) |
| amazon-gift-free.top | Phishing | 90-100 (ALTO) |
| login-bancolombia.tk | Phishing | 90-100 (ALTO) |
| bit.ly/free-gift | Sospechosa | 40-60 (MEDIO) |

### 3.3 Encuesta Pre-Prueba
Ver seccion 5.1

### 3.4 Encuesta Post-Prueba
Ver seccion 5.2

---

## 4. Protocolo de la Prueba

### 4.1 Preparacion (5 min)
1. Explicar el proposito de la prueba
2. Obtener consentimiento informado
3. Completar encuesta pre-prueba

### 4.2 Instalacion (3 min)
1. Instalar APK en el dispositivo
2. Otorgar permisos necesarios:
   - Acceso a internet
   - Permiso de notificaciones (opcional)

### 4.3 Tareas de Prueba (15 min)

#### Tarea 1: Analisis Manual
> "Ingrese la URL 'google.com' en la aplicacion y analicela"

Observar:
- Tiempo para encontrar el campo de entrada
- Facilidad para iniciar el analisis
- Comprension del resultado

#### Tarea 2: URL Sospechosa
> "Analice la URL 'secure-paypal-verify.xyz'"

Observar:
- Reaccion al resultado de alto riesgo
- Comprension de las senales mostradas
- Lectura de las recomendaciones

#### Tarea 3: Cambio de Modo
> "Cambie el modo de conexion a 'Offline'"

Observar:
- Facilidad para encontrar configuracion
- Comprension de los modos

#### Tarea 4: Revisar Historial
> "Revise el historial de analisis anteriores"

Observar:
- Navegacion en la interfaz
- Utilidad del historial

### 4.4 Encuesta Post-Prueba (10 min)
Completar cuestionario de usabilidad

### 4.5 Retroalimentacion Abierta (5 min)
Preguntas abiertas sobre la experiencia

---

## 5. Instrumentos de Evaluacion

### 5.1 Encuesta Pre-Prueba

```
INFORMACION DEL PARTICIPANTE
=============================

1. Edad: ____

2. Genero: [ ] Masculino [ ] Femenino [ ] Otro/Prefiero no decir

3. Nivel de experiencia con tecnologia:
   [ ] Basico (uso correo y redes sociales)
   [ ] Medio (instalo apps, configuro dispositivos)
   [ ] Avanzado (desarrollo software, IT)

4. Con que frecuencia recibe mensajes con enlaces por SMS/WhatsApp?
   [ ] Nunca
   [ ] Raramente (1-2 veces al mes)
   [ ] A veces (1-2 veces por semana)
   [ ] Frecuentemente (casi todos los dias)

5. Alguna vez ha sido victima de phishing o estafa digital?
   [ ] Si
   [ ] No
   [ ] No estoy seguro

6. Conoce alguna herramienta para verificar enlaces sospechosos?
   [ ] Si (Cual?: _______________)
   [ ] No
```

### 5.2 Encuesta Post-Prueba (Sistema de Usabilidad - SUS)

Escala: 1 = Totalmente en desacuerdo, 5 = Totalmente de acuerdo

```
CUESTIONARIO DE USABILIDAD (SUS)
=================================

1. Creo que me gustaria usar esta aplicacion frecuentemente.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

2. Encontre la aplicacion innecesariamente compleja.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

3. Pense que la aplicacion era facil de usar.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

4. Creo que necesitaria ayuda de una persona tecnica para usar esta aplicacion.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

5. Encontre que las diversas funciones de la aplicacion estaban bien integradas.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

6. Pense que habia demasiada inconsistencia en esta aplicacion.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

7. Imagino que la mayoria de las personas aprenderian a usar esta aplicacion muy rapidamente.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

8. Encontre la aplicacion muy complicada de usar.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

9. Me senti muy seguro usando la aplicacion.
   [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

10. Necesite aprender muchas cosas antes de poder usar esta aplicacion.
    [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5
```

### 5.3 Preguntas Especificas de ALERTA-LINK

```
EVALUACION ESPECIFICA
======================

11. El semaforo de riesgo (verde/amarillo/rojo) fue claro para entender el nivel de peligro.
    [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

12. Las explicaciones de las senales detectadas fueron comprensibles.
    [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

13. Las recomendaciones fueron utiles para saber que hacer.
    [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

14. El tiempo de analisis fue aceptable.
    [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

15. Recomendaria esta aplicacion a familiares o amigos.
    [ ] 1  [ ] 2  [ ] 3  [ ] 4  [ ] 5

PREGUNTAS ABIERTAS
==================

16. Que fue lo que mas le gusto de la aplicacion?
    _________________________________________________
    _________________________________________________

17. Que fue lo que menos le gusto o le parecio confuso?
    _________________________________________________
    _________________________________________________

18. Que funcionalidad adicional le gustaria que tuviera?
    _________________________________________________
    _________________________________________________

19. Tiene algun comentario o sugerencia adicional?
    _________________________________________________
    _________________________________________________
```

---

## 6. Metricas a Recopilar

### 6.1 Metricas Cuantitativas
| Metrica | Descripcion | Meta |
|---------|-------------|------|
| Tasa de exito de tareas | % tareas completadas correctamente | >80% |
| Tiempo promedio por tarea | Segundos para completar cada tarea | <60s |
| Score SUS | Puntuacion de usabilidad (0-100) | >68 |
| Errores por tarea | Numero de errores cometidos | <2 |

### 6.2 Metricas Cualitativas
- Comprension del semaforo de riesgo
- Claridad de las senales explicativas
- Utilidad de las recomendaciones
- Sugerencias de mejora

---

## 7. Analisis de Resultados

### 7.1 Calculo del Score SUS

```python
# Formula SUS
# Para items impares (1,3,5,7,9): restar 1 al puntaje
# Para items pares (2,4,6,8,10): restar puntaje de 5
# Sumar todos y multiplicar por 2.5

def calcular_sus(respuestas):
    """
    respuestas: lista de 10 valores (1-5)
    """
    score = 0
    for i, r in enumerate(respuestas):
        if (i + 1) % 2 == 1:  # Impar
            score += (r - 1)
        else:  # Par
            score += (5 - r)
    return score * 2.5

# Interpretacion:
# >80.3: Excelente
# 68-80.3: Bueno
# 68: Promedio
# <68: Por debajo del promedio
```

### 7.2 Plantilla de Reporte

```markdown
# Reporte de Prueba Piloto - ALERTA-LINK

## Resumen Ejecutivo
- Participantes: X usuarios
- Fecha: YYYY-MM-DD
- Score SUS promedio: XX/100

## Resultados por Tarea
| Tarea | Exito | Tiempo Promedio | Errores |
|-------|-------|-----------------|---------|
| T1    | X%    | Xs              | X       |
| T2    | X%    | Xs              | X       |
| T3    | X%    | Xs              | X       |
| T4    | X%    | Xs              | X       |

## Problemas Identificados
1. [Problema 1]: Descripcion - Severidad (Alta/Media/Baja)
2. [Problema 2]: Descripcion - Severidad

## Sugerencias de Usuarios
- Sugerencia 1
- Sugerencia 2

## Acciones Recomendadas
- [ ] Accion 1
- [ ] Accion 2

## Conclusion
[Resumen de hallazgos principales]
```

---

## 8. Consideraciones Eticas

### 8.1 Consentimiento Informado

```
CONSENTIMIENTO INFORMADO
=========================

Proyecto: ALERTA-LINK - Sistema de Deteccion de Phishing
Investigadores: Cristia Salazar, Samuel Ortiz, Juan Stiven Castro
Universidad Manuela Beltran

Proposito: Evaluar la usabilidad de una aplicacion movil para detectar
enlaces de phishing.

Procedimiento: Se le pedira usar la aplicacion durante aproximadamente
30 minutos y responder algunas preguntas.

Riesgos: No existen riesgos conocidos por participar en este estudio.

Beneficios: Contribuira al desarrollo de una herramienta gratuita para
proteger a colombianos del phishing.

Confidencialidad: Sus respuestas seran anonimas y usadas solo para
fines academicos.

Participacion Voluntaria: Puede retirarse en cualquier momento sin
consecuencias.

[ ] Acepto participar voluntariamente en esta prueba.

Firma: _________________ Fecha: _________________
```

### 8.2 Privacidad de Datos
- No se recopilaran datos personales identificables
- Los resultados se presentaran de forma agregada
- Los datos crudos se eliminaran despues del analisis

---

## 9. Cronograma Sugerido

| Actividad | Duracion | Responsable |
|-----------|----------|-------------|
| Preparar materiales | 1 dia | Equipo |
| Reclutar participantes | 2-3 dias | Equipo |
| Ejecutar pruebas | 2-3 dias | Equipo |
| Analizar resultados | 1-2 dias | Equipo |
| Generar reporte | 1 dia | Equipo |
| Implementar mejoras | Variable | Equipo |

---

## 10. Checklist Pre-Prueba

- [ ] APK compilado y probado
- [ ] Backend desplegado y accesible
- [ ] URLs de prueba verificadas
- [ ] Formularios impresos/digitales listos
- [ ] Dispositivos de prueba cargados
- [ ] Participantes confirmados
- [ ] Lugar de prueba reservado (si aplica)

---

**Universidad Manuela Beltran - Ingenieria de Software 2025**
