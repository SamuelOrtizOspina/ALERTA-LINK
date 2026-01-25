# Politica de Privacidad - ALERTA-LINK

> Politica de privacidad y manejo de datos

**Ultima actualizacion:** 2026-01-01

---

## Resumen

ALERTA-LINK es un sistema de analisis forense automatico para detectar URLs de phishing. Esta politica describe como manejamos los datos.

**Principios clave:**
- Privacidad por defecto
- Minimo de datos necesarios
- Sin datos personales obligatorios
- Transparencia total

---

## Datos que Recolectamos

### Al usar la funcion "Analizar"

| Dato | Proposito | Retencion |
|------|-----------|-----------|
| URL analizada | Realizar el analisis | No se guarda por defecto |
| Score resultante | Mostrar al usuario | No se guarda |

### Al usar la funcion "Reportar" (opcional)

| Dato | Proposito | Retencion |
|------|-----------|-----------|
| URL reportada | Mejorar deteccion | 1 ano |
| Tipo de amenaza | Clasificacion | 1 ano |
| Comentario | Contexto opcional | 1 ano |
| Contacto | Solo si el usuario lo proporciona | 1 ano |

### Al usar la funcion "Ingest" (API)

| Dato | Proposito | Retencion |
|------|-----------|-----------|
| URL | Entrenamiento del modelo | Indefinido |
| Label | Clasificacion | Indefinido |
| Metadatos | Auditoria | Indefinido |

---

## Datos que NO Recolectamos

- Direccion IP del usuario
- Identificadores del dispositivo
- Ubicacion geografica
- Historial de navegacion
- Datos biometricos
- Informacion financiera
- Cookies de terceros

---

## Uso de los Datos

Los datos recolectados se usan exclusivamente para:

1. **Analisis de URLs** - Detectar phishing/malware
2. **Mejora del modelo** - Entrenar con nuevos datos reportados
3. **Investigacion academica** - En forma anonimizada

Los datos **NUNCA** se usan para:
- Publicidad
- Venta a terceros
- Perfilamiento de usuarios
- Rastreo de comportamiento

---

## Seguridad

### Medidas implementadas

- Conexiones HTTPS obligatorias
- Hashing de URLs para deduplicacion
- Sin almacenamiento de datos sensibles
- Acceso restringido a la base de datos
- Logs sin informacion personal

### Proteccion SSRF

El sistema bloquea intentos de acceder a:
- IPs privadas (10.x, 172.x, 192.168.x)
- Localhost (127.x)
- Servicios de metadata cloud

---

## Derechos del Usuario

Como usuario tienes derecho a:

1. **Acceso** - Solicitar que datos tenemos sobre ti
2. **Rectificacion** - Corregir datos incorrectos
3. **Eliminacion** - Solicitar borrado de tus reportes
4. **Portabilidad** - Exportar tus datos

Para ejercer estos derechos, contactanos en: [contacto por definir]

---

## Cumplimiento Legal

Este proyecto cumple con:

- **Ley 1581/2012** - Proteccion de Datos Personales (Colombia)
- **Ley 1273/2009** - Delitos Informaticos (Colombia)
- **Principios UNESCO IA Etica** - Transparencia y explicabilidad

---

## Menores de Edad

El servicio esta disenado para mayores de 18 anos. No recolectamos intencionalmente datos de menores.

---

## Cambios a esta Politica

Cualquier cambio sera publicado en esta pagina con la fecha de actualizacion.

---

## Contacto

Para preguntas sobre privacidad:

- **Universidad:** Universidad Manuela Beltran
- **Proyecto:** Sistema de Analisis Forense Automatico
- **Autores:** Cristia Salazar, Samuel Ortiz Ospina, Juan Stiven Castro

---

**Documento version:** 1.0
