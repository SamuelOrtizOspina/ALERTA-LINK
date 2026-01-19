# ALERTA-LINK - Manual de Usuario

**Version:** 1.0
**Fecha:** 2026-01-09

---

## Bienvenido a ALERTA-LINK

ALERTA-LINK es una aplicacion gratuita que te ayuda a detectar enlaces peligrosos (phishing) antes de que te roben tu informacion personal o dinero.

---

## Tabla de Contenido

1. [Que es el Phishing](#1-que-es-el-phishing)
2. [Instalacion](#2-instalacion)
3. [Pantalla Principal](#3-pantalla-principal)
4. [Como Analizar un Enlace](#4-como-analizar-un-enlace)
5. [Entender los Resultados](#5-entender-los-resultados)
6. [Modos de Conexion](#6-modos-de-conexion)
7. [Historial de Analisis](#7-historial-de-analisis)
8. [Preguntas Frecuentes](#8-preguntas-frecuentes)
9. [Contacto y Soporte](#9-contacto-y-soporte)

---

## 1. Que es el Phishing

El **phishing** es una tecnica de estafa donde criminales crean paginas web falsas que imitan a bancos, tiendas o servicios conocidos para robar tus datos.

### Ejemplo de Phishing
```
URL Falsa:  https://secure-bancolombia-verify.xyz/login
URL Real:   https://www.bancolombia.com
```

### Senales de Alerta
- Mensajes urgentes: "Tu cuenta sera bloqueada"
- Premios falsos: "Ganaste un iPhone"
- Enlaces de desconocidos por WhatsApp/SMS
- Dominios extranos (.xyz, .tk, .top)

---

## 2. Instalacion

### Requisitos
- Telefono Android 8.0 o superior
- 50 MB de espacio libre
- Conexion a internet (opcional para modo offline)

### Pasos de Instalacion

1. **Descargar el APK**
   - Obtener el archivo `alerta-link.apk` del sitio oficial

2. **Permitir Instalacion**
   - Ir a Configuracion > Seguridad
   - Activar "Fuentes desconocidas" temporalmente

3. **Instalar**
   - Abrir el archivo APK
   - Tocar "Instalar"
   - Esperar a que termine

4. **Abrir la App**
   - Buscar "ALERTA-LINK" en tus aplicaciones
   - Tocar para abrir

### Permisos Necesarios
| Permiso | Para que se usa |
|---------|-----------------|
| Internet | Consultar bases de datos de seguridad |
| Notificaciones | Alertarte sobre enlaces peligrosos |

---

## 3. Pantalla Principal

```
+----------------------------------+
|         ALERTA-LINK              |
+----------------------------------+
|                                  |
|  [============================]  |
|  | Pega aqui la URL sospechosa | |
|  [============================]  |
|                                  |
|       [ ANALIZAR ENLACE ]        |
|                                  |
|  --------------------------------|
|  Historial Reciente:             |
|  - google.com          [SEGURO]  |
|  - paypal-login.xyz    [PELIGRO] |
+----------------------------------+
|  [Home]  [Historial]  [Config]   |
+----------------------------------+
```

### Elementos de la Pantalla
1. **Campo de URL**: Donde pegas o escribes el enlace
2. **Boton Analizar**: Inicia el analisis
3. **Historial Reciente**: Ultimos analisis realizados
4. **Barra de Navegacion**: Acceso a otras secciones

---

## 4. Como Analizar un Enlace

### Metodo 1: Copiar y Pegar

1. **Copia el enlace** del mensaje sospechoso (mantener presionado > Copiar)
2. **Abre ALERTA-LINK**
3. **Pega en el campo de URL** (mantener presionado > Pegar)
4. **Toca "ANALIZAR ENLACE"**
5. **Espera el resultado** (1-3 segundos)

### Metodo 2: Compartir desde Otra App

1. En WhatsApp/SMS, **mantener presionado el enlace**
2. Seleccionar **"Compartir"**
3. Elegir **ALERTA-LINK** de la lista
4. El analisis inicia automaticamente

### Metodo 3: Escribir Manualmente

1. Abre ALERTA-LINK
2. Escribe el enlace en el campo
3. Toca "ANALIZAR ENLACE"

---

## 5. Entender los Resultados

### El Semaforo de Riesgo

```
+----------------------------------+
|          RESULTADO               |
+----------------------------------+
|                                  |
|           [VERDE]                |
|          RIESGO BAJO             |
|           Score: 15              |
|                                  |
|  Este enlace parece seguro.      |
|  Puedes acceder con precaucion.  |
+----------------------------------+
```

| Color | Nivel | Score | Significado |
|-------|-------|-------|-------------|
| VERDE | BAJO | 0-30 | Enlace probablemente seguro |
| AMARILLO | MEDIO | 31-70 | Precaucion, verificar antes |
| ROJO | ALTO | 71-100 | Peligroso, NO hacer clic |

### Senales Detectadas

Cada analisis muestra las razones del resultado:

```
+----------------------------------+
|  SENALES DETECTADAS              |
+----------------------------------+
|                                  |
|  [!] SUPLANTACION DE MARCA       |
|  Severidad: ALTA                 |
|  Este sitio intenta hacerse      |
|  pasar por "PayPal"              |
|                                  |
|  [!] DOMINIO SOSPECHOSO          |
|  Severidad: MEDIA                |
|  Usa extension .xyz (alto riesgo)|
+----------------------------------+
```

### Senales Comunes

| Senal | Que significa |
|-------|---------------|
| SUPLANTACION DE MARCA | Imita un sitio conocido (banco, tienda) |
| IP COMO DOMINIO | Usa numeros en vez de nombre (ej: 192.168.1.1) |
| URL ACORTADA | Enlace abreviado que oculta el destino real |
| DOMINIO SOSPECHOSO | Extension de alto riesgo (.xyz, .tk, .top) |
| PALABRAS SOSPECHOSAS | Contiene "login", "verify", "secure" falsamente |
| SIN HTTPS | Conexion no segura |

### Recomendaciones

Segun el resultado, la app te sugiere que hacer:

**Para RIESGO BAJO:**
- Puedes acceder con precaucion normal
- Verifica que el candado aparezca en el navegador

**Para RIESGO MEDIO:**
- No ingreses datos personales aun
- Verifica la URL oficial del servicio
- Consulta con alguien de confianza

**Para RIESGO ALTO:**
- NO hagas clic en este enlace
- NO ingreses ningun dato
- Reporta el mensaje como spam
- Bloquea el remitente

---

## 6. Modos de Conexion

ALERTA-LINK puede funcionar de 3 formas:

### Modo Auto (Recomendado)
- Detecta automaticamente si hay internet
- Usa APIs externas cuando estan disponibles
- Funciona offline con analisis local

### Modo Online
- Siempre usa internet
- Consulta bases de datos en tiempo real
- Analisis mas completo

### Modo Offline
- No usa internet
- Analisis basico con inteligencia local
- Ideal si no tienes datos moviles

### Como Cambiar el Modo

1. Toca el icono de **Configuracion** (engranaje)
2. Busca **"Modo de Conexion"**
3. Selecciona: Auto / Online / Offline
4. Los cambios se aplican inmediatamente

---

## 7. Historial de Analisis

La app guarda un registro de todos los enlaces que has analizado.

### Ver el Historial

1. Toca **"Historial"** en la barra inferior
2. Veras una lista con:
   - URL analizada
   - Fecha y hora
   - Resultado (BAJO/MEDIO/ALTO)

### Usar el Historial

- **Tocar una entrada**: Ver detalles del analisis
- **Deslizar a la izquierda**: Eliminar entrada
- **Boton "Limpiar"**: Borrar todo el historial

---

## 8. Preguntas Frecuentes

### La app dice que un sitio es peligroso pero yo lo conozco
Es posible que el sitio legitimo tenga caracteristicas sospechosas. Verifica:
- Que la URL sea exactamente correcta
- Que no haya errores de escritura
- Que uses el enlace oficial

### Puedo confiar 100% en el resultado?
ALERTA-LINK es una herramienta de apoyo, no un sustituto del sentido comun. Siempre:
- Verifica URLs manualmente
- No compartas datos sensibles con desconocidos
- Consulta con tu banco directamente

### La app no analiza, que hago?
1. Verifica tu conexion a internet
2. Prueba cambiar a modo Offline
3. Reinicia la aplicacion
4. Si persiste, contacta soporte

### Puedo analizar enlaces de correo electronico?
Si, copia el enlace del correo y pegalo en la app.

### La app consume muchos datos?
No, cada analisis usa menos de 10 KB. En modo offline no consume datos.

### Como reporto un enlace peligroso?
1. Analiza el enlace
2. Si es peligroso, toca "Reportar"
3. Esto ayuda a mejorar la deteccion para todos

---

## 9. Contacto y Soporte

### Problemas Tecnicos
- Email: soporte@alertalink.co (ficticio)
- Repositorio: github.com/alertalink

### Sugerencias
Valoramos tu retroalimentacion. Envianos tus ideas a:
- feedback@alertalink.co (ficticio)

### Autores
- Cristia Salazar
- Samuel Ortiz Ospina
- Juan Stiven Castro

**Universidad Manuela Beltran - Ingenieria de Software 2025**

---

## Consejos Finales de Seguridad

1. **Nunca compartas tu clave bancaria** por mensaje
2. **Los bancos nunca piden datos por SMS/WhatsApp**
3. **Si algo suena demasiado bueno, probablemente es falso**
4. **Ante la duda, verifica directamente** con la entidad oficial
5. **Usa ALERTA-LINK** antes de hacer clic en enlaces sospechosos

---

**Gracias por usar ALERTA-LINK**
*Protegiendo a Colombia del phishing*
