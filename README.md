# 🔐 Security Toolkit

> **Web Security Scanner** — Auditoría de seguridad web automatizada y profesional

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)
[![GitHub](https://img.shields.io/badge/GitHub-alxgaray712-black.svg)](https://github.com/alxgaray712)

---

## 🎯 Características

✅ **Análisis completo de headers HTTP** — Detecta configuraciones de seguridad faltantes

✅ **Verificación SSL/TLS** — Valida certificados y versiones de protocolo

✅ **Detección de tecnologías expuestas** — Identifica versiones de servidores visibles

✅ **Puntuación de seguridad (0-100)** — Evaluación rápida del nivel de riesgo

✅ **Reportes JSON** — Exporta resultados para documentación

✅ **Interfaz colorida** — Terminal amigable con indicadores visuales

✅ **Totalmente legal** — Solo análisis pasivo, sin pruebas activas

---

## 📋 Tabla de Contenidos

- [Instalación](#instalación)
- [Uso](#uso)
- [Ejemplos](#ejemplos)
- [Severidades](#severidades)
- [Metodología](#metodología)
- [Ética y Legalidad](#ética-y-legalidad)
- [Casos de Estudio](#casos-de-estudio)

---

## 🚀 Instalación

### Requisitos previos
- Python 3.8 o superior
- pip (gestor de paquetes Python)

### Pasos

```bash
# Clonar el repositorio
git clone https://github.com/alxgaray712/security-toolkit.git
cd security-toolkit

# Crear un entorno virtual (opcional pero recomendado)
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

---

## 💻 Uso

### Análisis básico en terminal

```bash
python3 scanner.py https://ejemplo.com
```

### Generar reporte JSON

```bash
python3 scanner.py https://ejemplo.com --output json
```

Esto creará un archivo `reporte_ejemplo.com_YYYYMMDD_HHMM.json`

---

## 📊 Ejemplo de Output

```
╔═══════════════════════════════════════════╗
║     🔐 Web Security Scanner v1.0          ║
║     github.com/tu_usuario                 ║
╚═══════════════════════════════════════════╝

[*] Objetivo: https://ejemplo.com
[*] Inicio: 2025-04-25 15:30:45
───────────────────────────────────────────

[+] Analizando headers de seguridad...

  [HIGH] ✗ Content-Security-Policy
         → Sin política CSP — riesgo de XSS
         💡 Fix: Agregar: Content-Security-Policy: default-src 'self'

  [OK]  ✓ Strict-Transport-Security: max-age=31536000; includeSubDomains

  [MEDIUM] ✗ X-Frame-Options
          → Vulnerable a Clickjacking
          💡 Fix: Agregar: X-Frame-Options: DENY

[+] Verificando SSL/TLS...

  [OK]  ✓ SSL Válido
  [OK]  ✓ Versión: TLSv1.3
  [OK]  ✓ Expira: Jan 15 15:30:45 2026 GMT
  [OK]  ✓ Emisor: Let's Encrypt

───────────────────────────────────────────
[📊] RESUMEN FINAL
───────────────────────────────────────────
  Puntuación de Seguridad : 68/100
  Nivel de Riesgo         : MEDIO
  Problemas Críticos      : 0
  Problemas Medios        : 2
  Problemas Bajos         : 1
───────────────────────────────────────────

📋 Generado por: github.com/tu_usuario/security-toolkit
```

---

## 🎨 Severidades

| Nivel | CVSS Score | Color | Tiempo de respuesta |
|-------|-----------|-------|-------------------|
| 🔴 **CRÍTICO** | 9.0 - 10.0 | Rojo | Inmediato (< 24h) |
| 🔴 **ALTO** | 7.0 - 8.9 | Rojo | 24-48 horas |
| 🟡 **MEDIO** | 4.0 - 6.9 | Amarillo | 1 semana |
| 🔵 **BAJO** | 0.1 - 3.9 | Azul | 2-4 semanas |

---

## 📚 Metodología

Nuestro análisis sigue los estándares internacionales:

- **OWASP Top 10** — Las vulnerabilidades web más críticas
- **NIST Cybersecurity Framework** — Marco de gestión de riesgos
- **CIS Controls** — Controles críticos de seguridad

### Fases de auditoría

```
1️⃣  RECONOCIMIENTO PASIVO
   └─ Análisis de headers HTTP
   └─ Detección de tecnologías
   └─ Verificación SSL/TLS

2️⃣  ANÁLISIS DE VULNERABILIDADES
   └─ Comparación con OWASP Top 10
   └─ Asignación de CVSS Score
   └─ Clasificación por severidad

3️⃣  REPORTE
   └─ Documentación de hallazgos
   └─ Plan de remediación priorizado
   └─ Entrega inmediata

4️⃣  SEGUIMIENTO (Premium)
   └─ Verificación de correcciones
   └─ Re-auditoría de confirmación
```

---

## ⚠️ Ética y Legalidad

> **IMPORTANTE:** Este toolkit realiza **únicamente análisis pasivo**. No realiza ningún tipo de prueba activa (inyecciones, exploits) sin autorización explícita.

✅ **Uso autorizado:**
- Auditoría de tus propios sistemas
- Análisis con permiso escrito del propietario
- Cumplimiento de leyes locales e internacionales

❌ **Prohibido:**
- Usar en sistemas sin autorización
- Pruebas activas sin contrato firmado
- Violar leyes de ciberseguridad

---

## 📈 Casos de Estudio

### Caso #01: E-commerce (Anonimizado)

**Contexto:**
- Pequeña empresa de comercio electrónico
- ~5,000 visitas mensuales
- Score inicial: 34/100

**Resultados:**
- ✅ 7 vulnerabilidades detectadas
- ✅ Plan de remediación en 24h
- ✅ Score final: 91/100
- ✅ Tiempo de análisis: 45 minutos

> *"El reporte fue claro y las instrucciones fáciles de seguir"* — Cliente #01

---

## 📁 Estructura del Proyecto

```
security-toolkit/
├── scanner.py              # Herramienta principal
├── metodologia.md          # Documentación de metodología
├── caso_01.md             # Caso de estudio
├── plantilla_reporte.md   # Plantilla de reportes
├── requirements.txt       # Dependencias Python
├── .gitignore            # Archivos ignorados
└── README.md             # Este archivo
```

---

## 🔗 Headers de Seguridad Analizados

| Header | Función |
|--------|---------|
| `Strict-Transport-Security` | Fuerza HTTPS |
| `X-Frame-Options` | Previene Clickjacking |
| `X-Content-Type-Options` | Previene MIME sniffing |
| `Content-Security-Policy` | Previene XSS |
| `Referrer-Policy` | Controla información de referencia |
| `Permissions-Policy` | Controla permisos del navegador |

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Para reportar bugs o sugerir mejoras:

1. Abre un **Issue** en GitHub
2. Describe el problema o mejora
3. Proporciona ejemplos si es posible

---

## 📜 Licencia

Este proyecto está bajo la licencia **MIT**. Ver `LICENSE` para más detalles.

---

## 📞 Contacto

- **GitHub:** [@alxgaray712](https://github.com/alxgaray712)
- **Email:** alxgaray712@gmail.com

---

<div align="center">

**Hecho con ❤️ para la seguridad web**

⭐ Si te fue útil, considera darle una estrella en GitHub

</div>