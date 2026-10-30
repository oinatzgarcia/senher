# Fuente crt.sh en SENHER

Ejecutar con el punto de entrada integrado:

```bash
python3 senher.py ejemplo.com
python3 senher.py ejemplo.com --skip-crtsh
python3 senher.py ejemplo.com --crtsh-refresh
python3 senher.py ejemplo.com --crtsh-cache-dir /ruta/cache
```

No se necesita una API key ni nuevas dependencias Python para crt.sh. Se usa la biblioteca estándar.

La consulta busca certificados de subdominios, normaliza IDNA y filtra estrictamente el dominio. Las entradas `*.ejemplo.com` se guardan como evidencia de certificado wildcard, sin inventar un host. La caché dura 24 horas; hay dos intentos como máximo, timeout de socket de 20 segundos y límite de respuesta de 20 MiB. No es un plazo máximo global de ejecución. Un error de la fuente no interrumpe las demás fases.

Archivos por ejecución:
- `crtsh.txt`: nombres concretos en scope.
- `crtsh.json`: estado de la fuente, nombres, certificados wildcard y error si lo hay.
- `sources.json`: procedencia por host; también se muestra en el HTML.

El contador de candidatos adicionales compara crt.sh con Subfinder, no con el conjunto final de todas las fuentes. Subfinder conserva su archivo separado. Los nombres de certificados son candidatos históricos, no prueba de resolución actual.

`python3 subenum.py` sigue siendo el punto de entrada antiguo y no integra crt.sh. Esta ampliación no cambia todavía el comportamiento de los modos pasivo/activo: el flujo existente sigue realizando validación DNS y sondas wildcard incluso cuando se selecciona passive.

Regeneración de informes existentes, sin consultar crt.sh ni DNS:

```bash
python3 senher.py --report-only output/directorio --domain ejemplo.com
```

La regeneración utiliza los archivos guardados y no vuelve a aplicar el filtrado wildcard.
