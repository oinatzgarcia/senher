# Parar y reanudar por fases (Kali/Linux)

```bash
export SHODAN_API_KEY="TU_CLAVE"
python3 senher_resume.py ejemplo.com --session-dir output/mi_sesion
# Ctrl+C para detener
python3 senher_resume.py --resume output/mi_sesion
```

Ejecuta desde la misma carpeta de trabajo al reanudar. El lanzador conserva las opciones y elecciones interactivas, usa los módulos existentes de senher.py (crt.sh e informes incluidos) y no guarda la clave Shodan. No uses -k/--shodan-key; usa la variable de entorno. Utiliza --session-dir en lugar de -o.

Se guardan checkpoints después de cada fase terminada. No se presupone éxito por existir un TXT vacío: un código de salida no cero o timeout del proceso externo detiene la ejecución y deja la fase pendiente. Al reanudar se comprueban hashes de los archivos guardados; si faltan o cambian se repite la fase. La comprobación es conservadora: puede repetir fases si han cambiado archivos previos. Se vuelve a generar el informe al final.

La fase interrumpida se repite desde su principio, no desde una posición interna de Amass, dnsx o Gotator. La consulta crt.sh utiliza su caché independiente y puede repetirse si no quedó cacheada. La API Shodan puede devolver un error manejado por el módulo existente; el checkpoint conserva el resultado devuelto por ese módulo, por lo que un resultado vacío no garantiza que la API tuviera éxito. Estas limitaciones no se ocultan como reanudación por host.

Ctrl+C detiene el proceso externo y su grupo; los procesos externos se ejecutan sin privilegios adicionales. Las permutaciones se serializan para que no escriban simultáneamente el estado. Un bloqueo de archivo impide ejecutar dos instancias en la misma sesión. No se recomienda detener con kill -9; aun así se conservan los checkpoints previamente escritos mediante reemplazo atómico. No se incluyen reintentos automáticos de fallos.

No importa ejecuciones antiguas sin checkpoint.json. No cambies archivos de entrada, versiones de herramientas o código entre parada y reanudación; los hashes comprueban los resultados guardados, no congelan las dependencias ni el contenido de wordlists externas. La reanudación requiere las mismas herramientas instaladas. Un whois fallido detiene el flujo y queda pendiente, en lugar de marcarlo como completado.

Los modos pasivo/activo mantienen el comportamiento del programa existente: este cambio no convierte el modo passive en reconocimiento estrictamente pasivo.
