# Comando único: senher.py

Los escaneos del punto de entrada principal crean checkpoints por defecto. Los demás archivos son módulos internos: consérvalos, pero no necesitas ejecutarlos.

```bash
export SHODAN_API_KEY="TU_CLAVE"
python3 senher.py ejemplo.com --session-dir output/mi_sesion
# Ctrl+C para solicitar interrupción
python3 senher.py --resume output/mi_sesion
```

Sin --session-dir se crea una carpeta automática y se imprime su ruta. El mensaje interno aún puede mencionar senher_resume.py; senher.py --resume es equivalente. Ejecuta desde la misma carpeta de trabajo original. --resume recupera dominio, modo y opciones: no añadas otras opciones. Usa la variable de entorno para Shodan, no -k/--shodan-key, y --session-dir en lugar de -o/--output-dir.

La reanudación es por fases completadas, no por posición interna de cada herramienta. La fase interrumpida empieza de nuevo. No importa ejecuciones antiguas sin checkpoint.json. No borres resultados ni checkpoints. El gestor comprueba hashes y bloquea dos instancias sobre la misma sesión.

Regeneración HTML, sin consultas de red ni refiltrado wildcard:

```bash
python3 senher.py --report-only output/directorio --domain ejemplo.com
```

Limitaciones: esta integración no cambia el motor existente. Los hashes conservadores pueden repetir fases si cambian archivos previos. Las herramientas externas que fallan, incluido whois, detienen la sesión. Los errores de Shodan manejados por su módulo pueden quedar guardados como resultados vacíos. No cambies herramientas, código o entradas durante una sesión salvo para corregir un fallo conocido.

La interrupción durante permutaciones en hilos sigue pendiente de corrección y prueba: Ctrl+C puede esperar a que termine una tarea; no se garantiza parada inmediata en esa fase. Evita kill -9. Los checkpoints ya escritos se conservan. La separación estricta de modos también sigue pendiente: passive todavía hace validación DNS y sondas wildcard.
