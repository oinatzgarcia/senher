# Compatibilidad de salida Amass

Los puntos de entrada senher.py y senher_resume.py detectan las opciones de amass enum -h: utilizan -oA si existe y -o como alternativa para versiones antiguas. subenum.py sigue siendo el punto de entrada antiguo sin adaptador.

Los archivos originales se conservan en amass_raw/ y se extraen nombres del dominio objetivo a amass.txt. Esta extracción produce candidatos, no validación DNS. Si Amass no crea archivos de salida, el adaptador genera un error en lugar de marcar una fase vacía como éxito. El modo de reanudación sigue deteniéndose ante errores de ejecución.

En Amass 5.1.1, -passive está deprecado porque es el comportamiento por defecto; se conserva por compatibilidad con la interfaz anunciada. Este cambio solo corrige la salida, no configura ni inicia el collection engine. Si se produce un error de engine/configuración deberá diagnosticarse por separado.

Para recuperar la sesión que fallaba por -o:

```bash
git pull origin main
python3 senher_resume.py --resume output/session_20261030_113424_702825
```

No borres checkpoint.json. Amass quedó pendiente y se volverá a ejecutar. La corrección no resuelve otros defectos pendientes del lanzador de checkpoints, como invalidaciones conservadoras de hashes o interrupciones durante tareas en hilos. No se ha verificado una ejecución completa con el binario local del usuario.
