# Dashboard web — TFG-PQC

Interfaz web conectada al backend real del proyecto. Cada paso del pipeline
se ejecuta como subprocess real en tu máquina, los logs hacen streaming en
tiempo real por SSE, y los gráficos de la pestaña *Resultados* se generan a
partir de los CSVs/JSONs que tus scripts dejan en `resultados/` y `imagenes/`.

---

## 1. Integración con tu repo

Copia todo lo que hay en este paquete **a la raíz de `TFG-PQC/`**, conservando la
estructura de carpetas. Al final debe quedar:

```
TFG-PQC/
├── ejecutar_sonda.sh              (ya lo tenías)
├── ejecutar_analisis.sh           (ya lo tenías)
├── …                              (el resto de tus .sh)
├── scripts/                       (ya lo tenías)
├── resultados/                    (ya lo tenías)
├── imagenes/                      (ya lo tenías)
│
├── ejecutar_web.sh                ◀ NUEVO
└── web/                           ◀ NUEVO
    ├── backend/
    │   ├── config.py
    │   ├── jobs.py
    │   ├── results.py
    │   ├── server.py
    │   └── requirements.txt
    └── frontend/
        ├── index.html
        └── src/
            ├── api.js
            ├── ui.jsx
            ├── App.jsx
            └── results.jsx
```

Nada sobrescribe tu proyecto — solo añade una carpeta `web/` y un script
`ejecutar_web.sh`.

---

## 2. Arranque

```bash
chmod +x ejecutar_web.sh
./ejecutar_web.sh
```

Esto crea un venv aislado en `web/backend/.venv`, instala Flask, y sirve todo
desde `http://localhost:5001`. Para cambiar el puerto: `PORT=8080 ./ejecutar_web.sh`.

---

## 3. Cómo está cableado

### Ejecución real de los scripts

El backend invoca **directamente tus `.sh` existentes** con los flags que el
usuario elige en el drawer. Por ejemplo, cuando pulsas ▶ Ejecutar en *Sonda PQC*
con `max_hostnames=200`, el backend lanza:

```bash
bash ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 200 \
     --repeticiones 3 --max-workers 20
```

desde la raíz del repo. Si alguno de tus scripts `.sh` **no acepta todavía
estos flags**, tienes dos opciones:

1. **Adaptar el `.sh`** para que los pase a su script Python (normalmente una
   línea con `"$@"` al final del comando).
2. **Saltarte el `.sh`** y llamar directamente al `.py` desde el backend —
   edita `web/backend/config.py` y cambia la función `*_cmd` correspondiente.
   Por ejemplo:

   ```python
   def pqc_sonda_cmd(args):
       return [
           "python3", "scripts/sondas/sonda_pqc_final.py",
           "--input-csv",     args.get("input_csv", "majestic_million.csv"),
           "--max-hostnames", str(args.get("max_hostnames", 100)),
           # …
       ]
   ```

### Streaming de logs

`stdout` y `stderr` del subprocess se capturan línea a línea y se emiten por un
canal **SSE** (`GET /api/jobs/<id>/stream`). El frontend los pinta en el
Terminal de la UI a medida que llegan, con los mismos colores que ya usabas
(`[INFO]`, `[SUCCESS]`, `[ERROR]`, `✓`, `✗`…).

La barra de progreso se actualiza de dos maneras:
- **Exacta** si la línea contiene `[ 50/1000]` o `50%` (tus sondas ya lo hacen).
- **Estimada** si no — crece asintóticamente hacia el 90 % y salta al 100 %
  cuando el proceso termina.

### Cancelación

El botón ■ *Detener* envía `POST /api/jobs/<id>/stop`. El backend mata el
process group completo (`os.killpg`) para asegurarse de terminar contenedores
Docker secundarios que tus `.sh` puedan haber creado.

### Resultados

La pestaña *Resultados* hace `GET /api/results/<step_id>`. `web/backend/results.py`
parsea tus ficheros reales:

| Step              | Lee de                                   |
| ----------------- | ---------------------------------------- |
| pqc_sonda         | `resultados/resultados_sonda_pqc.json`   |
| pqc_analisis      | `resultados/resumen_por_grupo.csv`       |
| pqc_clasificacion | `resultados/resumen_clasificacion.json`* |
| ech_sonda         | `resultados/resultados_ech_prevalencia.csv` |
| ech_latencia_ech  | `resultados/resultados_latencia_ech.csv` |
| ech_latencia_pqc  | `resultados/resultados_latencia_pqc.csv` |

\* Si tu clasificador aún no genera un `resumen_clasificacion.json`, la pestaña
mostrará un mensaje explicativo — añádelo o adapta `_pqc_clasificacion()` en
`web/backend/results.py` para leer el formato que prefieras.

Además, se muestran automáticamente todas las PNGs que tus scripts hayan
generado en `imagenes/` (filtradas por paso mediante regex en
`web/frontend/src/results.jsx`).

### Robustez frente a nombres de columnas

`results.py` es tolerante: prueba varios nombres posibles para cada campo
(`grupo`/`group`/`grupo_pqc`, `hostname`/`host`, etc.). Si algo no cuadra con
tu CSV, edita la función correspondiente en `results.py`; cada paso está
aislado en su propia función.

---

## 4. Cosas que no he tocado

- **Docker** — tus `.sh` siguen gestionando Docker como lo hacían antes. El
  backend solo invoca el `.sh` y captura stdout. Si matas un job a medias, se
  mata también el process group, así que el contenedor recibe `SIGTERM`.
- **venv del proyecto** — el dashboard usa su propio venv (`web/backend/.venv`)
  que solo tiene Flask. No toco tu `requirements.txt`.
- **Gestión de usuarios** — no hay autenticación. Es un dashboard de desarrollo
  que se arranca localmente. Si quieres desplegarlo en red añade auth delante
  (nginx basic auth, por ejemplo).

---

## 5. Desarrollo y debugging

```bash
DEBUG=1 ./ejecutar_web.sh        # recarga en caliente del backend
```

El frontend NO necesita build: se sirve `.jsx` en bruto y Babel-standalone lo
compila en el navegador. Perfecto para iterar, malo para producción
(parseo JSX ~400 ms en cold start). Si lo necesitas en producción, montar un
build con Vite es trivial, pero para un TFG va sobradísimo como está.

Para probar las APIs sueltas:

```bash
curl localhost:5001/api/steps
curl -X POST localhost:5001/api/jobs/start \
  -H 'Content-Type: application/json' \
  -d '{"step_id":"pqc_sonda","args":{"max_hostnames":10,"repeticiones":1}}'
curl -N localhost:5001/api/jobs/<job_id>/stream   # -N = unbuffered, SSE
curl localhost:5001/api/results/pqc_sonda | jq .
```

---

## 6. Qué falta (pistas para después)

- Histórico de jobs: ahora mismo solo se recuerda el último de cada paso en
  memoria del backend. Si reinicias el server se pierde. Fácil de añadir
  persistiendo `job_manager.jobs` en un SQLite.
- Reconectar un SSE cuando recargas la página y hay un job vivo: el endpoint
  `/api/jobs/step/<step_id>` ya existe, solo falta consumirlo desde `App.jsx`
  en el mount.
- Descarga directa de CSVs desde la UI (un simple `<a href="/api/results/..">`
  servido como `application/octet-stream`).
