# Runner v6: corrección tras la parada en la trayectoria 20/80

El 16/11/2026 la campaña reiniciada con la v5 se detuvo en la trayectoria 20 (`cn1_p / sonnet-4.6 / conventional_adt_feedback / rep 2`, intento 2). Era un fallo del runner, no del modelo ni de AWS. **No cambia el diseño científico.** Los prompts, modelos, tareas, thresholds, schedule, condiciones, la validación técnica, `Q_pre`/`Q_post`, la limpieza y la red fija `cvr2-network` son idénticos a la v5.

El directorio sigue llamándose `-v4`. Cada intento registra la revisión del código (`runner_revision = v6-artifact-order-json-guard`).

## Qué pasó

- El prompt pide "exactly two fenced artifacts, first Python and then JSON".
- En el intento 2, el modelo explicó el error del intento anterior citando un trozo de la plantilla (`"ImageId": {...}`) en un bloque JSON **antes** del Python. Después dio el Python y el JSON completos.
- La v5 tomaba como manifiesto el primer bloque JSON. Ese trozo no es JSON válido, y el error no estaba controlado, así que la campaña se paró.
- El fallo era determinista: al relanzar `--run` se habría parado otra vez en el mismo punto.

## Cambios respecto a v5

1. **El JSON se toma después del Python.** El manifiesto es el primer bloque JSON que aparece después del bloque Python, como pide el prompt. Si no hay ninguno, se toma el primero (regla de la v5). El Python sigue siendo el primer bloque Python.
2. **Un manifiesto que no es JSON válido ya no para la campaña.** El intento queda como `technical_rejected` con el error de parseo, igual que cualquier otro rechazo técnico. Queda registrado en `attempt_events.jsonl` (`manifest_unparseable_kept_verbatim`).

## Las trayectorias 1 a 19 no se repiten

- **Extracción:** en las 115 respuestas guardadas (esta ejecución y la ejecución 1 archivada), la v6 extrae exactamente lo mismo que la v5 en 114. Solo cambia el intento parado.
- **Validación técnica:** los 38 candidatos de las trayectorias 1 a 19 dan el mismo veredicto con la v5 y con la v6 (38/38).
- **Prompts:** las 20 combinaciones son idénticas byte a byte.
- **Ejecución:** las 19 trayectorias están completas con la v5, sin paradas, errores de infraestructura ni reintentos de llamadas al modelo.
- **Trayectoria 5:** la limpieza de la v5 actuó una vez, como estaba previsto. Un rol IAM con nombre de más de 64 caracteres nunca llegó a crearse.
- **Trayectoria 20:** el intento 1 es válido y se conserva. El intento 2 se reanuda desde su respuesta guardada, sin volver a llamar al modelo.

## Estado

- La validación estática es correcta y pasan los 24 tests.
- La batería de reanudación (`campaign_logs/v6/tools/resume_harness.py`) pasa los 13 escenarios, incluidos los dos de este fallo.
- El pre-flight da `ready_for_run = true`.
- En AWS solo queda `cvr2-network`. No hay stacks, roles, instance profiles ni instancias EC2 `cvr2*` de intentos anteriores.
- Las pruebas, el diff y una copia del código v5 están en `campaign_logs/v6/`.

## Relanzar la campaña

Es el mismo comando. Retoma la trayectoria 20 y continúa hasta la 80:

```bash
cd <LOCAL_HOME>/ijis-experiments-controlled-validation/devsecops-adversary-llm-ijis-experiments-v4
source ../devsecops-adversary-llm-ijis-experiments-v2/automate/.venv/bin/activate
python -u controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --aws-profile default \
  --run 2>&1 | tee -a ../campaign_logs/v6/run_$(date -u +%Y%m%dT%H%M%SZ).log
```

Las reglas de las versiones anteriores se mantienen:

- No editar, borrar ni regenerar ningún intento a mano.
- Si la campaña se interrumpe, volver a lanzar el mismo `--run`.
- Si aparece `ambiguous_*_state`, detenerse y enviar el directorio del intento, incluido `attempt_events.jsonl`.
