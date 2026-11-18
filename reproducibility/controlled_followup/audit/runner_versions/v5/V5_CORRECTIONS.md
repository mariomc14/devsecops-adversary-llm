# Runner v5: correcciones tras la parada en la trayectoria 30/80

El 15/11/2026 la campaña se detuvo en la trayectoria 30 (`cn2_d / sonnet-4.6 / chaos_adt_no_feedback / rep 2`). Al revisarla aparecieron dos errores. La v5 corrige los dos. **No cambia el diseño científico.** Los prompts, modelos, tareas, thresholds, schedule, condiciones y la red fija `cvr2-network` son idénticos a la v4.

El directorio sigue llamándose `-v4` para no cambiar rutas a mitad de campaña. Cada intento registra la revisión del código (`runner_revision = v5-paginator-never-created-cleanup`).

## Cambios respecto a v4

1. **Falso positivo del validador en CN2-D.**
   - La v4 solo aceptaba una llamada directa a `cloudtrail.lookup_events()`.
   - Rechazaba `cloudtrail.get_paginator("lookup_events")`, que llama a la misma API LookupEvents.
   - Esto rechazó 20 de los 21 candidatos de CN2-D generados por Sonnet 4.6, y era su único error. Ninguno llegó a ejecutarse.
   - La v5 acepta las dos formas. Si un candidato no usa LookupEvents de ninguna manera, se sigue rechazando.
   - Revalidación offline de los 71 candidatos archivados: con la v5 cambian exactamente esos 20 (ahora pasan sin errores); los otros 51 no cambian.

2. **La campaña se repite entera desde cero.**
   - Las 7 trayectorias de CN2-D con Sonnet 4.6 afectadas (órdenes 5, 11, 12, 15, 17, 26 y 28) están identificadas en `INVALIDATED.json`.
   - Para que todas las trayectorias usen la misma revisión del runner y sigan el orden del calendario predeterminado, toda la primera ejecución se ha archivado sin modificarla (runner v4, trayectorias 1 a 30). Lleva sus hashes SHA-256 y el motivo en `ARCHIVE.json`.
   - Está en `previous_runs/run1_v4_halted_at_order30_20261115/`. **No se ha borrado nada.**
   - El runner solo lee `results/`, así que el próximo `--run` ejecuta las 80 trayectorias desde cero y nunca toca el archivo.

3. **Stacks en `DELETE_FAILED` por un recurso que nunca llegó a crearse.**
   - En la trayectoria 30, la plantilla generada llamaba al rol IAM `<intento>-role-<nombre del stack>`. Ese nombre tiene 73 caracteres y AWS admite como máximo 64.
   - IAM rechazó la creación. Sin embargo, CloudFormation reenvía el mismo nombre inválido en cada intento de borrado, así que el stack se quedaba en `DELETE_FAILED` y la campaña se detenía.
   - La v5 reintenta el borrado conservando (`RetainResources`) solo los recursos que cumplen todo esto: nunca llegaron a ningún estado `*_COMPLETE`, y AWS rechazó tanto su creación como su borrado por validación de entrada. Un recurso así no puede existir.
   - En cualquier otro caso la campaña se sigue deteniendo, igual que antes.
   - Queda registrado en el informe de limpieza y en `attempt_events.jsonl` (`cleanup_retained_never_created_resources`).
   - El fallo del candidato no cambia: la creación del stack falló y `Q_post` lo evalúa como siempre.

4. **Los informes de limpieza ya no se sobrescriben al reanudar.**
   - El `cleanup_report.json` anterior del intento se conserva como `cleanup_report_superseded_<UTC>.json`.
   - Queda registrado con el evento `previous_cleanup_report_preserved`.

## Estado

- El stack bloqueado de la trayectoria 30 se ha eliminado con la limpieza de la v5. Solo queda `cvr2-network`, y no hay roles ni instance profiles `cvr2*` en IAM.
- La validación estática es correcta y pasan los 20 tests.
- El pre-flight da `ready_for_run = true`.

## Relanzar la campaña

Desde el directorio de la campaña, con el mismo entorno Python:

```bash
cd <LOCAL_HOME>/ijis-experiments-controlled-validation/devsecops-adversary-llm-ijis-experiments-v4
source ../devsecops-adversary-llm-ijis-experiments-v2/automate/.venv/bin/activate
python -u controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --aws-profile default \
  --run 2>&1 | tee -a ../campaign_logs/v5/run_$(date -u +%Y%m%dT%H%M%SZ).log
```

Se ejecutan las 80 trayectorias, de la 1 a la 80, en el orden del calendario predeterminado.

Las reglas de las versiones anteriores se mantienen:

- No editar, borrar ni regenerar ningún intento a mano.
- Si la campaña se interrumpe, volver a lanzar el mismo `--run`.
- Si aparece `ambiguous_*_state`, detenerse y enviar el directorio del intento, incluido `attempt_events.jsonl`.
