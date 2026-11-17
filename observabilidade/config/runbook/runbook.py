"""Runbook de self-healing do ToggleMaster.

Recebe o webhook do alerta do Grafana e faz o equivalente a
`kubectl rollout restart deployment/<nome>` pela API do Kubernetes, usando a
ServiceAccount do próprio pod. Sem dependência externa: só biblioteca padrão.
"""

import hmac
import json
import os
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API = "https://kubernetes.default.svc"
CONTA = "/var/run/secrets/kubernetes.io/serviceaccount"

NAMESPACE = os.environ["NAMESPACE_ALVO"]
PERMITIDOS = set(os.environ["DEPLOYMENTS_PERMITIDOS"].split(","))
TOKEN = os.environ["RUNBOOK_TOKEN"]
# sem carência, um alerta que continua disparando reiniciaria o serviço em loop
CARENCIA = int(os.environ.get("CARENCIA_SEGUNDOS", "300"))

ultimo_restart = {}
trava = threading.Lock()


def registrar(evento, **campos):
    linha = {"hora": datetime.now(timezone.utc).isoformat(timespec="seconds"), "evento": evento}
    linha.update(campos)
    print(json.dumps(linha, ensure_ascii=False), flush=True)


def chamar_api(metodo, caminho, corpo=None, tipo="application/json"):
    with open(f"{CONTA}/token", encoding="utf-8") as f:
        token = f.read()
    dados = json.dumps(corpo).encode() if corpo is not None else None
    req = urllib.request.Request(
        API + caminho,
        data=dados,
        method=metodo,
        headers={"Authorization": f"Bearer {token}", "Content-Type": tipo},
    )
    contexto = ssl.create_default_context(cafile=f"{CONTA}/ca.crt")
    with urllib.request.urlopen(req, context=contexto, timeout=10) as resp:  # nosec B310 - url fixa da API do cluster
        return json.loads(resp.read())


def acompanhar_rollout(deployment, inicio):
    caminho = f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{deployment}"
    for _ in range(60):
        time.sleep(5)
        try:
            d = chamar_api("GET", caminho)
        except Exception as erro:  # noqa: BLE001
            registrar("erro_ao_acompanhar", deployment=deployment, erro=str(erro))
            continue
        status, spec = d.get("status", {}), d.get("spec", {})
        pronto = (
            status.get("observedGeneration", 0) >= d["metadata"]["generation"]
            and status.get("updatedReplicas", 0) == spec.get("replicas", 1)
            and status.get("availableReplicas", 0) == spec.get("replicas", 1)
            and status.get("replicas", 0) == spec.get("replicas", 1)
        )
        if pronto:
            registrar("rollout_concluido", deployment=deployment, segundos=round(time.time() - inicio))
            return
    registrar("rollout_sem_confirmacao", deployment=deployment, segundos=round(time.time() - inicio))


def reiniciar(deployment, alerta):
    agora = time.time()
    with trava:
        anterior = ultimo_restart.get(deployment, 0)
        if agora - anterior < CARENCIA:
            registrar("ignorado_por_carencia", deployment=deployment, alerta=alerta,
                      segundos_desde_o_ultimo=round(agora - anterior))
            return
        ultimo_restart[deployment] = agora

    # é exatamente o patch que o kubectl rollout restart envia: mudar uma anotação do template
    # faz o deployment criar pods novos e só derrubar os antigos quando os novos ficam prontos
    marca = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    corpo = {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": marca}}}}}
    try:
        chamar_api(
            "PATCH",
            f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{deployment}",
            corpo,
            tipo="application/strategic-merge-patch+json",
        )
    except Exception as erro:  # noqa: BLE001
        registrar("falha_no_restart", deployment=deployment, alerta=alerta, erro=str(erro))
        with trava:
            ultimo_restart.pop(deployment, None)
        return

    registrar("rollout_restart_executado", deployment=deployment, namespace=NAMESPACE, alerta=alerta)
    threading.Thread(target=acompanhar_rollout, args=(deployment, agora), daemon=True).start()


class Receptor(BaseHTTPRequestHandler):
    def responder(self, codigo, corpo):
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(corpo).encode())

    def do_GET(self):  # noqa: N802
        if self.path == "/saude":
            self.responder(200, {"status": "ok"})
        else:
            self.responder(404, {"erro": "rota inexistente"})

    def do_POST(self):  # noqa: N802
        if self.path != "/alerta":
            self.responder(404, {"erro": "rota inexistente"})
            return

        recebido = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(recebido, TOKEN):
            registrar("chamada_recusada", origem=self.client_address[0])
            self.responder(401, {"erro": "token invalido"})
            return

        tamanho = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(tamanho))
        except json.JSONDecodeError:
            self.responder(400, {"erro": "json invalido"})
            return

        registrar("webhook_recebido", status=payload.get("status"), alertas=len(payload.get("alerts", [])))

        for alerta in payload.get("alerts", []):
            rotulos = alerta.get("labels", {})
            nome = rotulos.get("alertname", "?")
            alvo = rotulos.get("deployment")
            if alerta.get("status") != "firing":
                registrar("alerta_resolvido", deployment=alvo, alerta=nome)
                continue
            if alvo not in PERMITIDOS:
                registrar("alvo_fora_da_lista", deployment=alvo, alerta=nome)
                continue
            reiniciar(alvo, nome)

        self.responder(200, {"recebido": True})

    def log_message(self, formato, *args):
        # o log de acesso padrão polui a saída que vai para o relatório
        pass


if __name__ == "__main__":
    registrar("runbook_iniciado", namespace=NAMESPACE, permitidos=sorted(PERMITIDOS), carencia=CARENCIA)
    ThreadingHTTPServer(("0.0.0.0", 8080), Receptor).serve_forever()  # nosec B104 - escuta dentro do pod
