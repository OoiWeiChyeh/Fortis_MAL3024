while ! grep -q QUEUE1-DONE eval/results/queue1.log 2>/dev/null; do sleep 60; done
set -x
export PYTHONIOENCODING=utf-8
PY=.venv/Scripts/python.exe
$PY -m eval redteam --model qwen3.5-4b --config baseline --max-tokens 384
$PY -m eval redteam --model qwen3.5-4b --config hardened --max-tokens 384
$PY -m eval triage --model qwen3.5-4b --config hardened
$PY -m eval ioc --model qwen3.5-4b --config hardened
echo QUEUE2-DONE
