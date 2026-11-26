set -x
export PYTHONIOENCODING=utf-8
PY=.venv/Scripts/python.exe
$PY -m eval qa --model qwen3.5-4b --config baseline --max-tokens 512
$PY -m eval qa --model qwen3.5-4b --config hardened --max-tokens 512
$PY -m eval qa --model qwen3.5-2b --config baseline --max-tokens 512 --only attack_id,false_premise,cve,injection
$PY -m eval qa --model qwen3.5-2b --config hardened --max-tokens 512 --only attack_id,false_premise,cve,injection
echo QUEUE1-DONE
