#!/usr/bin/env fish

function cmd__mypy
    mypy --strict acmeerkat/
end

function cmd__flake8
    flake8 $argv acmeerkat/
end

function cmd__pytest
    PYTHONPATH=. pytest $argv
end

function cmd__zip
    set amversion (grep 'version' pyproject.toml | string match -rg '.*"(.*)"')
    set zfilename "acmeerkat.$amversion.zip"
    rm $zfilename
    zip -r9 $zfilename acmeerkat -x '*.pyc' '*__pycache__*'
end

# -----

if not set -q argv[1]
    echo 'Command required'
    return 1
end
set command 'cmd__'$argv[1]
if not test "$(type --type $command 2> /dev/null)" = 'function'
    echo "Command $argv[1] does not exit"
    return 1
end
$command $argv[2..]
