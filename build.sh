#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# Description:

# rm -rf dist; python -m build . && twine upload -u ruanhao dist/*

tag=`date "+%Y%m%d%H%M%S"`
pytest --html=report-$tag.html --self-contained-html || exit 1

tempdir="$(mktemp -d)"
file "$tempdir"
python setup.py sdist -d "$tempdir" bdist_wheel -d "$tempdir"
echo "tempdir: $tempdir"
if [[ -n $1 ]]; then
    twine upload $tempdir/*
    # twine upload --repository-url $1 $tempdir/*
    exit 0
fi
