

virtualenv --no-site-packages .
pip install -f requirements.txt

$ python gitlab_import.py -t xxxx -l debug -u -s -p [--do-not-update-group-members ] [-do-not-update-group-readers]
