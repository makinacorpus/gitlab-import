

virtualenv --no-site-packages .
pip install -f requirements.txt

$ python gitlab_import.py -t xxxx  -l debug -p --push-repositories -u -s [--do-not-update-group-members ] [-do-not-update-group-readers]
