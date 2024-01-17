python3 glomar create --n_blocks 1000 volume
python3 glomar add volume magic /etc/passwd
python3 glomar add volume magic2 /etc/hosts
python3 glomar pack volume finished
python3 glomar get finished magic
python3 glomar get finished magic2
rm volume finished
