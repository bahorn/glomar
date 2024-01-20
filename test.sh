python3 glomar create --n-blocks 1000 --block-size 3000 volume
python3 glomar add volume magic /etc/passwd
python3 glomar add volume magic2 /etc/hosts
python3 glomar pack volume finished
python3 glomar get --block-size 3000 finished magic
python3 glomar get --block-size 3000 finished magic2
rm volume finished
