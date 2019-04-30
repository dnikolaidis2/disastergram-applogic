#!/usr/local/bin/python

import os
from pathlib import Path
import subprocess

keyname = os.getcwd().rsplit('-', 1)[1]

instance_content = ['config.py',
					keyname,
					keyname+'.pub']

inst = Path('instance')

if not inst.exists():
	# directory does not exists make it 
	inst.mkdir()
else:
	# check if all the correct files are in the directory
	count = 0
	for child in inst.iterdir():
		if str(child.name) in instance_content:
			count += 1

	if count == len(instance_content):
		exit()


os.chdir('instance')

ret = subprocess.call(["ssh-keygen",
					   "-t", "rsa",
					   "-P", "",
					   "-f", keyname,
					   "-b", "4096"], stdout=subprocess.DEVNULL)

if ret == 0:
	print('Generated keys for service: ' + keyname )
else:
	print('An error occured while generating keys')
	exit()

piv_key = open(keyname).read().rstrip('\n')
pub_key = open(keyname + '.pub').read().rstrip('\n')
secret = os.urandom(64)

with open('config.py', 'w') as f:
	f.write('SECRET_KEY = {}\n'.format(secret))
	f.write('PUBLIC_KEY = b\'{}\'\n'.format(pub_key))
	f.write('PRIVATE_KEY = b{}\n'.format(repr(piv_key)))

	f.close()

print('Instance folder successfuly created')

