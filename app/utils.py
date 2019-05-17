from flask import abort, current_app
from app.storage import Storage
from app import zk, storage_address
import random


def gen_storage(storage1_id, storage2_id):
    # TODO: IF ONLY ONE ACTIVE STORAGE SERVER ??????????
    storage_ids = []
    if storage1_id is None and storage2_id is None:

        if zk.get_children_info is None:
            abort(500, "Server error occurred while processing request")

        storage_ids = random.sample(zk.get_children_info, k=2)

    else:
        storage_ids[0] = storage1_id
        storage_ids[1] = storage2_id

    private_key = current_app.config.get('PRIVATE_KEY')

    if private_key is None:
        abort(500, "Server error occurred while processing request")

    s1 = Storage(storage_address+storage_ids[0]+'/',
                 current_app.config['STORAGE_{}_DOCKER_BASEURL'.format(storage_ids[0])],
                 current_app.config['TOKEN_ISSUER'], private_key, storage_ids[0])
    s2 = Storage(storage_address+storage_ids[1]+'/',
                 current_app.config['STORAGE_{}_DOCKER_BASEURL'.format(storage_ids[1])],
                 current_app.config['TOKEN_ISSUER'], private_key, storage_ids[1])
    return {'storage1': s1, 'storage2': s2}