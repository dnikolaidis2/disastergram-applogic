from datetime import datetime, timedelta
from random import sample
import jwt
import urllib.parse
import requests


class Storage:

    def __init__(self, baseurl, docker_baseurl, issuer, private_key):
        self._baseurl = baseurl
        self._docker_baseurl = docker_baseurl
        self._issuer = issuer
        self._private_key = private_key if not callable(private_key) else private_key()

    def upload_image(self, image_id, filename, file, mime_type):
        files = {'file': (filename, file, mime_type)}

        token = jwt.encode({
            'iss': self._issuer,
            'sub': image_id,
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'purpose': 'CREATE',
        }, self._private_key, algorithm='RS256')

        return requests.post(urllib.parse.urljoin(self._docker_baseurl, '{}/{}'.format(image_id, token.decode('utf-8'))),
                             files=files)

    def delete_image(self, image_id):

        token = jwt.encode({
            'iss': self._issuer,
            'sub': image_id,
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'purpose': 'DELETE',
        }, self._private_key, algorithm='RS256')

        return requests.delete(urllib.parse.urljoin(self._docker_baseurl, '{}/{}'.format(image_id, token.decode('utf-8'))))

    def gen_image_url(self, image_id):

        token = jwt.encode({
            'iss': self._issuer,
            'sub': image_id,
            'exp': datetime.utcnow() + timedelta(days=1),
            'purpose': 'READ',
        }, self._private_key, algorithm='RS256')

        return urllib.parse.urljoin(self._baseurl, '{}/{}'.format(image_id, token.decode('utf-8')))


class StorageManager:
    _storage_dict = {}

    def __init__(self, logger, issuer, private_key):
        self._logger = logger
        self._issuer = issuer
        self._private_key = private_key

    def upload_image(self, image_id, file):
        file_extension = file.filename.rsplit('.', 1)[-1].lower()

        services = sample(self._storage_dict.keys(), k=2)

        for service in services:
            if self._storage_dict[service].upload_image(image_id,
                                                        '{}.{}'.format(image_id, file_extension),
                                                        file,
                                                        file.mimetype).status_code != 201:
                return None

        return services

    def delete_image(self, image_id, image_locations):
        for service in image_locations:
            if service == -1:
                continue

            storage = self._storage_dict.get(str(service))
            if storage is None:
                return False
            else:
                if storage.delete_image(image_id).status_code != 200:
                    return False

        return True

    def get_image_url(self, image_id, image_locations):
        service = sample(set(image_locations), k=1)
        while service == -1:
            service = sample(set(image_locations), k=1)

        return self._storage_dict.get(str(service[0])).gen_image_url(image_id)

    def register_storage_service(self, storage_id, storage_info):
        if storage_id not in self._storage_dict.keys():
            self._storage_dict[storage_id] = Storage(storage_info['BASEURL'],
                                                     storage_info['DOCKER_BASEURL'],
                                                     self._issuer,
                                                     self._private_key)

    def unregister_storage_service(self, storage_id):
        try:
            del self._storage_dict[storage_id]
        except KeyError:
            self._logger.error('Error could not unregister storage service')

    def get_storage_services(self):
        return list(self._storage_dict.keys())
