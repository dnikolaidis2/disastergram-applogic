from datetime import datetime, timedelta
from random import sample
import jwt
import urllib.parse
import requests


class Storage:
    """
    A class for making requests to a storage service

    ...
    Methods
    -------
    upload_image(image_id, filename, file, mime_type)
        uploads image to this objects corresponding storage service
    delete_image(image_id)
        delete image from this objects corresponding storage service
    gen_image_url(iamge_id)
        generate a public url to image for this storage service
    """

    def __init__(self, baseurl, docker_baseurl, issuer, private_key):
        """
        Parameters
        ----------
        baseurl : str
            The storage service's public facing baseurl
        docker_baseurl : str
            The storage service's docker baseurl
        issuer : str
            The token issuer to be used when generating tokens
        private_key: str, callable
            A str or a callable that returns an str with the services private key
        """

        self._baseurl = baseurl
        self._docker_baseurl = docker_baseurl
        self._issuer = issuer
        self._private_key = private_key if not callable(private_key) else private_key()

    def upload_image(self, image_id, filename, file, mime_type):
        """Uploads image to objects storage service.

        Parameters
        ----------
        image_id : str
            The id this image has been given
        filename : str
            The images filename in format "image_id.file_extension"
        file : str, file
            A str or file like object with the images data
        mimetype : str
            The images mimetype

        Returns
        ------
        response
            A requests response object as returned by requests
        """

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
        """Deletes image from objects storage service.

        Parameters
        ----------
        image_id : str
            The id for the image to delete

        Returns
        ------
        response
            A requests response object as returned by requests
        """

        token = jwt.encode({
            'iss': self._issuer,
            'sub': image_id,
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'purpose': 'DELETE',
        }, self._private_key, algorithm='RS256')

        return requests.delete(urllib.parse.urljoin(self._docker_baseurl, '{}/{}'.format(image_id, token.decode('utf-8'))))

    def gen_image_url(self, image_id):
        """Generate public image url for objects storage service.

        Parameters
        ----------
        image_id : str
            The id for the image to generate a url

        Returns
        ------
        url
            A url string
        
        """

        token = jwt.encode({
            'iss': self._issuer,
            'sub': image_id,
            'exp': datetime.utcnow() + timedelta(days=1),
            'purpose': 'READ',
        }, self._private_key, algorithm='RS256')

        return urllib.parse.urljoin(self._baseurl, '{}/{}'.format(image_id, token.decode('utf-8')))


class StorageManager:
    """
    A class for managing all storage services with public methods to use with zookeeper

    ...
    Methods
    -------
    upload_image(image_id, file)
        upload image to two random storage services
    delete_image(image_id, image_locations)
        delete image from coresponding image locations
    get_image_url(iamge_id, image_locations)
        get a public url for an image form one of the image locations
    register_storage_service(self, storage_id, storage_info)
        register a storage service with this object
    unregister_storage_service(self, storage_id)
        unregister a storage service for this object
    get_available_storage_services(self)
        get all available storage services
    """

    _storage_dict = {}

    def __init__(self, logger, issuer, private_key):
        """
        Parameters
        ----------
        logger : python logger
            A logger to use for log output
        issuer : str
            The token issuer to be used when generating tokens
        private_key: str, callable
            A str or a callable that returns an str with the services private key
        """

        self._logger = logger
        self._issuer = issuer
        self._private_key = private_key

    def upload_image(self, image_id, file):
        """Uploads image to two storage services and returns their locations

        Parameters
        ----------
        image_id : str
            The id for the image that is beeing uploaded
        file : flask file
            The file that was part of the request with the image to be saved

        Returns
        ------
        image_locations
            A list with the storage services id's where the image was saved
        None
            The images could not be uploaded to two servicess
        """

        file_extension = file.filename.rsplit('.', 1)[-1].lower()
        file_content = file.read()

        # get two random storage services from the ones available 
        services = sample(self._storage_dict.keys(), k=2)

        for service in services:
            if self._storage_dict[service].upload_image(image_id,
                                                        '{}.{}'.format(image_id, file_extension),
                                                        file_content,
                                                        file.mimetype).status_code != 201:
                return None

        return services

    def delete_image(self, image_id, image_locations):
        """Delete image from the two storage services given in image_locations

        Parameters
        ----------
        image_id : str
            The id for the image that will be deleted
        image_locations : list
            The storage service's id where the image was saved

        Returns
        ------
        True
            The image where successfully delete
        False
            The image could not be deleted
        """

        for service in image_locations:
            # This was done for images without replication
            if service == -1:
                continue

            storage = self._storage_dict.get(str(service))
            if storage is None:
                # storage serice is not online
                return False
            else:
                if storage.delete_image(image_id).status_code != 200:
                    # error on the storage service side
                    return False

        return True

    def get_image_url(self, image_id, image_locations):
        """Get image image url from one of the two storage services given in image_locations

        Parameters
        ----------
        image_id : str
            The id for the image to get a url for
        image_locations : list
            The storage service's id where the image was saved

        Returns
        ------
        url
            The image url
        None
            Could not get url for this image
        """

        service = sample(set(image_locations), k=1)
        no_replication = False
        # Check if this image was saved without replication
        if service == [-1]:
            no_replication = True
            # Get the other image_location
            service = image_locations[abs(image_locations.index(service[0]) - 1)]
        else
            service = service[0]

        storage = self._storage_dict.get(str(service))
        if storage is None:
            # could not get first storage service
            if no_replication:
                return None
            else
                # get other storage service
                storage = self._storage_dict.\
                    get(str(abs(image_locations.index(service) - 1)))
                if storage is None:
                    return None
        
        return service.gen_image_url(image_id)

    def register_storage_service(self, storage_id, storage_info):
        """Register a storage service with the storage manager object

        Parameters
        ----------
        storage_id : str
            The id of the storage service to be registered
        storage_info : dict
            The storage services information dict 

        """

        if storage_id not in self._storage_dict.keys():
            self._storage_dict[storage_id] = Storage(storage_info['BASEURL'],
                                                     storage_info['DOCKER_BASEURL'],
                                                     self._issuer,
                                                     self._private_key)

    def unregister_storage_service(self, storage_id):
        """Unregister a storage service with the storage manager object

        Parameters
        ----------
        storage_id : str
            The id of the storage service to be unregistered

        """
        
        try:
            del self._storage_dict[storage_id]
        except KeyError:
            self._logger.error('Error could not unregister storage service')

    def get_available_storage_services(self):
        """Get all registered storage services with storage manager object

        Returns
        ----------
        storage_services : list
            The id's of the available storage services as a list

        """

        return list(self._storage_dict.keys())
