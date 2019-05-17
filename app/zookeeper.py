from flask import current_app
from kazoo.client import KazooState
from kazoo.exceptions import NodeExistsError, ZookeeperError, NoNodeError
from kazoo.recipe.watchers import ChildrenWatch
from kazoo.protocol.states import EventType
from multiprocessing import Condition

import json


class AppZoo:
    _znode_path = None
    _cv = Condition()

    def __init__(self, client, znode_data, storage_manager):
        self._client = client
        self._znode_data = znode_data

        self._client.start()
        self._client.add_listener(self.zoo_listener)
        self.create_znodes()
        self._storage_manager = storage_manager

        ChildrenWatch(self._client,
                      "/storage",
                      func=self.storage_children_watcher,
                      allow_session_lost=True,
                      send_event=False)

    def zoo_listener(self, state):
        if state == KazooState.LOST:
            # Register somewhere that the session was lost
            self._client.logger.warning('Session was lost')
        elif state == KazooState.SUSPENDED:
            # Handle being disconnected from Zookeeper
            self._client.logger.warning('Disconnected from Zookeeper')
        else:
            # Handle being connected/reconnected to Zookeeper
            self._client.logger.warning('Reconnected to Zookeeper')
            self._client.handler.spawn(self.create_znodes)

    def create_znodes(self):
        # TODO: maybe wrap create with proper try except handling instead of duplicating code
        try:
            self._client.create('/app', json.dumps(self._znode_data).encode())
        except NodeExistsError:
            # one of our brother workers has done this already
            self._client.logger.info('app znode already exists')
        except ZookeeperError:
            # other error occurred
            self._client.logger.info('Server error while creating znode')

        # check if we are trying to create multiple instances
        # of our ephemeral node
        if self._znode_path is not None:
            if self._client.exists(self._znode_path) is not None:
                return

        # create auth sequence znode for this worker
        try:
            self._znode_path = self._client.create('/app/', ephemeral=True, sequence=True)
        except NodeExistsError:
            # NOTE: this should be imposible. Maybe remove catch?
            self._client.logger.info('Sequence znode already exists?')
            self._znode_path = None
        except ZookeeperError:
            # other error occurred
            self._client.logger.info('Server error while creating znode')
            self._znode_path = None

    def get_znode(self):
        try:
            return self._client.exists("/auth")
        except ZookeeperError:
            return None

    def wait_for_znode(self, path):
        ret = self._client.exists(path, watch=self.watch_znode_creation)
        if ret is not None:
            return

        with self._cv:
            self._cv.wait()

    def watch_znode_creation(self, event):
        if event.type == EventType.CREATED:
            with self._cv:
                self._cv.notify_all()

    def get_znode_data(self, path):
        node = None
        try:
            node = self._client.get(path)
        except NoNodeError:
            return None
        except ZookeeperError:
            return None

        return json.loads(node[0])

    def storage_children_watcher(self, children):
        storage_services = self._storage_manager.get_storage_services()
        for child in list(set(children) - set(storage_services)):
            child_info = self.get_znode_data('/storage/{}'.format(child))
            if child_info is not None:
                self._storage_manager.register_storage_service(child, child_info)

        for child in list(set(storage_services) - set(children)):
            self._storage_manager.unregister_storage_service(child)
