from kazoo.client import KazooState
from kazoo.exceptions import NodeExistsError, ZookeeperError

import json


class AppZoo:

    def __init__(self, client, znode_data):
        self._client = client
        self._znode_data = znode_data

        self._client.start()
        self._client.add_listener(self.zoo_listener)
        self.create_znodes()

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
        # create auth znode if it does not exist
        self._client.ensure_path("/app-logic")
        try:
            self._client.create('/app-logic/app', json.dumps(self._znode_data).encode())
        except NodeExistsError:
            # one of our brother workers has done this already
            self._client.logger.info('app znode already exists')
        except ZookeeperError:
            # other error occurred
            self._client.logger.info('Server error while creating znode')


