import logging
from collections import namedtuple

from data.events_model.interface import EventsInterface
from data.events_model.events_model import EventsModel


logger = logging.getLogger(__name__)


class EventsModelProxy(EventsInterface):
    def configure(self):
        self.model = EventsModel()

        logger.info("===============================")
        logger.info("Using events model: default")
        logger.info("===============================")

        return self

    def publish(self, event):
        return self.model.publish(event)

    def subscribe(self, callback):
        return self.model.subscribe(callback)

events_model = EventsModelProxy()
