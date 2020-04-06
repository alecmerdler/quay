from abc import ABCMeta, abstractmethod
from six import add_metaclass


class UnsupportedEventException(Exception):
    """
    Exception raised when trying to publish or subscribe to an unsupported event type.
    """
    pass


class SubscriptionInterface(object):
    """
    Represents a cancelable subscription to a stream of events. 
    """

    @abstractmethod
    def cancel(self):
        """
        Stop receiving events.
        """
        pass


@add_metaclass(ABCMeta)
class EventsInterface(object):
    """
    Interface for code to work with the events data model.

    This model encapsulates all access when accessing events, as well as any
    data tracking in the database.
    """

    @abstractmethod
    def publish(self, event):
        """
        Emits a new `Event` to all subscribers.
        """
        pass
    
    @abstractmethod
    def subscribe(self, callback):
        """
        Begin receiving events. Returns a `Subscription`.
        """
        pass
