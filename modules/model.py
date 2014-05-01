class Cracker(object):
    """Base class to every cracker class"""

    @classmethod
    def algo_supported(cls, algo):
        raise NotImplementedError("You should never use this class directly")

    @classmethod
    def crack(cls, hash):
        raise NotImplementedError("You should never use this class directly")
