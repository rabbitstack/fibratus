# https://stackoverflow.com/questions/2352181/how-to-use-a-dot-to-access-members-of-dictionary
class dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def dotdictify(fn):
    """
    The decorator for converting the dict parameter to dot notation access dictionary.
    """
    def __wrap(event):
        event = dotdict(event)
        event.params = dotdict(event.params)
        return fn(event)
    return __wrap
