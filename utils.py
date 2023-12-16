import typing


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


def filter_items(filter_string: str,
                 argument_separator: str = " ",
                 range_separator: str = ":") -> typing.List[int]:
    args = filter_string.split(argument_separator)
    values = []
    for arg in args:
        try:
            if range_separator in arg:
                min_val, max_val = arg.split(range_separator)
                values.extend(list(range(int(min_val), int(max_val) + 1)))
            else:
                values.append(int(arg))
        except ValueError:
            pass
    return sorted(set(values))
