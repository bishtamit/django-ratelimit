import hashlib
import re
import time
import zlib
from importlib import import_module

from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured

from ratelimit import ALL, UNSAFE


__all__ = ['is_ratelimited']

_PERIODS = {
    's': 1,
    'm': 60,
    'h': 60 * 60,
    'd': 24 * 60 * 60,
}

# Extend the expiration time by a few seconds to avoid misses.
EXPIRATION_FUDGE = 5


def user_or_ip(request):
    if request.user.is_authenticated:
        return str(request.user.pk)
    return request.META['REMOTE_ADDR']


_SIMPLE_KEYS = {
    'ip': lambda r: r.META['REMOTE_ADDR'],
    'user': lambda r: str(r.user.pk),
    'user_or_ip': user_or_ip,
}


def get_header(request, header):
    key = 'HTTP_' + header.replace('-', '_').upper()
    return request.META.get(key, '')


_ACCESSOR_KEYS = {
    'get': lambda r, k: r.GET.get(k, ''),
    'post': lambda r, k: r.POST.get(k, ''),
    'header': get_header,
}


def _method_match(request, method=ALL):
    if method == ALL:
        return True
    if not isinstance(method, (list, tuple)):
        method = [method]
    return request.method in [m.upper() for m in method]


rate_re = re.compile(r'([\d]+)/([\d]*)([smhd])?')
fl_re = re.compile(r'([\d]*)([smhd])?')


def _calculate_lock_duration(fl):
    multi, period = fl_re.match(fl).groups()
    if not period:
        period = 's'
    seconds = _PERIODS[period.lower()]
    if multi:
        seconds = seconds * int(multi)
    return seconds

def _split_rate(rate):
    if isinstance(rate, tuple):
        return rate
    count, multi, period = rate_re.match(rate).groups()
    count = int(count)
    if not period:
        period = 's'
    seconds = _PERIODS[period.lower()]
    if multi:
        seconds = seconds * int(multi)
    return count, seconds


def _get_window(value, period):
    ts = int(time.time())
    if period == 1:
        return ts
    if not isinstance(value, bytes):
        value = value.encode('utf-8')
    w = ts - (ts % period) + (zlib.crc32(value) % period)
    if w < ts:
        return w + period
    return w


def _make_cache_key(group, rate, value, methods, use_window=True):
    count, period = _split_rate(rate)
    safe_rate = '%d/%ds' % (count, period)
    if use_window:
        window = _get_window(value, period)
        parts = [group + safe_rate, value, str(window)]
    else:
        parts = [group + safe_rate, value]

    if methods is not None:
        if methods == ALL:
            methods = ''
        elif isinstance(methods, (list, tuple)):
            methods = ''.join(sorted([m.upper() for m in methods]))
        parts.append(methods)
    prefix = getattr(settings, 'RATELIMIT_CACHE_PREFIX', 'rl:')
    return prefix + hashlib.md5(u''.join(parts).encode('utf-8')).hexdigest()



def is_ratelimited(request, group=None, fn=None, key=None, rate=None,
                   method=ALL, increment=False, lock_for=None):
    if lock_for is None:
        raise ImproperlyConfigured("lock_for duration must be provided")

    lock_for = _calculate_lock_duration(lock_for)
    # print 'lock duration set to:', lock_for

    if group is None:
        if hasattr(fn, '__self__'):
            parts = fn.__module__, fn.__self__.__class__.__name__, fn.__name__
        else:
            parts = (fn.__module__, fn.__name__)
        group = '.'.join(parts)

    if not getattr(settings, 'RATELIMIT_ENABLE', True):
        request.limited = False
        return False

    if not _method_match(request, method):
        return False

    old_limited = getattr(request, 'limited', False)

    if callable(rate):
        rate = rate(group, request)

    if rate is None:
        request.limited = old_limited
        return False

    # get cache object
    cache_store = getattr(settings, 'RATELIMIT_USE_CACHE', 'default')
    cache = caches[cache_store]

    # create a cache key for caller
    value = key_to_value(key, group, request)
    cache_key = _make_cache_key(group, rate, value, method, use_window=False)
    # print(cache_key)
    lock_info = cache.get(cache_key)

    # print 'locked info: ', lock_info
    ts = time.time()
    # print'current timestamp: ', ts

    if lock_info:
        blocked = lock_info['blocked']
        block_window = lock_info['block_window']
        # print 'block', block_window
        if blocked and block_window and ts < block_window:
            # print 'LOCKED. time left for unlock', block_window - ts
            return True

    usage = get_usage_count(request, group, fn, key, rate, method, increment)
    # print 'usage: ', usage

    fail_open = getattr(settings, 'RATELIMIT_FAIL_OPEN', False)

    usage_count = usage.get('count')
    usage_limit = usage.get('limit')

    if usage_count is None:
        limited = not fail_open
    else:
        limited = usage_count > usage_limit

    if usage_count > usage_limit:
        # print 'usage exceeded limit, setting the cache'
        cache.set(cache_key, {
            'blocked': True,
            'block_window': ts + lock_for if lock_for else None
        })
    else:
        # print('none')
        cache.set(cache_key, None)

    print "="*50
    if increment:
        request.limited = old_limited or limited
    return limited


def key_to_value(key, group, request):
    if callable(key):
        value = key(group, request)
    elif key in _SIMPLE_KEYS:
        value = _SIMPLE_KEYS[key](request)
    elif ':' in key:
        accessor, k = key.split(':', 1)
        if accessor not in _ACCESSOR_KEYS:
            raise ImproperlyConfigured('Unknown ratelimit key: %s' % key)
        value = _ACCESSOR_KEYS[accessor](request, k)
    elif '.' in key:
        mod, attr = key.rsplit('.', 1)
        keyfn = getattr(import_module(mod), attr)
        value = keyfn(group, request)
    else:
        raise ImproperlyConfigured(
            'Could not understand ratelimit key: %s' % key)
    return value

def get_usage_count(request, group=None, fn=None, key=None, rate=None,
                    method=ALL, increment=False):
    if not key:
        raise ImproperlyConfigured('Ratelimit key must be specified')
    limit, period = _split_rate(rate)
    cache_name = getattr(settings, 'RATELIMIT_USE_CACHE', 'default')
    cache = caches[cache_name]

    value = key_to_value(key, group, request)

    cache_key = _make_cache_key(group, rate, value, method)
    time_left = _get_window(value, period) - int(time.time())
    initial_value = 1 if increment else 0
    added = cache.add(cache_key, initial_value, period + EXPIRATION_FUDGE)
    if added:
        count = initial_value
    else:
        if increment:
            try:
                count = cache.incr(cache_key)
            except ValueError:
                count = initial_value
        else:
            count = cache.get(cache_key, initial_value)
    return {'count': count, 'limit': limit, 'time_left': time_left}


is_ratelimited.ALL = ALL
is_ratelimited.UNSAFE = UNSAFE
