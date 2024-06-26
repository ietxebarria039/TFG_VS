from functools import wraps
from flask import session, redirect, url_for, flash

def require_previous_page(required_page):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('last_page') != required_page:
                flash('You must follow the correct navigation flow.', 'warning')
                return redirect(url_for(required_page))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
