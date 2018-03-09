from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid.security import ALL_PERMISSIONS, Allow, Authenticated
from pyramid.session import UnencryptedCookieSessionFactoryConfig
from sqlalchemy import engine_from_config
from .helpers import get_queue_func
from .models import configure_sql, create_schema, populate_database
from .security import get_user, group_finder

__version__ = '1.0.3'


class Root(object):
    __acl__ = [(Allow, Authenticated, 'authenticated'),
               (Allow, 'admin', ALL_PERMISSIONS)]

    def __init__(self, request):
        self.request = request


def add_routes(config):
    # Application routes
    config.add_route('home', '/')
    config.add_route('robots', '/robots.txt')
    config.add_route('build_file', '/build_file')
    config.add_route('build_file_item', '/build_file/{build_file_id}')
    config.add_route('class', '/class')
    config.add_route('class.admins', '/class/{class_id}/admins'),
    config.add_route('class_item', '/class/{class_id}')
    config.add_route('execution_file', '/execution_file')
    config.add_route('execution_file_item',
                     '/execution_file/{execution_file_id}')
    config.add_route('file', '/file')
    config.add_route('file_item', '/file/{sha1sum}/{filename}')
    config.add_route('file_verifier', '/file_verifier')
    config.add_route('file_verifier_item', '/file_verifier/{file_verifier_id}')
    config.add_route('password_reset', '/password_reset')
    config.add_route('password_reset_item', '/password_reset/{token}')
    config.add_route('project', '/p')
    config.add_route('project_group', '/p/{project_id}/group')
    config.add_route('project_group_item',
                     '/p/{project_id}/group/{group_request_id}')
    config.add_route('project_info', '/p/{project_id}/info')
    config.add_route('project_item_download', '/p/{project_id}/download')
    config.add_route('project_item_summary', '/p/{project_id}')
    config.add_route('project_item_detailed', '/p/{project_id}/g/{group_id}')
    config.add_route('project_item_detailed_user',
                     '/p/{project_id}/u/{username}')
    config.add_route('project_scores', '/p/{project_id}/scores')
    config.add_route('session', '/session')
    config.add_route('submission', '/submission')
    config.add_route('submission_item', '/submission/{submission_id}')
    config.add_route('submission_item_gen', '/submission/{submission_id}/gen')
    config.add_route('test_case', '/test_case')
    config.add_route('test_case_item', '/test_case/{test_case_id}')
    config.add_route('testable', '/testable')
    config.add_route('testable_item', '/testable/{testable_id}')
    config.add_route('user', '/user')
    config.add_route('user_item', '/user/{username}')
    config.add_route('zipfile_download', '/zipfile_download/{submission_id}')

    # Form view routes
    config.add_route('class_new', '/form/class')
    config.add_route('class_edit', '/form/class/{class_id}')
    config.add_route('project_new', '/form/class/{class_id}/project')
    config.add_route('project_edit', '/form/project/{project_id}')
    config.add_route('group_admin', '/form/project/{project_id}/group')
    config.add_route('submission_new', '/form/project/{project_id}/submission')
    config.add_route('user_new', '/form/user')
    config.add_route('user_new_special', '/form/user_special')
    config.add_route('user_join', '/form/user/join')


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    # Initialize the database
    engine = engine_from_config(settings, 'sqlalchemy.')
    configure_sql(engine)

    secure_cookies = True
    if 'pyramid_debugtoolbar' in settings['pyramid.includes']:
        create_schema(global_config['__file__'])
        populate_database()
        secure_cookies = False

    # Configure the webapp
    authen = AuthTktAuthenticationPolicy(secret=settings['auth_secret'],
                                         callback=group_finder,
                                         secure=secure_cookies,
                                         include_ip=False, hashalg='sha512',
                                         wild_domain=False, max_age=5000000)
    author = ACLAuthorizationPolicy()
    session_factory = UnencryptedCookieSessionFactoryConfig(
        settings['cookie_secret'])
    config = Configurator(settings=settings, authentication_policy=authen,
                          authorization_policy=author, root_factory=Root,
                          session_factory=session_factory)
    config.add_static_view('static', 'static', cache_max_age=3600)
    # Add attributes to request
    config.add_request_method(get_user, 'user', reify=True)
    config.add_request_method(get_queue_func, 'queue', reify=True)

    add_routes(config)
    config.scan()
    return config.make_wsgi_app()
