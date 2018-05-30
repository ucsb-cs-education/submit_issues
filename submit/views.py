from __future__ import unicode_literals
import codecs
import numpy
import os
import transaction
from base64 import b64decode
from hashlib import sha1
from pyramid_addons.helpers import (http_created, http_gone, http_ok)
from pyramid_addons.validation import (EmailAddress, Enum, List, Or, String,
                                       RegexString, TextNumber,
                                       WhiteSpaceString, validate, SOURCE_GET,
                                       SOURCE_MATCHDICT as MATCHDICT)
from pyramid.httpexceptions import (HTTPBadRequest, HTTPConflict, HTTPError,
                                    HTTPFound, HTTPNotFound, HTTPOk,
                                    HTTPRedirection, HTTPSeeOther)
from pyramid.response import FileResponse, Response
from pyramid.security import forget, remember
from pyramid.settings import asbool
from pyramid.view import (forbidden_view_config, notfound_view_config,
                          view_config)
from sqlalchemy.exc import IntegrityError
from .diff_render import HTMLDiff
from .exceptions import GroupWithException, InvalidId
from .helpers import (
    AccessibleDBThing, DBThing as AnyDBThing, DummyTemplateAttr,
    EditableDBThing, TestableStatus, TextDate, ViewableDBThing, UmailAddress,
    add_user, clone, fetch_request_ids, file_verifier_verification,
    prepare_renderable, prev_next_submission, prev_next_group,
    project_file_create, project_file_delete, send_email,
    test_case_verification, zip_response)
from .models import (BuildFile, Class, ExecutionFile, File, FileVerifier,
                     Group, GroupRequest, PasswordReset, Project, Session,
                     Submission, SubmissionToFile, TestCase, Testable, User,
                     UserToGroup)

# Hack for old pickle files
# TODO: Migrate this data to not use pickle
import sys
import submit
sys.modules['nudibranch'] = submit
sys.modules['nudibranch.diff_unit'] = submit.diff_unit
sys.modules['nudibranch.models'] = submit.models

# A few reoccuring validators
OUTPUT_SOURCE = Enum('output_source', 'stdout', 'stderr', 'file')
OUTPUT_TYPE = Enum('output_type', 'diff', 'image', 'text')
SHA1_VALIDATOR = String('sha1sum', min_length=40, max_length=40,
                        source=MATCHDICT)
UUID_VALIDATOR = String('token', min_length=36, max_length=36,
                        source=MATCHDICT)


# We need a specific view config for each of HTTPError, HTTPOk, and
# HTTPRedirection as HTTPException will not work as a context. Because python
# has explicit decorators for forbidden and notfound (and we use them) we must
# also use those decorators here.
@forbidden_view_config(xhr=True, renderer='json')
@notfound_view_config(xhr=True, renderer='json')
@view_config(context=HTTPError, xhr=True, renderer='json')
@view_config(context=HTTPOk, xhr=True, renderer='json')
@view_config(context=HTTPRedirection, xhr=True, renderer='json')
def json_exception(context, request):
    """Always return json content in the body of Exceptions to xhr requests."""
    request.response.status = context.code
    return {'error': context._status, 'messages': context.message}


# Prevent PredicateMismatch exception
@view_config(context=HTTPError)
@view_config(context=HTTPOk)
@view_config(context=HTTPRedirection)
def normal_exception(context, request):
    """Just return the normal context"""
    return context


@forbidden_view_config()
def forbidden_view(context, request):
    if request.user:
        return context
    request.session.flash('You must be logged in to do that.', 'warnings')
    return HTTPSeeOther(request.route_path('session',
                                           _query={'next': request.path}))


@notfound_view_config()
def not_found(request):
    return Response('Not Found', status='404 Not Found')


@view_config(route_name='robots', request_method='GET', http_cache=86400)
def robots(request):
    return Response(body='User-agent: *\nDisallow: /\n',
                    content_type=str('text/plain'))


@view_config(route_name='build_file', request_method='PUT',
             permission='authenticated', renderer='json')
@validate(file_=ViewableDBThing('file_id', File),
          filename=String('filename', min_length=1),
          project=EditableDBThing('project_id', Project))
def build_file_create(request, file_, filename, project):
    return project_file_create(request, file_, filename, project, BuildFile)


@view_config(route_name='build_file_item', request_method='DELETE',
             permission='authenticated', renderer='json')
@validate(build_file=EditableDBThing('build_file_id', BuildFile,
                                     source=MATCHDICT))
def build_file_delete(request, build_file):
    return project_file_delete(request, build_file)


@view_config(route_name='class.admins', renderer='json', request_method='PUT')
@validate(class_=EditableDBThing('class_id', Class, source=MATCHDICT),
          user=AnyDBThing('email', User, fetch_by='username',
                          validator=EmailAddress('email')))
def class_admins_add(request, class_, user):
    if user in class_.admins:
        raise HTTPConflict('That user is already an admin for the class.')
    user.admin_for.append(class_)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('The user could not be added.')
    request.session.flash('Added {} as an admin to the class.'.format(user),
                          'successes')
    return http_ok(request, redir_location=request.url)


@view_config(route_name='class.admins', request_method='GET',
             permission='authenticated',
             renderer='templates/forms/class_admins.pt')
@validate(class_=EditableDBThing('class_id', Class, source=MATCHDICT))
def class_admins_view(request, class_):
    return {'class_': class_}


@view_config(route_name='class', request_method='PUT', permission='admin',
             renderer='json')
@validate(name=String('name', min_length=3))
def class_create(request, name):
    class_ = Class(name=name)
    Session.add(class_)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('Class \'{0}\' already exists'.format(name))
    request.session.flash('Created class {}'.format(name), 'successes')
    return http_created(request,
                        redir_location=request.route_path('class_new'))


@view_config(route_name='class_new', request_method='GET',
             renderer='templates/forms/class_create.pt', permission='admin')
def class_edit(request):
    return {'classes': sorted(Class.query_by().all())}


@view_config(route_name='class_item', request_method='JOIN',
             permission='authenticated', renderer='json')
@validate(class_=AnyDBThing('class_id', Class, source=MATCHDICT))
def class_join(request, class_):
    if class_.is_locked:
        raise HTTPBadRequest('Invalid class')
    request.user.classes.append(class_)
    request.session.flash('You have joined {}'.format(class_.name),
                          'successes')
    url = request.route_path('user_item', username=request.user.username)
    return http_created(request, redir_location=url)


@view_config(route_name='class_item', request_method='GET',
             renderer='templates/class_view.pt', permission='authenticated')
@validate(class_=AnyDBThing('class_id', Class, source=MATCHDICT))
def class_view(request, class_):
    class_admin = class_.is_admin(request.user)
    recent_subs = None
    if class_admin:
        project_ids = [x.id for x in class_.projects]
        if project_ids:
            recent_subs = (Submission.query_by()
                           .filter(Submission.project_id.in_(project_ids))
                           .order_by(Submission.created_at.desc()).limit(16)
                           .all())
    return {'class_': class_, 'class_admin': class_admin,
            'recent_subs': recent_subs}


@view_config(route_name='execution_file', request_method='PUT',
             permission='authenticated', renderer='json')
@validate(file_=ViewableDBThing('file_id', File),
          filename=String('filename', min_length=1),
          project=EditableDBThing('project_id', Project))
def execution_file_create(request, file_, filename, project):
    return project_file_create(request, file_, filename, project,
                               ExecutionFile)


@view_config(route_name='execution_file_item', request_method='DELETE',
             permission='authenticated', renderer='json')
@validate(execution_file=EditableDBThing('execution_file_id', ExecutionFile,
                                         source=MATCHDICT))
def execution_file_delete(request, execution_file):
    return project_file_delete(request, execution_file)


@view_config(route_name='file_item', request_method='PUT', renderer='json',
             permission='authenticated')
@validate(b64data=WhiteSpaceString('b64data'), sha1sum=SHA1_VALIDATOR)
def file_create(request, b64data, sha1sum):
    data = b64decode(b64data.encode('ascii'))
    # Verify the sha1 matches
    expected_sha1 = sha1(data).hexdigest()
    if sha1sum != expected_sha1:
        msg = 'sha1sum does not match expected: {0}'.format(expected_sha1)
        raise HTTPBadRequest(msg)

    # fetch or create (and save to disk) the file
    base_path = request.registry.settings['file_directory']
    file_ = File.fetch_or_create(data, base_path, sha1sum=sha1sum)
    # associate user with the file
    request.user.files.add(file_)
    return {'file_id': file_.id}


@view_config(route_name='file_item', request_method='INFO',
             permission='authenticated', renderer='json')
@validate(file_=ViewableDBThing('sha1sum', File, fetch_by='sha1',
                                validator=SHA1_VALIDATOR, source=MATCHDICT))
def file_item_info(request, file_):
    return {'file_id': file_.id, 'owns_file': file_ in request.user.files}


@view_config(route_name='file_item', request_method='GET',
             permission='authenticated', renderer='templates/file_view.pt')
@validate(file_=ViewableDBThing('sha1sum', File, fetch_by='sha1',
                                validator=SHA1_VALIDATOR, source=MATCHDICT),
          filename=String('filename', min_length=1, source=MATCHDICT),
          raw=TextNumber('raw', min_value=0, max_value=1,
                         optional=True, source=SOURCE_GET))
def file_item_view(request, file_, filename, raw):
    source = File.file_path(request.registry.settings['file_directory'],
                            file_.sha1)
    if raw:
        return FileResponse(source, request)
    try:
        contents = codecs.open(source, encoding='utf-8').read()
    except UnicodeDecodeError as exc:
        contents = 'File contents could not be displayed: {}'.format(exc)
    return {'contents': contents,
            'filename': filename,
            'url': request.route_path('file_item', sha1sum=file_.sha1,
                                      filename=filename, _query={'raw': '1'})}


@view_config(route_name='file_verifier', request_method='PUT',
             permission='authenticated', renderer='json')
@validate(copy_to_execution=TextNumber('copy_to_execution', min_value=0,
                                       max_value=1, optional=True),
          filename=String('filename', min_length=1),
          min_size=TextNumber('min_size', min_value=0),
          max_size=TextNumber('max_size', min_value=0, optional=True),
          min_lines=TextNumber('min_lines', min_value=0),
          max_lines=TextNumber('max_lines', min_value=0, optional=True),
          optional=TextNumber('optional', min_value=0, max_value=1,
                              optional=True),
          project=EditableDBThing('project_id', Project),
          warning_regex=RegexString('warning_regex', optional=True))
@file_verifier_verification
def file_verifier_create(request, copy_to_execution, filename, min_size,
                         max_size, min_lines, max_lines, optional, project,
                         warning_regex):
    # Check for build-file conflict
    if not optional and BuildFile.fetch_by(project=project, filename=filename):
        msg = ('A build file already exists with that name. '
               'Provide a different name, or mark as optional.')
        raise HTTPBadRequest(msg)
    filev = FileVerifier(copy_to_execution=bool(copy_to_execution),
                         filename=filename, min_size=min_size,
                         max_size=max_size, min_lines=min_lines,
                         max_lines=max_lines, optional=bool(optional),
                         project=project, warning_regex=warning_regex)
    Session.add(filev)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That filename already exists for the project')
    request.session.flash('Added expected file: {}'.format(filename),
                          'successes')
    redir_location = request.route_path('project_edit', project_id=project.id)
    return http_created(request, redir_location=redir_location)


@view_config(route_name='file_verifier_item', request_method='DELETE',
             permission='authenticated', renderer='json')
@validate(file_verifier=EditableDBThing('file_verifier_id', FileVerifier,
                                        source=MATCHDICT))
def file_verifier_delete(request, file_verifier):
    return project_file_delete(request, file_verifier)


@view_config(route_name='file_verifier_item', request_method='POST',
             permission='authenticated', renderer='json')
@validate(copy_to_execution=TextNumber('copy_to_execution', min_value=0,
                                       max_value=1, optional=True),
          file_verifier=EditableDBThing('file_verifier_id', FileVerifier,
                                        source=MATCHDICT),
          filename=String('filename', min_length=1),
          min_size=TextNumber('min_size', min_value=0),
          max_size=TextNumber('max_size', min_value=0, optional=True),
          min_lines=TextNumber('min_lines', min_value=0),
          max_lines=TextNumber('max_lines', min_value=0, optional=True),
          optional=TextNumber('optional', min_value=0, max_value=1,
                              optional=True),
          warning_regex=RegexString('warning_regex', optional=True))
@file_verifier_verification
def file_verifier_update(request, copy_to_execution, file_verifier, filename,
                         min_size, max_size, min_lines, max_lines, optional,
                         warning_regex):
    # Check for build-file conflict
    if not optional and BuildFile.fetch_by(project=file_verifier.project,
                                           filename=filename):
        msg = ('A build file already exists with that name. '
               'Provide a different name, or mark as optional.')
        raise HTTPBadRequest(msg)
    if not file_verifier.update(copy_to_execution=bool(copy_to_execution),
                                filename=filename, min_size=min_size,
                                max_size=max_size, min_lines=min_lines,
                                max_lines=max_lines, optional=bool(optional),
                                warning_regex=warning_regex):
        return http_ok(request, message='Nothing to change')

    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That filename already exists for the project')
    request.session.flash('Updated expected file: {}'.format(filename),
                          'successes')
    redir_location = request.route_path('project_edit',
                                        project_id=file_verifier.project.id)
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='home', request_method='GET')
def home(request):
    if request.user:
        url = request.route_path('user_item', username=request.user.username)
    else:
        url = request.route_path('session')
    raise HTTPFound(location=url)


@view_config(route_name='password_reset', request_method='PUT',
             renderer='json')
@validate(username=EmailAddress('email'))
def password_reset_create(request, username):
    if username == 'admin':
        raise HTTPConflict('Hahaha, nice try!')
    user = User.fetch_by(username=username)
    if not user:
        raise HTTPConflict('Invalid email')
    password_reset = PasswordReset.generate(user)
    failure_message = 'You were already sent a password reset email.'
    if password_reset:
        Session.add(password_reset)
        try:
            Session.flush()
        except IntegrityError:
            raise HTTPConflict(failure_message)
        site_name = request.registry.settings['site_name']
        reset_url = request.route_url('password_reset_item',
                                      token=password_reset.get_token())
        body = ('Visit the following link to reset your password:\n\n{0}'
                .format(reset_url))
        send_email(request, recipients=user.username, body=body,
                   subject='{0} password reset email'.format(site_name))
        return http_ok(request,
                       message='A password reset link will be emailed to you.')
    else:
        raise HTTPConflict(failure_message)


@view_config(route_name='password_reset', request_method='GET',
             renderer='templates/forms/password_reset.pt')
def password_reset_edit(request):
    return {}


@view_config(route_name='password_reset_item', request_method='GET',
             renderer='templates/forms/password_reset_item.pt')
@validate(reset=AnyDBThing('token', PasswordReset, fetch_by='reset_token',
                           validator=UUID_VALIDATOR, source=MATCHDICT))
def password_reset_edit_item(request, reset):
    return {'token': reset.get_token()}


@view_config(route_name='password_reset_item', renderer='json',
             request_method='PUT')
@validate(username=EmailAddress('email'),
          password=WhiteSpaceString('password', min_length=6),
          reset=AnyDBThing('token', PasswordReset, fetch_by='reset_token',
                           validator=UUID_VALIDATOR, source=MATCHDICT))
def password_reset_item(request, username, password, reset):
    if reset.user.username != username:
        raise HTTPConflict('The reset token and username '
                           'combination is not valid.')
    reset.user.password = password
    Session.delete(reset)
    Session.flush()
    request.session.flash('Your password has been updated!', 'successes')
    redir_location = request.route_path('session',
                                        _query={'username': username})
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='project', request_method='CLONE',
             permission='authenticated', renderer='json')
@validate(class_=EditableDBThing('class_id', Class),
          name=String('name', min_length=2),
          src_project=ViewableDBThing('project_id', Project))
def project_clone(request, class_, name, src_project):
    # Additional check as we can clone projects whose classes are locked,
    # but we cannot clone projects that are locked
    if src_project.status not in (u'notready', u'ready'):
        raise HTTPConflict('Cannot clone a project with status: {}'
                           .format(src_project.status))
    # Build a copy of the project settings
    update = {'class_': class_, 'status': 'notready', 'name': name}
    project = clone(src_project, ('class_id',), update)

    Session.autoflush = False  # Don't flush while testing for changes

    # Copy project "files" keeping a mapping between src and dst objects
    mapping = {'build_files': {}, 'execution_files': {}, 'file_verifiers': {}}
    for attr in mapping:
        for item in getattr(src_project, attr):
            new = clone(item, ('project_id',))
            getattr(project, attr).append(new)
            mapping[attr][item] = new

    # Copy project testables
    for src_testable in src_project.testables:
        testable = clone(src_testable, ('project_id',))
        project.testables.append(testable)
        # Set testable "files" with the appropriate "new" file
        for attr, file_mapping in mapping.items():
            getattr(testable, attr).extend(file_mapping[x] for x
                                           in getattr(src_testable, attr))
        # Copy test cases
        testable.test_cases = [clone(x, ('testable_id',))
                               for x in src_testable.test_cases]
    Session.add(project)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('The name `{0}` already exists for the class.'
                           .format(name))
    request.session.flash('Cloned {} {} as {}'.format(src_project.class_.name,
                                                      src_project.name,
                                                      name),
                          'successes')
    redir_location = request.route_path('project_edit', project_id=project.id)
    return http_created(request, redir_location=redir_location)


@view_config(route_name='project', request_method='PUT',
             permission='authenticated', renderer='json')
@validate(name=String('name', min_length=2),
          class_=EditableDBThing('class_id', Class),
          makefile=ViewableDBThing('makefile_id', File, optional=True))
def project_create(request, name, class_, makefile):
    project = Project(name=name, class_=class_, makefile=makefile)
    Session.add(project)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That project name already exists for the class')
    redir_location = request.route_path('project_edit', project_id=project.id)
    request.session.flash('Project added!', 'successes')
    return http_created(request, redir_location=redir_location)


@view_config(route_name='project_item_download', request_method='GET',
             permission='authenticated')
@validate(project=ViewableDBThing('project_id', Project, source=MATCHDICT))
def project_download(request, project):
    def file_path(file_):
        return File.file_path(request.registry.settings['file_directory'],
                              file_.sha1)

    files = []
    for sub in project.recent_submissions():
        users = sub.group.users_str.replace(' ', '_').replace(',', '-')
        user_path = '{0}_{1}'.format(users, sub.id)
        for filename, file_ in sub.file_mapping().items():
            files.append((os.path.join(project.name, user_path, filename),
                          file_path(file_)))
    return zip_response(request, project.name + '.zip', files)


@view_config(route_name='project_edit',
             renderer='templates/forms/project_edit.pt',
             request_method='GET', permission='authenticated')
@validate(project=ViewableDBThing('project_id', Project, source=MATCHDICT))
def project_edit(request, project):
    action = request.route_path('project_item_summary',
                                class_id=project.class_.id,
                                project_id=project.id)
    return {'project': project, 'action': action}


@view_config(route_name='project_group', request_method='JOIN',
             permission='authenticated', renderer='json')
@validate(project=EditableDBThing('project_id', Project, source=MATCHDICT),
          users=List('user_ids', ViewableDBThing('', User), min_elements=2,
                     max_elements=2))
def project_group_admin_join(request, project, users):
    try:
        group = users[0].group_with(users[1], project, bypass_limit=True)
    except GroupWithException as exc:
        request.session.flash(exc.args[0], 'errors')
        group = None
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('Could not join the users at this time.')
    redir_location = request.route_path('group_admin', project_id=project.id)
    if not group:
        return http_gone(request, redir_location=redir_location)
    request.session.flash('Made group: {}'.format(group.users_str),
                          'successes')
    redir_location = request.route_path('group_admin', project_id=project.id)
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='group_admin', request_method='GET',
             renderer='templates/forms/group_admin.pt',
             permission='authenticated')
@validate(project=EditableDBThing('project_id', Project, source=MATCHDICT))
def project_group_admin_view(request, project):
    students = set(project.class_.users)
    selectable = []
    for group in project.groups:
        students = students - set(group.users)
        selectable.append((group.users_str, group.group_assocs[0].user.id))
    selectable.extend((x.name, x.id) for x in students)
    return {'project': project, 'selectable': selectable}


@view_config(route_name='project_group_item', renderer='json',
             request_method='PUT')
@validate(project=AccessibleDBThing('project_id', Project, source=MATCHDICT),
          group_request=EditableDBThing('group_request_id', GroupRequest,
                                        source=MATCHDICT))
def project_group_request_confirm(request, project, group_request):
    try:
        request.user.group_with(group_request.from_user, project)
        failed = False
    except GroupWithException as exc:
        request.session.flash(exc.args[0], 'errors')
        failed = True
    Session.delete(group_request)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('Could not join the group at this time.')
    url = request.route_url('project_group', project_id=project.id)
    if failed:
        return http_gone(request, redir_location=url)
    request.session.flash('Joined group with {}'
                          .format(group_request.from_user), 'successes')
    return http_ok(request, redir_location=url)


@view_config(route_name='project_group', renderer='json', request_method='PUT')
@validate(project=AccessibleDBThing('project_id', Project, source=MATCHDICT),
          username=EmailAddress('email'))
def project_group_request_create(request, project, username):
    if not request.user.can_join_group(project):
        raise HTTPConflict('You cannot expand your group for this project.')
    user = User.fetch_by(username=username)
    if not user or project.class_ not in user.classes:
        raise HTTPConflict('Invalid email.')
    if not user.can_join_group(project):
        raise HTTPConflict('That user cannot join your group.')
    self_assoc = request.user.fetch_group_assoc(project)
    user_assoc = user.fetch_group_assoc(project)
    if request.user == user or \
            self_assoc == user_assoc and self_assoc is not None:
        raise HTTPConflict('You are already in a group with that student.')

    Session.add(GroupRequest(from_user=request.user, project=project,
                             to_user=user))
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('Could not create your group request.')

    site_name = request.registry.settings['site_name']
    url = request.route_url('project_group', project_id=project.id)
    body = ('Your fellow {} student, {}, has requested you join their '
            'group for "{}". Please visit the following link to confirm or '
            'deny the request:\n\n{}'
            .format(project.class_.name, request.user, project.name, url))
    send_email(request, recipients=user.username, body=body,
               subject='{}: {} "{}" Group Request'
               .format(site_name, project.class_.name, project.name))
    request.session.flash('Request to {} sent via email.'.format(user),
                          'successes')
    return http_ok(request, redir_location=request.url)


@view_config(route_name='project_group_item', renderer='json',
             request_method='DELETE')
@validate(project=AccessibleDBThing('project_id', Project, source=MATCHDICT),
          group_request=AccessibleDBThing('group_request_id', GroupRequest,
                                          source=MATCHDICT))
def project_group_request_delete(request, project, group_request):
    if request.user == group_request.from_user:
        msg = 'Revoked request to {}.'.format(group_request.to_user)
    else:
        msg = 'Denied request from {}.'.format(group_request.from_user)
    Session.delete(group_request)
    request.session.flash(msg, 'successes')
    url = request.route_url('project_group', project_id=project.id)
    return http_ok(request, redir_location=url)


@view_config(route_name='project_group', request_method='GET',
             renderer='templates/forms/project_group.pt',
             permission='authenticated')
@validate(project=AccessibleDBThing('project_id', Project, source=MATCHDICT))
def project_group_view(request, project):
    assoc = request.user.fetch_group_assoc(project)
    members = assoc.group.users_str if assoc else request.user.name
    pending = GroupRequest.query_by(project=project, to_user=request.user)
    requested = GroupRequest.query_by(from_user=request.user,
                                      project=project).first()
    can_join = request.user.can_join_group(project)
    return {'project': project, 'members': members, 'can_join': can_join,
            'pending': pending.all(), 'requested': requested}


@view_config(route_name='project_info', request_method='GET',
             permission='authenticated', renderer='json')
@validate(project=EditableDBThing('project_id', Project, source=MATCHDICT))
def project_info(request, project):
    retval = {'id': project.id, 'name': project.name, 'testables': {}}
    for testable in project.testables:
        test_cases = {}
        for test_case in testable.test_cases:
            stdin = test_case.stdin.sha1 if test_case.stdin else None
            expected = test_case.expected.sha1 if test_case.expected else None
            test_cases[test_case.name] = {
                'id': test_case.id, 'args': test_case.args,
                'source': test_case.source,
                'stdin': stdin, 'expected': expected,
                'output_type': test_case.output_type,
                'output_filename': test_case.output_filename}
        retval['testables'][testable.name] = {'id': testable.id,
                                              'test_cases': test_cases}
    return retval


@view_config(route_name='project_new', request_method='GET',
             renderer='templates/forms/project_new.pt',
             permission='authenticated')
@validate(class_=EditableDBThing('class_id', Class, source=MATCHDICT))
def project_new(request, class_):
    dummy_project = DummyTemplateAttr(None)
    dummy_project.class_ = class_
    clone_projects = []
    for other in sorted(request.user.admin_for):
        clone_projects.extend(other.projects)
    return {'project': dummy_project, 'clone_projects': clone_projects}


@view_config(route_name='project_edit', renderer='json',
             request_method='PUT', permission='authenticated')
@validate(project=EditableDBThing('project_id', Project, source=MATCHDICT))
def project_requeue(request, project):
    count = 0
    for count, submission in enumerate(project.recent_submissions(), start=1):
        request.queue(submission_id=submission.id, _priority=2)
    if count == 0:
        return http_ok(request, message='There are no submissions to requeue.')
    request.session.flash('Requeued the most recent submissions ({0} items).'
                          .format(count), 'successes')
    return http_ok(request, redir_location=request.url)


@view_config(route_name='project_scores', request_method='GET',
             permission='authenticated')
@validate(project=EditableDBThing('project_id', Project, source=MATCHDICT))
def project_scores(request, project):
    rows = ['Name, Email, Group ID, Score (On Time), Score']
    _, best_ontime, best = project.process_submissions()
    for group, (sub, points) in best.items():
        on_time = best_ontime[group][1] if group in best_ontime else ''
        for user in group.users:
            rows.append('{}, {}, {}, {}, {}'
                        .format(user.name, user.username, group.id,
                                points, on_time))
    disposition = 'attachment; filename="{0}.csv"'.format(project.name)
    return Response(body='\n'.join(rows), content_type=str('text/csv'),
                    content_disposition=disposition)


@view_config(route_name='submission_item_gen', renderer='json',
             request_method='PUT', permission='authenticated')
@validate(submission=EditableDBThing('submission_id', Submission,
                                     source=MATCHDICT))
def project_test_case_generate(request, submission):
    project = submission.project
    if project.status == u'locked':
        raise HTTPConflict('The project is already locked.')
    # Verify the submission is okay to use
    if not submission.verification_results:
        raise HTTPConflict('The submission has not been verified.')
    if submission.testables_pending():
        raise HTTPConflict('The submission has pending test groups.')
    # Look for testables with issues
    by_testable = {x.testable: x for x in submission.testable_results}
    for testable in submission.project.testables:
        if TestableStatus(testable, by_testable.get(testable),
                          submission.verification_results.errors).issue:
            raise HTTPConflict('The submission contains failing test groups.')

    # Mark the project and its testables as locked
    project.status = u'locked'
    for testable in project.testables:
        testable.is_locked = True

    # Saved attributes
    submission_id = submission.id
    project_id = project.id

    try:
        transaction.commit()  # Need to commit before queuing the job.
    except IntegrityError:
        transaction.abort()
        raise
    # Schedule a task to generate the expected outputs
    request.queue(submission_id=submission_id, update_project=True,
                  _priority=0)
    request.session.flash('Rebuilding the project\'s expected outputs.',
                          'successes')
    redir_location = request.route_url('project_edit', project_id=project_id)
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='project_item_summary', request_method='POST',
             permission='authenticated', renderer='json')
@validate(name=String('name', min_length=2),
          makefile=ViewableDBThing('makefile_id', File, optional=True),
          is_ready=TextNumber('is_ready', min_value=0, max_value=1,
                              optional=True),
          deadline=TextDate('deadline', optional=True),
          delay_minutes=TextNumber('delay_minutes', min_value=1),
          group_max=TextNumber('group_max', min_value=1),
          project=EditableDBThing('project_id', Project, source=MATCHDICT))
def project_update(request, name, makefile, is_ready, deadline, delay_minutes,
                   group_max, project):
    # Fix timezone if it doesn't exist
    if project.deadline and deadline and not deadline.tzinfo:
        deadline = deadline.replace(tzinfo=project.deadline.tzinfo)
    if not project.update(name=name, makefile=makefile, deadline=deadline,
                          delay_minutes=delay_minutes,
                          group_max=group_max,
                          status=u'ready' if bool(is_ready) else u'notready'):
        return http_ok(request, message='Nothing to change')
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That project name already exists for the class')
    request.session.flash('Project updated', 'successes')
    redir_location = request.route_path('project_edit', project_id=project.id)
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='project_item_detailed',
             request_method=('GET', 'HEAD'),
             renderer='templates/project_view_detailed.pt',
             permission='authenticated')
@validate(project=AccessibleDBThing('project_id', Project, source=MATCHDICT),
          group=ViewableDBThing('group_id', Group, source=MATCHDICT))
def project_view_detailed(request, project, group):
    submissions = Submission.query_by(project=project, group=group)
    if not submissions:
        raise HTTPNotFound()

    project_admin = project.can_view(request.user)
    if project_admin:
        prev_group, next_group = prev_next_group(project, group)
    else:
        prev_group = next_group = None

    return {'project': project,
            'project_admin': project_admin,
            'is_member': request.user in group.users,
            'users_str': group.users_str,
            'can_edit': project_admin,
            'prev_group': prev_group,
            'next_group': next_group,
            'submissions': sorted(submissions,
                                  key=lambda s: s.created_at,
                                  reverse=True)}


@view_config(route_name='project_item_detailed_user',
             renderer='templates/project_view_detailed.pt',
             request_method=('GET', 'HEAD'),
             permission='authenticated')
@validate(project=AccessibleDBThing('project_id', Project, source=MATCHDICT),
          user=ViewableDBThing('username', User, fetch_by='username',
                               validator=String('username'), source=MATCHDICT))
def project_view_detailed_user(request, project, user):
    group_assoc = user.fetch_group_assoc(project)
    if group_assoc:
        url = request.route_path('project_item_detailed',
                                 project_id=project.id,
                                 group_id=group_assoc.group_id)
        raise HTTPFound(location=url)
    return {'project': project,
            'project_admin': False,
            'is_member': request.user == user,
            'users_str': user.name,
            'can_edit': False,
            'prev_group': None,
            'next_group': None,
            'submissions': []}


@view_config(route_name='project_item_summary', request_method=('GET', 'HEAD'),
             renderer='templates/project_view_summary.pt',
             permission='authenticated')
@validate(project=ViewableDBThing('project_id', Project, source=MATCHDICT))
def project_view_summary(request, project):
    # Compute student stats
    by_group, best_ontime, best = project.process_submissions()
    possible = project.points_possible(include_hidden=True)
    if best:
        best_scores = numpy.array([x[1] for x in best.values()])
        normed = [min(x[1], possible) for x in best.values()]
        max_score = max(best_scores)
        mean = numpy.mean(best_scores)
        median = numpy.median(best_scores)
        bins = [x * possible for x in [0, 0, .6, .7, .8, .9, 1, 1]]
        bins[1] = min(1, bins[2])
        hist, _ = numpy.histogram(normed, range=(0, possible), bins=bins)
    else:
        hist = max_score = mean = median = None

    # Find most recent for each group
    submissions = {}
    group_truncated = set()
    for group in project.groups:
        if group in by_group:
            newest = by_group[group][:-4:-1]
            if group in best:
                best[group][0]._is_best = True
                if best[group][0] not in newest:
                    newest.append(best[group][0])
            if group in best_ontime:
                best_ontime[group][0]._is_best = True
                if best_ontime[group][0] not in newest:
                    newest.append(best_ontime[group][0])
            if len(newest) < len(by_group[group]):
                group_truncated.add(group)
            submissions[group] = newest

        else:
            submissions[group] = []
    # The 16 most recent submissions
    recent_submissions = (Submission.query_by(project=project)
                          .order_by(Submission.created_at.desc())
                          .limit(16).all())
    return {'group_truncated': group_truncated,
            'hist': hist,
            'max': max_score,
            'mean': mean,
            'median': median,
            'num_groups': len(best),
            'project': project,
            'recent_submissions': recent_submissions,
            'submissions': sorted(submissions.items())}


@view_config(route_name='session', request_method='PUT', renderer='json')
@validate(username=Or('email', EmailAddress(''), String('')),
          password=WhiteSpaceString('password', min_length=6),
          next_path=String('next', optional=True))
def session_create(request, username, password, next_path):
    development_mode = asbool(request.registry.settings.get('development_mode',
                                                            False))
    user = User.login(username, password, development_mode=development_mode)
    if not user:
        raise HTTPConflict('Invalid login')
    headers = remember(request, user.id)
    request.session.flash('Welcome {}!'.format(user.name), 'successes')
    url = next_path or request.route_path('user_item', username=user.username)
    return http_created(request, headers=headers, redir_location=url)


@view_config(route_name='session', request_method='DELETE', renderer='json',
             permission='authenticated')
def session_destroy(request):
    headers = forget(request)
    return http_gone(request, headers=headers,
                     redir_location=request.route_path('home'))


@view_config(route_name='session', request_method='GET',
             renderer='templates/forms/login.pt')
@validate(username=String('username', optional=True, source=SOURCE_GET),
          next_path=String('next', optional=True, source=SOURCE_GET))
def session_edit(request, username, next_path):
    next_path = next_path or request.route_url('home')
    return {'next': next_path, 'username': username}


@view_config(route_name='submission', renderer='json', request_method='PUT',
             permission='authenticated')
@validate(project=AccessibleDBThing('project_id', Project),
          file_ids=List('file_ids', TextNumber('', min_value=0),
                        min_elements=1),
          filenames=List('filenames', String('', min_length=1),
                         min_elements=1))
def submission_create(request, project, file_ids, filenames):
    # Additional input verification
    filename_set = set(filenames)
    if len(filename_set) != len(filenames):
        raise HTTPBadRequest('A filename cannot be provided more than once')
    elif len(file_ids) != len(filenames):
        msg = 'Number of file_ids must match number of filenames'
        raise HTTPBadRequest(msg)
    # Verify there are no extra files
    extra = filename_set - set(x.filename for x in project.file_verifiers)
    if extra:
        raise HTTPBadRequest('Invalid files: {}'.format(', '.join(extra)))

    # Verify user permission on files
    msgs = []
    user_files = {x.id: x for x in request.user.files}
    files = set()
    for i, file_id in enumerate(file_ids):
        if file_id in user_files:
            files.add(user_files[file_id])
        else:
            msgs.append('Invalid file "{0}"'.format(filenames[i]))
    if msgs:
        raise HTTPBadRequest(msgs)

    submission = request.user.make_submission(project)

    # Grant the files' permissions to the other members of the group
    for user in submission.group.users:
        if user == request.user:
            continue
        user.files.update(files)

    # Associate the files with the submissions by their submission name
    assoc = []
    for file_id, filename in zip(file_ids, filenames):
        assoc.append(SubmissionToFile(file_id=file_id, filename=filename))
    submission.files.extend(assoc)
    Session.add(submission)
    Session.add_all(assoc)
    Session.flush()
    submission_id = submission.id
    # We must commit the transaction before queueing the job.
    transaction.commit()
    request.queue(submission_id=submission_id)
    # Redirect to submission result page
    redir_location = request.route_path('submission_item',
                                        submission_id=submission_id)
    return http_created(request, redir_location=redir_location)


@view_config(route_name='submission_new', request_method='GET',
             renderer='templates/forms/submission_new.pt',
             permission='authenticated')
@validate(project=AccessibleDBThing('project_id', Project, source=MATCHDICT))
def submission_new(request, project):
    return {'project': project,
            'submit_path': request.registry.settings['submit_path']}


@view_config(route_name='submission_item', renderer='json',
             request_method='PUT', permission='authenticated')
@validate(submission=EditableDBThing('submission_id', Submission,
                                     source=MATCHDICT))
def submission_requeue(request, submission):
    request.queue(submission_id=submission.id, _priority=0)
    request.session.flash('Requeued the submission', 'successes')
    return http_ok(request, redir_location=request.url)


@view_config(route_name='submission_item', request_method='GET',
             renderer='templates/submission_view.pt',
             permission='authenticated')
@validate(submission=ViewableDBThing('submission_id', Submission,
                                     source=MATCHDICT),
          as_user=TextNumber('as_user', min_value=0, max_value=1,
                             optional=True, source=SOURCE_GET))
def submission_view(request, submission, as_user):
    actual_admin = submission.project.can_edit(request.user)
    submission_admin = not bool(as_user) and actual_admin
    if not submission_admin:  # Only check delay for user view
        delay = submission.get_delay(
            update=request.user in submission.group.users)
        if delay:
            request.override_renderer = 'templates/submission_delay.pt'
            files = {x.filename: x.file for x in submission.files}
            prev_sub, next_sub = prev_next_submission(submission)
            return {'delay': '{0:.1f} minutes'.format(delay),
                    'files': files,
                    'next_sub': next_sub,
                    'prev_sub': prev_sub,
                    'submission': submission,
                    'submission_admin': actual_admin}

    points_possible = submission.project.points_possible(
        include_hidden=submission_admin)
    if submission_admin:
        diff_renderer = HTMLDiff(num_reveal_limit=None,
                                 points_possible=points_possible)
    else:
        diff_renderer = HTMLDiff(points_possible=points_possible)

    for tcr in submission.test_case_results:
        if submission_admin or not tcr.test_case.testable.is_hidden:
            diff_renderer.add_renderable(prepare_renderable(request, tcr,
                                                            submission_admin))
    if submission.verification_results:
        mapping = submission.file_mapping()
        extra_files = {x: mapping[x] for x in
                       submission.verification_results.extra_filenames}
        files = {x.filename: x.file for x in submission.files
                 if x.filename not in extra_files}
        warnings = submission.verification_results.warnings
        pending = submission.testables_pending(prune=not submission_admin)

        # Build all testables' statuses
        # Testables that failed verification do not have a TestableResult
        by_testable = {x.testable: x for x in submission.testable_results}
        testable_issues = []
        # Add testables which have issues (verification or build)
        for testable in (set(submission.project.testables) - pending):
            if submission_admin or not testable.is_hidden:
                ts = TestableStatus(testable, by_testable.get(testable),
                                    submission.verification_results.errors)
                if ts.issue:
                    testable_issues.append(ts)
    else:
        extra_files = files = pending = warnings = None
        testable_issues = []

    if submission.testables_succeeded():
        # Decode utf-8 and ignore errors until the data is diffed in unicode.
        diff_table = diff_renderer.make_whole_file().decode('utf-8', 'ignore')
    else:
        diff_table = None

    # Do this after we've potentially updated the session
    prev_sub, next_sub = prev_next_submission(submission)
    if submission_admin:
        prev_group, next_group = prev_next_group(submission.project,
                                                 submission.group)
    else:
        prev_group = next_group = None


    if not submission_admin and submission.project.name[0:4]=="EXAM":
       files = {}

    return {'diff_table': diff_table,
            'extra_files': extra_files,
            'files': files,
            'next_sub': next_sub,
            'next_group': next_group,
            'pending': pending,
            'prev_sub': prev_sub,
            'prev_group': prev_group,
            'submission': submission,
            'submission_admin': submission_admin,
            'testable_issues': testable_issues,
            'warnings': warnings}


@view_config(route_name='test_case', request_method='PUT',
             permission='authenticated', renderer='json')
@validate(name=String('name', min_length=1),
          args=String('args', min_length=1),
          expected=ViewableDBThing('expected_id', File, optional=True),
          hide_expected=TextNumber('hide_expected', min_value=0, max_value=1,
                                   optional=True),
          output_filename=String('output_filename', min_length=1,
                                 optional=True),
          output_source=OUTPUT_SOURCE, output_type=OUTPUT_TYPE,
          points=TextNumber('points'),
          stdin=ViewableDBThing('stdin_id', File, optional=True),
          testable=EditableDBThing('testable_id', Testable))
@test_case_verification
def test_case_create(request, name, args, expected, hide_expected,
                     output_filename, output_source, output_type, points,
                     stdin, testable):
    test_case = TestCase(name=name, args=args, expected=expected,
                         hide_expected=bool(hide_expected),
                         output_filename=output_filename,
                         output_type=output_type, points=points,
                         source=output_source, stdin=stdin, testable=testable)
    Session.add(test_case)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That name already exists for the testable')
    redir_location = request.route_path('project_edit',
                                        project_id=testable.project.id)
    return http_created(request, redir_location=redir_location)


@view_config(route_name='test_case_item', request_method='DELETE',
             permission='authenticated', renderer='json')
@validate(test_case=EditableDBThing('test_case_id', TestCase,
                                    source=MATCHDICT))
def test_case_delete(request, test_case):
    redir_location = request.route_path(
        'project_edit', project_id=test_case.testable.project.id)
    request.session.flash('Deleted TestCase {0}.'.format(test_case.name),
                          'successes')
    testable = test_case.testable
    Session.delete(test_case)
    # Update the testable point score
    testable.update_points()
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='test_case_item', request_method='POST',
             permission='authenticated', renderer='json')
@validate(name=String('name', min_length=1),
          args=String('args', min_length=1),
          expected=ViewableDBThing('expected_id', File, optional=True),
          hide_expected=TextNumber('hide_expected', min_value=0, max_value=1,
                                   optional=True),
          output_filename=String('output_filename', min_length=1,
                                 optional=True),
          output_source=OUTPUT_SOURCE, output_type=OUTPUT_TYPE,
          points=TextNumber('points'),
          stdin=ViewableDBThing('stdin_id', File, optional=True),
          test_case=EditableDBThing('test_case_id', TestCase,
                                    source=MATCHDICT))
@test_case_verification
def test_case_update(request, name, args, expected, hide_expected,
                     output_filename, output_source, output_type, points,
                     stdin, test_case):
    if not test_case.update(name=name, args=args, expected=expected,
                            hide_expected=bool(hide_expected),
                            output_filename=output_filename,
                            output_type=output_type, points=points,
                            source=output_source, stdin=stdin):
        return http_ok(request, message='Nothing to change')
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That name already exists for the testable')
    # Update the testable point score
    test_case.testable.update_points()
    request.session.flash('Updated TestCase {0}.'.format(test_case.name),
                          'successes')
    redir_location = request.route_path(
        'project_edit', project_id=test_case.testable.project.id)
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='testable', request_method='PUT',
             permission='authenticated', renderer='json')
@validate(name=String('name', min_length=1),
          is_hidden=TextNumber('is_hidden', min_value=0, max_value=1,
                               optional=True),
          make_target=String('make_target', min_length=1, optional=True),
          executable=String('executable', min_length=1),
          build_file_ids=List('build_file_ids', TextNumber('', min_value=0),
                              optional=True),
          execution_file_ids=List('execution_file_ids',
                                  TextNumber('', min_value=0), optional=True),
          file_verifier_ids=List('file_verifier_ids',
                                 TextNumber('', min_value=0), optional=True),
          project=EditableDBThing('project_id', Project))
def testable_create(request, name, is_hidden, make_target, executable,
                    build_file_ids, execution_file_ids, file_verifier_ids,
                    project):
    if make_target and not project.makefile:
        msg = 'make_target cannot be specified without a make file'
        raise HTTPBadRequest(msg)

    try:
        # Verify the ids actually exist and are associated with the project
        build_files = fetch_request_ids(build_file_ids, BuildFile,
                                        'build_file_id',
                                        project.build_files)
        execution_files = fetch_request_ids(execution_file_ids, ExecutionFile,
                                            'execution_file_id')
        file_verifiers = fetch_request_ids(file_verifier_ids, FileVerifier,
                                           'file_verifier_id',
                                           project.file_verifiers)
    except InvalidId as exc:
        raise HTTPBadRequest('Invalid {0}'.format(exc.message))

    testable = Testable(name=name, is_hidden=bool(is_hidden),
                        make_target=make_target,
                        executable=executable, project=project,
                        build_files=build_files,
                        execution_files=execution_files,
                        file_verifiers=file_verifiers)
    redir_location = request.route_path('project_edit', project_id=project.id)
    Session.add(testable)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That name already exists for the project')
    return http_created(request, redir_location=redir_location,
                        testable_id=testable.id)


@view_config(route_name='testable_item', request_method='POST',
             permission='authenticated', renderer='json')
@validate(name=String('name', min_length=1),
          is_hidden=TextNumber('is_hidden', min_value=0, max_value=1,
                               optional=True),
          make_target=String('make_target', min_length=1, optional=True),
          executable=String('executable', min_length=1),
          build_file_ids=List('build_file_ids', TextNumber('', min_value=0),
                              optional=True),
          execution_file_ids=List('execution_file_ids',
                                  TextNumber('', min_value=0), optional=True),
          file_verifier_ids=List('file_verifier_ids',
                                 TextNumber('', min_value=0), optional=True),
          testable=EditableDBThing('testable_id', Testable, source=MATCHDICT))
def testable_edit(request, name, is_hidden, make_target, executable,
                  build_file_ids, execution_file_ids, file_verifier_ids,
                  testable):
    if make_target and not testable.project.makefile:
        msg = 'make_target cannot be specified without a make file'
        raise HTTPBadRequest(msg)

    try:
        # Verify the ids actually exist and are associated with the project
        build_files = fetch_request_ids(build_file_ids, BuildFile,
                                        'build_file_id',
                                        testable.project.build_files)
        execution_files = fetch_request_ids(execution_file_ids, ExecutionFile,
                                            'execution_file_id')
        file_verifiers = fetch_request_ids(file_verifier_ids, FileVerifier,
                                           'file_verifier_id',
                                           testable.project.file_verifiers)
    except InvalidId as exc:
        raise HTTPBadRequest('Invalid {0}'.format(exc.message))

    Session.autoflush = False  # Don't flush while testing for changes
    if not testable.update(_ignore_order=True, is_hidden=bool(is_hidden),
                           name=name, make_target=make_target,
                           executable=executable,
                           build_files=build_files,
                           execution_files=execution_files,
                           file_verifiers=file_verifiers):
        return http_ok(request, message='Nothing to change')
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That name already exists for the project')
    request.session.flash('Updated Testable {0}.'.format(testable.name),
                          'successes')
    redir_location = request.route_path('project_edit',
                                        project_id=testable.project.id)
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='testable_item', request_method='DELETE',
             permission='authenticated', renderer='json')
@validate(testable=EditableDBThing('testable_id', Testable, source=MATCHDICT))
def testable_delete(request, testable):
    redir_location = request.route_path('project_edit',
                                        project_id=testable.project.id)
    request.session.flash('Deleted Testable {0}.'.format(testable.name),
                          'successes')
    Session.delete(testable)
    return http_ok(request, redir_location=redir_location)


@view_config(route_name='user', request_method='PUT', renderer='json')
@validate(identity=UmailAddress('email', min_length=16, max_length=64),
          verification=String('verification'))
def user_create(request, identity, verification):
    username, name = identity
    return add_user(request, name, username, verification)


@view_config(route_name='user', request_method='ADMINPUT', renderer='json',
             permission='admin')
@validate(name=String('name', min_length=5),
          username=String('email', min_length=6, max_length=64),
          verification=String('verification'))
def user_create_special(request, name, username, verification):
    return add_user(request, name, username, verification,
                    request.route_path('user_new_special'))


@view_config(route_name='user_join', request_method='GET',
             permission='authenticated',
             renderer='templates/forms/class_join_list.pt')
def user_join(request):
    # get all the classes that the given user is not in, and let the
    # user optionally join them
    all_classes = frozenset(Class.query_by(is_locked=False).all())
    user_classes = frozenset(request.user.classes)
    return {'classes': sorted(all_classes - user_classes)}


@view_config(route_name='user_new', request_method='GET',
             renderer='templates/forms/user_create.pt')
def user_edit(request):
    return {}


@view_config(route_name='user_new_special', request_method='GET',
             renderer='templates/forms/user_create_special.pt',
             permission='admin')
def user_edit_special(request):
    return {}


@view_config(route_name='user_item', request_method='GET',
             renderer='templates/user_view.pt', permission='authenticated')
@validate(user=ViewableDBThing('username', User, fetch_by='username',
                               validator=String('username'), source=MATCHDICT))
def user_view(request, user):
    user_groups = [x.group_id for x in Session.query(UserToGroup)
                   .filter(UserToGroup.user == user).all()]
    admin_subs = user_subs = None
    if user_groups:
        user_subs = (Submission.query_by()
                     .filter(Submission.group_id.in_(user_groups))
                     .order_by(Submission.created_at.desc()).limit(10).all())
    admin_classes = user.classes_can_admin()
    if admin_classes:
        class_ids = [x.id for x in admin_classes]
        class_projs = [x.id for x in Project.query_by()
                       .filter(Project.class_id.in_(class_ids))
                       .all()]
        if class_projs:
            admin_subs = (Submission.query_by()
                          .filter(Submission.project_id.in_(class_projs))
                          .order_by(Submission.created_at.desc()).limit(10)
                          .all())
    return {'name': user.name,
            'user_subs': user_subs,
            'classes_taking': sorted(user.classes),
            'admin_subs': admin_subs,
            'admin_classes': admin_classes}


@view_config(route_name='zipfile_download', request_method='GET',
             permission='authenticated')
@validate(submission=ViewableDBThing('submission_id', Submission,
                                     source=MATCHDICT))
def zipfile_download(request, submission):
    def file_path(file_):
        return File.file_path(request.registry.settings['file_directory'],
                              file_.sha1)
    users = submission.group.users_str.replace(' ', '_').replace(',', '-')
    base_path = '{0}_{1}'.format(users, submission.id)
    # include makefile and student submitted files
    files = [(os.path.join(base_path, 'Makefile'),
              file_path(submission.project.makefile))]
    for filename, file_ in submission.file_mapping().items():
        files.append((os.path.join(base_path, filename), file_path(file_)))
    return zip_response(request, base_path + '.zip', files)
