import dateutil.parser
import json
import ldap
import pickle
import pika
import re
import traceback
from pyramid_addons.helpers import http_created, http_ok
from pyramid_addons.validation import (SOURCE_MATCHDICT, EmailAddress,
                                       TextNumber, Validator)
from pyramid.httpexceptions import (HTTPBadRequest, HTTPConflict,
                                    HTTPForbidden, HTTPNotFound)
from pyramid_mailer import get_mailer
from pyramid_mailer.message import Message
from pyramid.response import FileResponse
from pyramid.settings import asbool
from sqlalchemy.exc import IntegrityError
from tempfile import NamedTemporaryFile
from zipfile import ZipFile
from .exceptions import InvalidId


class TestableStatus(object):
    def __init__(self, testable, testable_result, verification_errors):
        self.issue = None
        self.errors = {x: y for (x, y) in verification_errors.items()
                       if testable.requires_file(x)}
        self.show_make_output = False
        self.testable = testable
        self.testable_result = testable_result

        if testable_result:
            if testable_result.status == 'make_failed':
                self.issue = 'Build failed'
                self.show_make_output = True
            elif testable_result.status == 'nonexistent_executable':
                self.issue = ('The expected executable was not created during '
                              'the build process')
        else:
            self.issue = ('One or more of the required files did not pass '
                          'verification (see below)')

    def __cmp__(self, other):
        return cmp(self.testable, other.testable)


class DummyTemplateAttr(object):
    def __init__(self, default=None):
        self.default = default

    def __getattr__(self, attr):
        return self.default


class TextDate(Validator):

    """A validator that converts a string into a tz-enabled datetime object."""

    def run(self, value, errors, _):
        if not isinstance(value, unicode):
            self.add_error(errors, 'must be a unicode string')
            return value
        try:
            return dateutil.parser.parse(value)
        except ValueError:
            self.add_error(errors, 'is not a valid datetime format')
            return value


class UmailAddress(EmailAddress):

    """A validator to verify that a umail address is correct."""

    def run(self, value, errors, *args):
        retval = super(UmailAddress, self).run(value.lower(), errors, *args)
        if errors:
            return retval
        if not retval.endswith('@umail.ucsb.edu'):
            self.add_error(errors, 'must end with @umail.ucsb.edu')
            return retval
        # Fetch name
        try:
            name = fetch_name_by_umail(retval)
        except Exception as exc:
            self.add_error(errors, exc.message)
            return retval
        if not name:
            self.add_error(errors, 'does not appear to be a valid umail email')
            return retval
        return (retval, name)


class DBThing(Validator):

    """A validator that converts a primary key into the database object."""

    def __init__(self, param, cls, fetch_by=None, validator=None,
                 **kwargs):
        super(DBThing, self).__init__(param, **kwargs)
        self.cls = cls
        self.fetch_by = fetch_by
        self.id_validator = validator if validator else TextNumber(param,
                                                                   min_value=0)

    def run(self, value, errors, request):
        """Return the object if valid and available, otherwise None."""
        value = self.id_validator(value, errors, request)
        if errors:
            return None
        if self.fetch_by:
            thing = self.cls.fetch_by(**{self.fetch_by: value})
        else:
            thing = self.cls.fetch_by_id(value)
        if not thing and self.source == SOURCE_MATCHDICT:
            # If part of the URL we should have a not-found error
            raise HTTPNotFound()
        elif not thing:
            self.add_error(errors, 'Invalid {0}'
                           .format(self.cls.__name__))
        return thing


class AccessibleDBThing(DBThing):

    """An extension of DBThing that also checks for accessibility.

    Usage of this validator assumes the Thing class has a `can_acess` method
    that takes as a sole argument a User object.

    """

    def run(self, value, errors, request):
        """Return thing, but abort validation if request.user cannot edit."""
        thing = super(AccessibleDBThing, self).run(value, errors, request)
        if errors:
            return None
        if not thing.can_access(request.user):
            message = 'Insufficient permissions for {0}'.format(self.param)
            raise HTTPForbidden(message)
        return thing


class EditableDBThing(DBThing):

    """An extension of DBThing that also checks for edit access.

    Usage of this validator assumes the Thing class has a `can_edit` method
    that takes as a sole argument a User object.

    """

    def run(self, value, errors, request):
        """Return thing, but abort validation if request.user cannot edit."""
        thing = super(EditableDBThing, self).run(value, errors, request)
        if errors:
            return None
        if not thing.can_edit(request.user):
            message = 'Insufficient permissions for {0}'.format(self.param)
            raise HTTPForbidden(message)
        return thing


class ViewableDBThing(DBThing):

    """An extension of DBThing that also checks for view access.

    Usage of this validator assumes the Thing class has a `can_view` method
    that takes as a sole argument a User object.

    """

    def run(self, value, errors, request):
        """Return thing, but abort validation if request.user cannot view."""
        thing = super(ViewableDBThing, self).run(value, errors, request)
        if errors:
            return None
        if not thing.can_view(request.user):
            message = 'Insufficient permissions for {0}'.format(self.param)
            raise HTTPForbidden(message)
        return thing


def add_user(request, name, username, verification, redir_location=None):
    if username != verification:
        raise HTTPBadRequest('email and verification do not match')

    # Set the password to blank
    new_user = User(name=name, username=username, password='', is_admin=False)
    Session.add(new_user)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('User \'{0}\' already exists'.format(username))

    password_reset = PasswordReset.generate(new_user)
    Session.add(password_reset)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('Error creating password reset.')
    site_name = request.registry.settings['site_name']
    reset_url = request.route_url('password_reset_item',
                                  token=password_reset.get_token())
    body = ('Please visit the following link to complete your account '
            'creation:\n\n{0}'.format(reset_url))
    send_email(request, recipients=username, body=body,
               subject='{0} password reset email'.format(site_name))
    request.session.flash('Account creation initiated. Instructions for '
                          'completion have been emailed to {0}.'
                          .format(username), 'successes')
    redir_location = redir_location or request.route_path(
        'session', _query={'username': username})
    return http_created(request, redir_location=redir_location)


def alphanum_key(string):
    """Return a comparable tuple with extracted number segments.

    Adapted from: http://stackoverflow.com/a/2669120/176978

    """
    convert = lambda text: int(text) if text.isdigit() else text
    return [convert(segment) for segment in re.split('([0-9]+)', string)]


def clone(item, exclude=None, update=None):
    """Return a clone of the SQLA object.

    :param item: The SQLA object to copy the attributes from.
    :param exclude: If provided, should be an iterable that contains the names
        attributes to exclude from the copy. The attributes `created_at` and
        `id` are always excluded.
    :param update: If provided, should be a mapping of attribute name, to the
        value that should be set.

    """
    # Prepare attribute exclusion set
    if not exclude:
        exclude = set()
    if not isinstance(exclude, set):
        exclude = set(exclude)
    exclude.update(('created_at', 'id'))
    # Build a mapping of attributes to values
    attrs = {x: getattr(item, x) for x in item.__mapper__.columns.keys()
             if x not in exclude}
    if update:  # Update the mapping if necessary
        attrs.update(update)
    # Build and return the SQLA object
    return item.__class__(**attrs)


def fetch_request_ids(item_ids, cls, attr_name, verification_list=None):
    """Return a list of cls instances for all the ids provided in item_ids.

    :param item_ids: The list of ids to fetch objects for
    :param cls: The class to fetch the ids from
    :param attr_name: The name of the attribute for exception purposes
    :param verification_list: If provided, a list of acceptable instances

    Raise InvalidId exception using attr_name if any do not
        exist, or are not present in the verification_list.

    """
    if not item_ids:
        return []
    items = []
    for item_id in item_ids:
        item = cls.fetch_by_id(item_id)
        if not item or (verification_list is not None and
                        item not in verification_list):
            raise InvalidId(attr_name)
        items.append(item)
    return items


def fetch_name_by_umail(umail):
    def extract(item):
        if len(data[item]) == 1:
            return data[item][0]
        raise Exception('Multiple values returned: {}'.format(data))

    uid = umail.split('@')[0]

    # connect to ldap
    ldap_conn = ldap.initialize('ldaps://directory.ucsb.edu')
    ldap_conn.protocol_version = ldap.VERSION3
    results = ldap_conn.search_s(
        'o=ucsb', ldap.SCOPE_ONELEVEL, filterstr='uid={}'.format(uid),
        attrlist=('cn', 'sn', 'mail', 'uid', 'givenname', 'initials'))
    if len(results) != 1:
        return None
    data = results[0][1]
    if 'initials' in data:
        fullname = '{} {} {}'.format(extract('givenname'), extract('initials'),
                                     extract('sn'))
    elif 'cn' in data:
        fullname = extract('cn')
    else:
        raise Exception('Missing required LDAP information')
    return fullname


def file_verifier_verification(function):
    def wrapped(request, min_size, max_size, min_lines, max_lines,
                *args, **kwargs):
        msgs = []
        if max_size is not None and max_size < min_size:
            msgs.append('min_size cannot be > max_size')
        if max_lines is not None and max_lines < min_lines:
            msgs.append('min_lines cannot be > max_lines')
        if min_size < min_lines:
            msgs.append('min_lines cannot be > min_size')
        if max_size is not None and max_lines is not None \
                and max_size < max_lines:
            msgs.append('max_lines cannot be > max_size')
        if msgs:
            raise HTTPBadRequest(msgs)
        return function(request, *args, min_size=min_size, max_size=max_size,
                        min_lines=min_lines, max_lines=max_lines, **kwargs)
    return wrapped


def get_queue_func(request):
    """Establish the connection to rabbitmq."""
    def cleanup(request):
        conn.close()

    def queue_func(**kwargs):
        return conn.channel().basic_publish(
            exchange='', body=json.dumps(kwargs), routing_key=queue,
            properties=pika.BasicProperties(delivery_mode=2))
    server = request.registry.settings['queue_server']
    queue = request.registry.settings['queue_verification']
    conn = pika.BlockingConnection(pika.ConnectionParameters(host=server))
    request.add_finished_callback(cleanup)
    return queue_func


def prev_next_submission(submission):
    """Return adjacent sumbission objects for the given submission."""
    return (Submission.earlier_submission_for_group(submission),
            Submission.later_submission_for_group(submission))


def prev_next_group(project, group):
    """Return adjacent group objects or None for the given project and group.

    The previous and next group objects are relative to sort order of the
    project's groups with respect to the passed in group.

    """
    # TODO: Profile and optimize this query if necessary
    groups = sorted(x for x in project.groups if x.submissions)
    try:
        index = groups.index(group)
    except ValueError:
        return None, None
    prev_group = groups[index - 1] if index > 0 else None
    next_group = groups[index + 1] if index + 1 < len(groups) else None
    return prev_group, next_group


def project_file_create(request, file_, filename, project, cls):
    # Check for BuildFile and FileVerifier conflict
    if cls == BuildFile and FileVerifier.fetch_by(project_id=project.id,
                                                  filename=filename,
                                                  optional=False):
        msg = 'A required expected file already exists with that name.'
        raise HTTPBadRequest(msg)
    cls_file = cls(file=file_, filename=filename, project=project)
    Session.add(cls_file)
    try:
        Session.flush()
    except IntegrityError:
        raise HTTPConflict('That filename already exists for the project')
    redir_location = request.route_path('project_edit', project_id=project.id)
    request.session.flash('Added {0} {1}.'.format(cls.__name__, filename),
                          'successes')
    return http_created(request, redir_location=redir_location)


def project_file_delete(request, project_file):
    redir_location = request.route_path('project_edit',
                                        project_id=project_file.project.id)
    request.session.flash('Deleted {0} {1}.'
                          .format(project_file.__class__.__name__,
                                  project_file.filename),
                          'successes')
    # Delete the file
    Session.delete(project_file)
    return http_ok(request, redir_location=redir_location)


def send_email(request, recipients, subject, body):
    # If in development mode send email to exception email
    if asbool(request.registry.settings.get('development_mode', False)):
        recipients = [request.registry.settings['exc_mail_to']]

    if isinstance(recipients, basestring):
        recipients = [recipients]
    message = Message(subject=subject, recipients=recipients, body=body)
    return get_mailer(request).send(message)


def test_case_verification(function):
    def wrapped(request, expected, output_filename, output_source, output_type,
                *args, **kwargs):
        msgs = []
        if output_filename and output_source != 'file':
            msgs.append('output_filename can only be set when the source '
                        'is a named file')
        elif not output_filename and output_source == 'file':
            msgs.append('output_filename must be set when the source is a '
                        'named file')
        if expected and output_type != 'diff':
            msgs.append('expected_id can only be set when the type is diff')
        elif not expected and output_type == 'diff':
            msgs.append('expected_id must be set when the type is diff')
        if msgs:
            raise HTTPBadRequest(msgs)
        return function(request, *args, expected=expected,
                        output_filename=output_filename,
                        output_source=output_source, output_type=output_type,
                        **kwargs)
    return wrapped


def prepare_renderable(request, test_case_result, is_admin):
    """Return a completed Renderable."""
    test_case = test_case_result.test_case
    file_directory = request.registry.settings['file_directory']
    sha1 = test_case_result.diff.sha1 if test_case_result.diff else None
    kwargs = {'number': test_case.id, 'group': test_case.testable.name,
              'name': test_case.name, 'points': test_case.points,
              'status': test_case_result.status,
              'extra': test_case_result.extra}

    if test_case.output_type == 'image':
        url = request.route_path('file_item', filename='_', _query={'raw': 1},
                                 sha1sum=sha1) if sha1 else None
        return ImageOutput(url=url, **kwargs)
    elif test_case.output_type == 'text':
        content = None
        if sha1:
            with open(File.file_path(file_directory, sha1)) as fp:
                content = fp.read()
        return TextOutput(content=content, **kwargs)
    elif not test_case_result.diff:  # Outputs match
        return DiffWithMetadata(diff=None, **kwargs)

    try:
        with open(File.file_path(file_directory, sha1)) as fp:
            diff = pickle.load(fp)
    except (AttributeError, EOFError):
        content = 'submit system mismatch -- requeue submission'
        content += traceback.format_exc(1)
        return TextOutput(content=content, **kwargs)
    except Exception:
        content = 'unexected error -- requeue submission\n'
        content += traceback.format_exc(1)
        return TextOutput(content=content, **kwargs)

    diff.hide_expected = not is_admin and test_case.hide_expected
    return DiffWithMetadata(diff=diff, **kwargs)


def zip_response(request, filename, files):
    """Return a Response object that is a zipfile with name filename.

    :param request: The request object.
    :param filename: The filename the browser should save the file as.
    :param files: A list of mappings between filenames (path/.../file) to file
        objects.

    """
    tmp_file = NamedTemporaryFile()
    try:
        with ZipFile(tmp_file, 'w') as zip_file:
            for zip_path, actual_path in files:
                zip_file.write(actual_path, zip_path)
        tmp_file.flush()  # Just in case
        response = FileResponse(tmp_file.name, request=request,
                                content_type=str('application/zip'))
        response.headers['Content-disposition'] = ('attachment; filename="{0}"'
                                                   .format(filename))
        return response
    finally:
        tmp_file.close()


# Avoid cyclic import
from .diff_unit import DiffWithMetadata, ImageOutput, TextOutput
from .models import (BuildFile, File, FileVerifier, PasswordReset, Session,
                     Submission, User)
