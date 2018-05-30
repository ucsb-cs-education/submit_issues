from __future__ import unicode_literals
import errno
import json
import os
import re
import sys
import transaction
import uuid
from datetime import datetime, timedelta
from hashlib import sha1
from pyramid_addons.helpers import UTC
from sqla_mixins import BasicBase, UserMixin
from sqlalchemy import (Binary, Boolean, Column, DateTime, Enum, ForeignKey,
                        Integer, PickleType, String, Table, Unicode,
                        UnicodeText, and_, func)
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import backref, relationship, scoped_session, sessionmaker
from sqlalchemy.schema import UniqueConstraint
from zope.sqlalchemy import ZopeTransactionExtension
from .exceptions import GroupWithException
from .helpers import alphanum_key

if sys.version_info < (3, 0):
    builtins = __import__('__builtin__')
else:
    import builtins

Base = declarative_base()
Session = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
# Make Session available to sqla_mixins
builtins._sqla_mixins_session = Session


testable_to_build_file = Table(
    'testable_to_build_file', Base.metadata,
    Column('testable_id', Integer, ForeignKey('testable.id'),
           primary_key=True),
    Column('build_file_id', Integer, ForeignKey('buildfile.id'),
           primary_key=True))

testable_to_execution_file = Table(
    'testable_to_execution_file', Base.metadata,
    Column('testable_id', Integer, ForeignKey('testable.id'),
           primary_key=True),
    Column('execution_file_id', Integer, ForeignKey('executionfile.id'),
           primary_key=True))

testable_to_file_verifier = Table(
    'testable_to_file_verifier', Base.metadata,
    Column('testable_id', Integer, ForeignKey('testable.id'),
           primary_key=True),
    Column('file_verifier_id', Integer, ForeignKey('fileverifier.id'),
           primary_key=True))

user_to_class = Table(
    'user_to_class', Base.metadata,
    Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
    Column('class_id', Integer, ForeignKey('class.id'), primary_key=True))

user_to_class_admin = Table(
    'user_to_class_admin', Base.metadata,
    Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
    Column('class_id', Integer, ForeignKey('class.id'), primary_key=True))

user_to_file = Table(
    'user_to_file', Base.metadata,
    Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
    Column('file_id', Integer, ForeignKey('file.id'), primary_key=True))


class BuildFile(BasicBase, Base):
    __table_args__ = (UniqueConstraint('filename', 'project_id'),)
    file = relationship('File', backref='build_files')
    file_id = Column(Integer, ForeignKey('file.id'), nullable=False)
    filename = Column(Unicode, nullable=False)
    project_id = Column(Integer, ForeignKey('project.id'), nullable=False)

    def __cmp__(self, other):
        return cmp(alphanum_key(self.filename), alphanum_key(other.filename))

    def can_edit(self, user):
        """Return whether or not the user can edit the build file."""
        return self.project.can_edit(user)

    def edit_json(self, jsonify=True):
        data = {'id': self.id, 'name': self.filename,
                'file_hex': self.file.sha1}
        return json.dumps(data) if jsonify else data


class Class(BasicBase, Base):
    is_locked = Column(Boolean, default=False, nullable=False,
                       server_default='0')
    name = Column(Unicode, nullable=False, unique=True)
    projects = relationship('Project', backref='class_',
                            cascade='all, delete-orphan')

    def __repr__(self):
        return 'Class(name={0})'.format(self.name)

    def __str__(self):
        return 'Class Name: {0}'.format(self.name)

    def __cmp__(self, other):
        locked = cmp(self.is_locked, other.is_locked)
        if locked:
            return locked
        return cmp(alphanum_key(self.name), alphanum_key(other.name))

    def can_edit(self, user):
        """Return whether or not `user` can make changes to the class."""
        return user.is_admin or not self.is_locked and self in user.admin_for

    def can_view(self, user):
        """Return whether or not `user` can view the class."""
        return self.is_admin(user) or self in user.classes

    def is_admin(self, user):
        """Return whether or not `user` is an admin for the class."""
        return user.is_admin or self in user.admin_for


class ExecutionFile(BasicBase, Base):
    __table_args__ = (UniqueConstraint('filename', 'project_id'),)
    file = relationship('File', backref='execution_files')
    file_id = Column(Integer, ForeignKey('file.id'), nullable=False)
    filename = Column(Unicode, nullable=False)
    project_id = Column(Integer, ForeignKey('project.id'), nullable=False)

    def __cmp__(self, other):
        return cmp(alphanum_key(self.filename), alphanum_key(other.filename))

    def can_edit(self, user):
        """Return whether or not the user can edit the build file."""
        return self.project.can_edit(user)

    def edit_json(self, jsonify=True):
        data = {'id': self.id, 'name': self.filename,
                'file_hex': self.file.sha1}
        return json.dumps(data) if jsonify else data


class File(BasicBase, Base):
    lines = Column(Integer, nullable=False)
    sha1 = Column(String, nullable=False, unique=True)
    size = Column(Integer, nullable=False)

    @staticmethod
    def fetch_or_create(data, base_path, sha1sum=None):
        if not sha1sum:
            sha1sum = sha1(data).hexdigest()
        file_ = File.fetch_by(sha1=sha1sum)
        if not file_:
            file_ = File(base_path=base_path, data=data, sha1=sha1sum)
            Session.add(file_)
            Session.flush()
        return file_

    @staticmethod
    def file_path(base_path, sha1sum):
        first = sha1sum[:2]
        second = sha1sum[2:4]
        return os.path.join(base_path, first, second, sha1sum[4:])

    def __init__(self, base_path, data, sha1):
        self.lines = 0
        for byte in data:
            if byte == '\n':
                self.lines += 1
        self.size = len(data)
        self.sha1 = sha1
        # save file
        path = File.file_path(base_path, sha1)
        try:
            os.makedirs(os.path.dirname(path))
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
        with open(path, 'wb') as fp:
            fp.write(data)

    def can_view(self, user):
        """Return true if the user can view the file."""
        # Perform simplest checks first
        if user.is_admin or self in user.files:
            return True
        elif user.admin_for:  # Begin more expensive comparisions
            # Single-indirect lookup
            classes = set(x.class_ for x in self.makefile_for_projects)
            if classes.intersection(user.admin_for):
                return True
            # Double indirect lookups
            classes = set(x.project.class_ for x in self.build_files)
            if classes.intersection(user.admin_for):
                return True
            classes = set(x.project.class_ for x in self.execution_files)
            if classes.intersection(user.admin_for):
                return True
            # Triple-indirect lookups
            classes = set(x.testable.project.class_ for x in self.expected_for)
            if classes.intersection(user.admin_for):
                return True
            classes = set(x.testable.project.class_ for x in self.stdin_for)
            if classes.intersection(user.admin_for):
                return True
            classes = set(x.submission.project.class_ for x in
                          self.submission_assocs)
            if classes.intersection(user.admin_for):
                return True
            # 4x-indirect lookups
            classes = set(x.test_case.testable.project.class_ for x
                          in self.test_case_result_for)
            if classes.intersection(user.admin_for):
                return True
        return False


class FileVerifier(BasicBase, Base):
    __table_args__ = (UniqueConstraint('filename', 'project_id'),)
    copy_to_execution = Column(Boolean, server_default='0', default=False,
                               nullable=False)
    filename = Column(Unicode, nullable=False)
    min_size = Column(Integer, nullable=False)
    max_size = Column(Integer)
    min_lines = Column(Integer, nullable=False)
    max_lines = Column(Integer)
    optional = Column(Boolean, default=False, nullable=False)
    project_id = Column(Integer, ForeignKey('project.id'), nullable=False)
    warning_regex = Column(Unicode)

    def __cmp__(self, other):
        return cmp(alphanum_key(self.filename), alphanum_key(other.filename))

    def can_edit(self, user):
        return self.project.can_edit(user)

    def edit_json(self, jsonify=True):
        attrs = ('id', ('name', 'filename'), 'copy_to_execution', 'min_size',
                 'max_size', 'min_lines', 'max_lines', 'optional',
                 'warning_regex')
        data = {}
        for attr in attrs:
            if isinstance(attr, tuple):
                data[attr[0]] = getattr(self, attr[1])
            else:
                data[attr] = getattr(self, attr)
        return json.dumps(data) if jsonify else data

    def verify(self, base_path, file_):
        errors = []
        if file_.size < self.min_size:
            errors.append('must be >= {0} bytes'.format(self.min_size))
        elif self.max_size and file_.size > self.max_size:
            errors.append('must be <= {0} bytes'.format(self.max_size))
        if file_.lines < self.min_lines:
            errors.append('must have >= {0} lines'.format(self.min_lines))
        elif self.max_lines and file_.lines > self.max_lines:
            errors.append('must have <= {0} lines'.format(self.max_lines))

        if not self.warning_regex:
            return errors, None

        regex = re.compile(self.warning_regex)
        warnings = []
        for i, line in enumerate(open(File.file_path(base_path, file_.sha1))):
            for match in regex.findall(line):
                warnings.append({'lineno': i + 1, 'token': match})
        return errors, warnings


class Group(BasicBase, Base):
    project = relationship('Project', backref='groups')
    project_id = Column(Integer, ForeignKey('project.id'), nullable=False)
    viewed_at = Column(DateTime(timezone=True), nullable=True)

    @property
    def has_consent(self):
        return all(x.consent_at for x in self.users)

    @property
    def users(self):
        return (x.user for x in self.group_assocs)

    @property
    def users_str(self):
        return ', '.join(sorted(x.name for x in self.users))

    def __lt__(self, other):
        """Compare the first users in sorted order."""
        return sorted(self.users)[0] < sorted(other.users)[0]

    def can_view(self, user):
        """Return whether or not `user` can view info about the group."""
        return user.is_admin or user in self.users \
            or self.project.class_ in user.admin_for


class GroupRequest(BasicBase, Base):
    __table_args__ = (UniqueConstraint('from_user_id', 'project_id'),)
    from_user_id = Column(Integer, ForeignKey('user.id'), index=True)
    from_user = relationship('User', foreign_keys=[from_user_id],
                             backref=backref('sent_requests', cascade='all'))
    project = relationship('Project')
    project_id = Column(Integer, ForeignKey('project.id'), index=True)
    to_user_id = Column(Integer, ForeignKey('user.id'), index=True)
    to_user = relationship('User', foreign_keys=[to_user_id],
                           backref=backref('pending_requests', cascade='all'))

    def can_access(self, user):
        return user == self.from_user or user == self.to_user

    def can_edit(self, user):
        return user == self.to_user


class VerificationResults(object):

    """Stores verification information about a single submission.

    WARNING: The attributes of this class cannot easily be changed as this
    class is pickled in the database.

    """

    @property
    def errors(self):
        return self._errors_by_filename

    @property
    def extra_filenames(self):
        return self._extra_filenames or []

    @property
    def warnings(self):
        return self._warnings_by_filename

    def __init__(self):
        self._errors_by_filename = {}
        self._extra_filenames = None
        self._missing_to_testable_ids = {}
        self._warnings_by_filename = {}

    def __str__(self):
        import pprint
        return pprint.pformat(vars(self))

    def missing_testables(self):
        """Return a set of testables that have files missing."""
        ids = set()
        for id_set in self._missing_to_testable_ids.values():
            ids |= id_set
        return set(x for x in (Testable.fetch_by_id(y) for y in ids) if x)

    def set_errors_for_filename(self, errors, filename):
        self._errors_by_filename[filename] = errors

    def set_extra_filenames(self, filenames):
        self._extra_filenames = filenames

    def set_warnings_for_filename(self, warnings, filename):
        self._warnings_by_filename[filename] = warnings


class PasswordReset(Base):
    __tablename__ = 'passwordreset'
    created_at = Column(DateTime(timezone=True), default=func.now(),
                        nullable=False)
    reset_token = Column(Binary(length=16), primary_key=True)
    user = relationship('User', backref=backref('password_reset',
                                                cascade='all'))
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False,
                     unique=True)

    @classmethod
    def fetch_by(cls, **kwargs):
        if 'reset_token' in kwargs:
            kwargs['reset_token'] = uuid.UUID(kwargs['reset_token']).bytes
        return Session.query(cls).filter_by(**kwargs).first()

    @classmethod
    def generate(cls, user):
        pr = cls.fetch_by(user=user)
        if pr:
            retval = None
        else:
            retval = cls(reset_token=uuid.uuid4().bytes, user=user)
        return retval

    def get_token(self):
        return str(uuid.UUID(bytes=self.reset_token))


class Project(BasicBase, Base):
    __table_args__ = (UniqueConstraint('name', 'class_id'),)
    build_files = relationship(BuildFile, backref='project',
                               cascade='all, delete-orphan')
    class_id = Column(Integer, ForeignKey('class.id'), nullable=False)
    deadline = Column(DateTime(timezone=True), nullable=True)
    delay_minutes = Column(Integer, nullable=False, default=1,
                           server_default='1')
    execution_files = relationship(ExecutionFile, backref='project',
                                   cascade='all, delete-orphan')
    file_verifiers = relationship('FileVerifier', backref='project',
                                  cascade='all, delete-orphan')
    group_max = Column(Integer, nullable=False, default=1, server_default='1')
    makefile = relationship(File, backref='makefile_for_projects')
    makefile_id = Column(Integer, ForeignKey('file.id'), nullable=True)
    name = Column(Unicode, nullable=False)
    status = Column(Enum('locked', 'notready', 'ready', name='status'),
                    nullable=False, server_default='notready')
    submissions = relationship('Submission', backref='project',
                               cascade='all, delete-orphan')
    testables = relationship('Testable', backref='project',
                             cascade='all, delete-orphan')

    @property
    def delay(self):
        return timedelta(minutes=self.delay_minutes)

    @property
    def is_ready(self):
        return self.status == 'ready'

    @property
    def student_submissions(self):
        admins = set(self.class_.admins)
        return [x for x in self.submissions if not set(x.group.users) & admins]

    def __cmp__(self, other):
        return cmp(alphanum_key(self.name), alphanum_key(other.name))

    def build_files_json(self):
        return json.dumps([x.edit_json(False) for x in self.build_files])

    def can_access(self, user):
        """Return whether or not `user` can access a project.

        The project's is_ready field must be set for a user to access.

        """
        return self.class_.is_admin(user) or \
            self.is_ready and self.class_ in user.classes

    def can_edit(self, user):
        """Return whether or not `user` can make changes to the project."""
        return self.class_.can_edit(user) and self.status != u'locked'

    def can_view(self, user):
        """Return whether or not `user` can view the project's settings."""
        return self.class_.is_admin(user)

    def execution_files_json(self):
        return json.dumps([x.edit_json(False) for x in self.execution_files])

    def file_verifiers_json(self):
        return json.dumps([x.edit_json(False) for x in self.file_verifiers])

    def points_possible(self, include_hidden=False):
        """Return the total points possible for this project."""
        return sum([test_case.points for testable in self.testables
                    for test_case in testable.test_cases
                    if include_hidden or not testable.is_hidden])

    def process_submissions(self):
        by_group = {}
        best_ontime = {}
        best = {}
        admins = set(self.class_.admins)
        for sub in sorted(self.submissions, key=lambda x: x.created_at):
            is_student = not set(sub.group.users) & admins
            points = sub.points(include_hidden=True)
            if sub.group in by_group:
                by_group[sub.group].append(sub)
                if is_student:
                    if points > best[sub.group][1]:
                        best[sub.group] = sub, points
                    if not sub.is_late and points > best_ontime[sub.group][1]:
                        best_ontime[sub.group] = sub, points
            else:
                by_group[sub.group] = [sub]
                if is_student:
                    best[sub.group] = sub, points
                    if not sub.is_late:
                        best_ontime[sub.group] = sub, points
        return by_group, best_ontime, best

    def recent_submissions(self):
        """Generate a list of the most recent submissions for each user.

        Only yields a submission for a user if they've made one.

        """
        for group in self.groups:
            submission = Submission.most_recent_submission(self, group)
            if submission:
                yield submission

    def submit_string(self):
        """Return a string specifying the files to submit for this project."""
        required = []
        optional = []
        for file_verifier in self.file_verifiers:
            if file_verifier.optional:
                optional.append('[{0}]'.format(file_verifier.filename))
            else:
                required.append(file_verifier.filename)
        return ' '.join(sorted(required) + sorted(optional))

    def testables_json(self):
        return json.dumps([x.edit_json(False) for x in sorted(self.testables)]
                          + [{'id': 'new', 'name': 'Add New', 'target': '',
                              'executable': '', 'hidden': False,
                              'test_cases': []}])

    def verify_submission(self, base_path, submission, update):
        """Return list of testables that can be built."""
        results = VerificationResults()
        valid_files = set()
        file_mapping = submission.file_mapping()

        # Create a list of in-use file verifiers
        file_verifiers = set(fv for testable in self.testables
                             for fv in testable.file_verifiers)

        for fv in file_verifiers:
            if fv.filename in file_mapping:
                errors, warnings = fv.verify(base_path,
                                             file_mapping[fv.filename])
                if errors:
                    results.set_errors_for_filename(errors, fv.filename)
                else:
                    valid_files.add(fv.filename)
                if warnings:
                    results.set_warnings_for_filename(warnings, fv.filename)
                del file_mapping[fv.filename]
            elif not fv.optional:
                results.set_errors_for_filename(['missing'], fv.filename)
        if file_mapping:
            results.set_extra_filenames(frozenset(file_mapping.keys()))

        # Determine valid testables
        retval = []
        for testable in self.testables:
            missing = frozenset(x.filename for x in testable.file_verifiers
                                if not x.optional) - valid_files
            if missing:
                results._missing_to_testable_ids.setdefault(
                    missing, set()).add(testable.id)
            elif testable.file_verifiers:
                retval.append(testable)

        if update:
            # Reset existing attributes
            submission.test_case_results = []
            submission.testable_results = []
            # Set new information
            submission.verification_results = results
            submission.verified_at = func.now()
        return retval


class Submission(BasicBase, Base):
    created_by = relationship('User')
    created_by_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    group = relationship(Group, backref='submissions')
    group_id = Column(Integer, ForeignKey('group.id'), nullable=False)
    files = relationship('SubmissionToFile', backref='submission',
                         cascade='all, delete-orphan')
    project_id = Column(Integer, ForeignKey('project.id'), nullable=False)
    test_case_results = relationship('TestCaseResult', backref='submission',
                                     cascade='all, delete-orphan')
    testable_results = relationship('TestableResult', backref='submission',
                                    cascade='all, delete-orphan')
    verification_results = Column(PickleType)
    verified_at = Column(DateTime(timezone=True), index=True)

    @property
    def is_late(self):
        return self.project.deadline \
            and self.created_at >= self.project.deadline

    @staticmethod
    def earlier_submission_for_group(submission):
        """Return the submission immediately prior to the given submission."""
        return (Submission
                .query_by(project=submission.project, group=submission.group)
                .filter(Submission.created_at < submission.created_at)
                .order_by(Submission.created_at.desc()).first())

    @staticmethod
    def later_submission_for_group(submission):
        """Return the submission immediately prior to the given submission."""
        return (Submission
                .query_by(project=submission.project, group=submission.group)
                .filter(Submission.created_at > submission.created_at)
                .order_by(Submission.created_at).first())

    @staticmethod
    def merge_dict(d1, d2, on_collision):
        retval = {}
        for key in d1.keys():
            if key in d2:
                retval[key] = on_collision(d1[key], d2[key])
            else:
                retval[key] = d1[key]
        for key in d2.keys():
            if key not in retval:
                retval[key] = d2[key]
        return retval

    @staticmethod
    def most_recent_submission(project, group):
        """Return the most recent submission for the user and project id."""
        return (Submission.query_by(project=project, group=group)
                .order_by(Submission.created_at.desc()).first())

    def __cmp__(self, other):
        return cmp(self.created_at, other.created_at)

    def can_edit(self, user):
        """Return whether or not `user` can edit the submission."""
        return self.project.can_edit(user)

    def can_view(self, user):
        """Return whether or not `user` can view the submission."""
        return user in self.group.users or self.project.can_view(user)

    def file_mapping(self):
        """Return a mapping of filename to File object for the submission."""
        return {x.filename: x.file for x in self.files}

    def get_delay(self, update):
        """Return the minutes to delay the viewing of submission results.

        Only store information into the datebase when `update` is set.

        """
        if hasattr(self, '_delay'):
            return self._delay

        now = datetime.now(UTC())
        zero = timedelta(0)
        delay = self.project.delay - (now - self.created_at)
        if delay <= zero:  # Never delay longer than the project's delay time
            self._delay = None
        elif self.group.viewed_at is None:  # Don't delay
            if update:
                self.group.viewed_at = func.now()
            self._delay = None
        elif self.created_at <= self.group.viewed_at:  # Show older results
            self._delay = None
        else:
            pv_delay = self.project.delay - (now - self.group.viewed_at)
            if pv_delay <= zero:
                if update:  # Update the counter
                    self.group.viewed_at = func.now()
                self._delay = None
            else:
                self._delay = min(delay, pv_delay).total_seconds() / 60
        return self._delay

    def points(self, include_hidden=False):
        """Return the number of points awarded to this submission."""
        return sum(x.points for x in self.testable_results
                   if include_hidden or not x.testable.is_hidden)

    def testables_pending(self, prune=False):
        """Return the set of testables that _can_ execute and have yet to.

        If prune is true, filter out hidden testables.

        """
        if prune:
            tbs = set(x for x in self.project.testables if not x.is_hidden)
        else:
            tbs = set(self.project.testables)
        return (tbs - self.verification_results.missing_testables()
                - set(x.testable for x in self.testable_results))

    def testables_succeeded(self):
        """Return the testables which have successfully executed."""
        return set(x.testable for x in self.testable_results
                   if x.status == 'success')

    def time_score(self, request, group=False, admin=False):
        url = request.route_path('submission_item', submission_id=self.id)
        fmt = '<a href="{url}">{created}</a>{name} {score} {modifier}'
        if not self.verification_results:
            score = '<span class="label">waiting to verify submission</span>'
        elif self.testables_pending():
            score = '<span class="label">waiting for results</span>'
        elif not admin and self.get_delay(update=False):
            score = '<span class="label">waiting for delay to expire</span>'
        else:
            points = self.points(include_hidden=admin)
            possible = self.project.points_possible(include_hidden=admin)
            score = 100 * points / possible if possible else 0
            if score >= 100:
                style = 'badge-info'
            elif score >= 90:
                style = 'badge-success'
            elif score >= 75:
                style = ''
            elif score >= 60:
                style = 'badge-warning'
            elif score == 0:
                style = 'badge-inverse'
            else:
                style = 'badge-important'
            score = ('<span class="badge {}">{} / {}</span>'
                     .format(style, points, possible))
        name = ' by {}'.format(self.group.users_str) if group else ''
        modifier = ''
        if self.is_late:
            modifier += '<span class="label label-important">Late</span>'
        if getattr(self, '_is_best', False):
            modifier += '<span><i class="icon-star"></i></span>'

        return fmt.format(url=url, created=self.created_at,
                          name=name, score=score, modifier=modifier)

    def verify(self, base_path, update=False):
        """Verify the submission and return testables that can be executed."""
        return self.project.verify_submission(base_path, self, update=update)


class SubmissionToFile(Base):
    __tablename__ = 'submissiontofile'
    file = relationship(File, backref='submission_assocs')
    file_id = Column(Integer, ForeignKey('file.id'), nullable=False)
    filename = Column(Unicode, nullable=False, primary_key=True)
    submission_id = Column(Integer, ForeignKey('submission.id'),
                           primary_key=True, nullable=False)

    def __cmp__(self, other):
        return cmp(alphanum_key(self.filename), alphanum_key(other.filename))


class TestCase(BasicBase, Base):
    __table_args__ = (UniqueConstraint('name', 'testable_id'),)
    args = Column(Unicode, nullable=False)
    expected = relationship(File, primaryjoin='File.id==TestCase.expected_id',
                            backref='expected_for')
    expected_id = Column(Integer, ForeignKey('file.id'), nullable=True)
    hide_expected = Column(Boolean, default=False, nullable=False,
                           server_default='0')
    name = Column(Unicode, nullable=False)
    output_filename = Column(Unicode, nullable=True)
    output_type = Column(Enum('diff', 'image', 'text', name='output_type'),
                         nullable=False, server_default='diff')
    points = Column(Integer, nullable=False)
    source = Column(Enum('file', 'stderr', 'stdout', name='source'),
                    nullable=False, server_default='stdout')
    stdin = relationship(File, primaryjoin='File.id==TestCase.stdin_id',
                         backref='stdin_for')
    stdin_id = Column(Integer, ForeignKey('file.id'), nullable=True)
    testable_id = Column(Integer, ForeignKey('testable.id'), nullable=False)
    test_case_for = relationship('TestCaseResult', backref='test_case',
                                 cascade='all, delete-orphan')

    def __cmp__(self, other):
        return cmp(alphanum_key(self.name), alphanum_key(other.name))

    def can_edit(self, user):
        """Return whether or not `user` can make changes to the test_case."""
        return self.testable.project.can_edit(user)

    def edit_json(self, jsonify=False):
        data = {'id': self.id, 'name': self.name, 'points': self.points,
                'source': self.source, 'hide_expected': self.hide_expected,
                'stdin': self.stdin is not None, 'args': self.args,
                'output_type': self.output_type}
        return json.dumps(data) if jsonify else data

    def serialize(self):
        data = dict([(x, getattr(self, x)) for x in ('args', 'id', 'source',
                                                     'output_filename')])
        if self.stdin:
            data['stdin'] = self.stdin.sha1
        else:
            data['stdin'] = None
        return data


class TestCaseResult(Base):
    """Stores information about a single run of a test case.

    The extra field stores the exit status when the status is `success`, and
    stores the signal number when the status is `signal`.

    When the TestCase output_type is not `diff` the diff file is actually
    the raw output file.

    """
    __tablename__ = 'testcaseresult'
    diff = relationship(File, backref='test_case_result_for')
    diff_id = Column(Integer, ForeignKey('file.id'), nullable=True)
    status = Column(Enum('nonexistent_executable', 'output_limit_exceeded',
                         'signal', 'success', 'timed_out',
                         name='status'), nullable=False)
    extra = Column(Integer)
    submission_id = Column(Integer, ForeignKey('submission.id'),
                           primary_key=True, nullable=False)
    test_case_id = Column(Integer, ForeignKey('testcase.id'),
                          primary_key=True, nullable=False)

    @classmethod
    def fetch_by_ids(cls, submission_id, test_case_id):
        return Session.query(cls).filter_by(
            submission_id=submission_id, test_case_id=test_case_id).first()

    def update(self, data):
        for attr, val in data.items():
            setattr(self, attr, val)
        self.created_at = func.now()


class Testable(BasicBase, Base):
    """Represents a set of properties for a single program to test."""
    __table_args__ = (UniqueConstraint('name', 'project_id'),)
    build_files = relationship(BuildFile, backref='testables',
                               secondary=testable_to_build_file)
    executable = Column(Unicode, nullable=False)
    execution_files = relationship(ExecutionFile, backref='testables',
                                   secondary=testable_to_execution_file)
    file_verifiers = relationship(FileVerifier, backref='testables',
                                  secondary=testable_to_file_verifier)
    is_hidden = Column(Boolean, default=False, nullable=False,
                       server_default='0')
    is_locked = Column(Boolean, default=False, nullable=False,
                       server_default='0')
    make_target = Column(Unicode)  # When None, no make is required
    name = Column(Unicode, nullable=False)
    project_id = Column(Integer, ForeignKey('project.id'), nullable=False)
    test_cases = relationship('TestCase', backref='testable',
                              cascade='all, delete-orphan')
    testable_results = relationship('TestableResult', backref='testable',
                                    cascade='all, delete-orphan')

    def __cmp__(self, other):
        return cmp(alphanum_key(self.name), alphanum_key(other.name))

    def can_edit(self, user):
        """Return whether or not `user` can make changes to the testable."""
        return self.project.can_edit(user)

    def edit_json(self, jsonify=True):
        def ids(item):
            return [x.id for x in sorted(item)]
        data = {'id': self.id, 'name': self.name, 'target': self.make_target,
                'executable': self.executable, 'hidden': self.is_hidden,
                'build_files': ids(self.build_files),
                'execution_files': ids(self.execution_files),
                'expected_files': ids(self.file_verifiers),
                'test_cases': [x.edit_json(False) for x in
                               sorted(self.test_cases)]}
        return json.dumps(data) if jsonify else data

    def points(self):
        return sum([test_case.points for test_case in self.test_cases])

    def requires_file(self, filename):
        for fv in self.file_verifiers:
            if filename == fv.filename and not fv.optional:
                return True
        return False

    def update_points(self):
        """Recompute the points for all TestableResults."""
        tc_ids = [x.id for x in self.test_cases]
        for result in self.testable_results:
            points = 0
            for tcr in (Session.query(TestCaseResult).filter(
                    and_(TestCaseResult.submission == result.submission,
                         TestCaseResult.test_case_id.in_(tc_ids))).all()):
                if tcr.status == 'success' and tcr.diff is None:
                    points += tcr.test_case.points
            result.points = points


class TestableResult(BasicBase, Base):
    __table_args__ = (UniqueConstraint('submission_id', 'testable_id'),)
    make_results = Column(UnicodeText, nullable=True)
    points = Column(Integer, nullable=False)
    status = Column(Enum('make_failed', 'nonexistent_executable', 'success',
                         name='make_status'), nullable=False)
    submission_id = Column(Integer, ForeignKey('submission.id'),
                           nullable=False)
    testable_id = Column(Integer, ForeignKey('testable.id'), nullable=False)

    @staticmethod
    def fetch_or_create(make_results, status, **kwargs):
        tr = TestableResult.fetch_by(**kwargs)
        if tr:
            tr.created_at = func.now()
        else:
            tr = TestableResult(**kwargs)
            Session.add(tr)
        tr.make_results = make_results
        tr.status = status
        return tr


class User(UserMixin, BasicBase, Base):
    """The UserMixin provides the `username` and `password` attributes.
    `password` is a write-only attribute and can be verified using the
    `verify_password` function."""
    admin_for = relationship(Class, secondary=user_to_class_admin,
                             backref='admins')
    classes = relationship(Class, secondary=user_to_class, backref='users')
    consent_at = Column(DateTime(timezone=True), nullable=True, index=True)
    files = relationship(File, secondary=user_to_file, backref='users',
                         collection_class=set)
    is_admin = Column(Boolean, default=False, nullable=False)
    name = Column(Unicode, nullable=False)

    @staticmethod
    def get_value(cls, value):
        '''Takes the class of the item that we want to
        query, along with a potential instance of that class.
        If the value is an instance of int or basestring, then
        we will treat it like an id for that instance.'''
        if isinstance(value, (basestring, int)):
            value = cls.fetch_by(id=value)
        return value if isinstance(value, cls) else None

    @staticmethod
    def login(username, password, development_mode=False):
        """Return the user if successful, None otherwise"""
        retval = None
        try:
            user = User.fetch_by(username=username)
            if user and (development_mode or user.verify_password(password)):
                retval = user
        except OperationalError:
            pass
        return retval

    def __cmp__(self, other):
        return cmp((self.name, self.username), (other.name, other.username))

    def __repr__(self):
        return 'User(username="{0}", name="{1}")'.format(self.username,
                                                         self.name)

    def __str__(self):
        admin_str = ' (admin)' if self.is_admin else ''
        return '{0} <{1}>{2}'.format(self.name, self.username, admin_str)

    def can_join_group(self, project):
        """Return whether or not user can join a group on `project`."""
        if project.class_.is_locked or project.group_max < 2:
            return False
        u2g = self.fetch_group_assoc(project)
        if u2g:
            return len(list(u2g.group.users)) < project.group_max
        return True

    def can_view(self, user):
        """Return whether or not `user` can view information about the user."""
        return user.is_admin or self == user \
            or set(self.classes).intersection(user.admin_for)

    def classes_can_admin(self):
        """Return all the classes (sorted) that this user can admin."""
        if self.is_admin:
            return sorted(Session.query(Class).all())
        else:
            return sorted(self.admin_for)

    def group_with(self, to_user, project, bypass_limit=False):
        """Join the users in a group."""
        from_user = self
        from_assoc = from_user.fetch_group_assoc(project)
        to_assoc = to_user.fetch_group_assoc(project)

        if from_user == to_user or from_assoc == to_assoc and from_assoc:
            raise GroupWithException('You are already part of that group.')

        if not from_assoc and not to_assoc:
            to_assoc = UserToGroup(group=Group(project=project),
                                   project=project, user=to_user)
            Session.add(to_assoc)
            from_count = 1
        elif not to_assoc:
            from_assoc, to_assoc = to_assoc, from_assoc
            from_user, to_user = to_user, from_user
            from_count = 1
        elif not from_assoc:
            from_count = 1
        elif to_assoc.user_count > from_assoc.user_count:
            from_assoc, to_assoc = to_assoc, from_assoc
            from_user, to_user = to_user, from_user
            from_count = from_assoc.user_count
        else:
            from_count = from_assoc.user_count

        if not bypass_limit and \
                project.group_max < to_assoc.user_count + from_count:
            raise GroupWithException('There are too many users to join that '
                                     'group.')

        if from_assoc:  # Move the submissions and users
            old_group = from_assoc.group
            for submission in from_assoc.group.submissions[:]:
                submission.group = to_assoc.group
            for assoc in from_assoc.group.group_assocs[:]:
                assoc.group = to_assoc.group
            if to_assoc.group.viewed_at is None:
                to_assoc.group.viewed_at = old_group.viewed_at
            elif old_group.viewed_at:
                to_assoc.group.viewed_at = max(old_group.viewed_at,
                                               to_assoc.group.viewed_at)
            Session.delete(old_group)
        else:  # Add the user to the group
            from_assoc = UserToGroup(group=to_assoc.group, project=project,
                                     user=from_user)
            Session.add(from_assoc)

        # Update the group's submissions' files' permissions
        files = set(assoc.file for sub in to_assoc.group.submissions
                    for assoc in sub.files)
        for user in to_assoc.group.users:
            user.files.update(files)

        return to_assoc.group

    def fetch_group_assoc(self, project):
        return (Session.query(UserToGroup)
                .filter(UserToGroup.user == self)
                .filter(UserToGroup.project == project)).first()

    def make_submission(self, project):
        group_assoc = None
        while not group_assoc:
            group_assoc = self.fetch_group_assoc(project)
            if not group_assoc:
                sp = transaction.savepoint()
                try:
                    group_assoc = UserToGroup(group=Group(project=project),
                                              project=project, user=self)
                    Session.add(group_assoc)
                    Session.flush()
                except IntegrityError:
                    group_assoc = None
                    sp.rollback()
        return Submission(created_by=self, group=group_assoc.group,
                          project=project)


class UserToGroup(Base):
    __tablename__ = 'user_to_group'
    created_at = Column(DateTime(timezone=True), default=func.now(),
                        nullable=False)
    group = relationship('Group', backref='group_assocs', cascade='all')
    group_id = Column(Integer, ForeignKey('group.id'), index=True,
                      nullable=False)
    project = relationship(
        'Project',
        backref=backref('group_assocs', cascade='all, delete-orphan'))
    project_id = Column(Integer, ForeignKey('project.id'), primary_key=True)
    user = relationship('User',
                        backref=backref('groups_assocs', cascade='all'))
    user_id = Column(Integer, ForeignKey('user.id'), primary_key=True)

    @property
    def user_count(self):
        return (Session.query(UserToGroup)
                .filter(UserToGroup.group_id == self.group_id).count())

    def __eq__(self, other):
        if not isinstance(other, UserToGroup):
            return False
        return self.group_id == other.group_id


def configure_sql(engine):
    """Configure session and metadata with the database engine."""
    Session.configure(bind=engine)
    Base.metadata.bind = engine


def create_schema(alembic_config_ini=None):
    """Create the database schema.

    :param alembic_config_ini: When provided, stamp with the current revision
    version.

    """
    Base.metadata.create_all()
    if alembic_config_ini:
        from alembic.config import Config
        from alembic import command
        alembic_cfg = Config(alembic_config_ini)
        command.stamp(alembic_cfg, 'head')


def populate_database():
    """Populate the database with some data useful for development."""
    if User.fetch_by(username='admin'):
        return

    # Admin user
    admin = User(name='Administrator', password='password',
                 username='admin', is_admin=True)
    # Class
    class_ = Class(name='CS32')
    Session.add(class_)
    Session.flush()

    # Project
    project = Project(name='Project 1', class_id=class_.id)
    Session.add(project)
    Session.flush()

    # File verification
    fv = FileVerifier(filename='test.c', min_size=3, min_lines=1,
                      project_id=project.id)

    Session.add_all([admin, fv])
    try:
        transaction.commit()
        print('Admin user created')
    except IntegrityError:
        transaction.abort()
