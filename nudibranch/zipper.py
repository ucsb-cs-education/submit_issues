import os
import sys
import zipfile
from .models import File, Project, Submission, SubmissionToFile, User

if sys.version_info < (3, 0):
    builtins = __import__('__builtin__')
else:
    import builtins


class MissingSomethingException(Exception):
    def __init__(self, message):
        super(MissingSomethingException, self).__init__(message)


class ZipSubmission(object):
    '''Puts a submission into a zip file.
    This packages up the following:
    -Makefile to build the project
    -User-submitted code that can be build with said makefile
    -Test cases, along with any stdin needed to run said test cases'''
    def __init__(self, submission):
        self.dirname = ZipSubmission.get_dirname_from_submission(submission)
        with open("nudibranch/static/" + self.zipfile_name(), "wb") as self.backing_file:
            self.submission = submission
            self.project = ZipSubmission.get_project_from_submission(
                submission)
            self.zip = zipfile.ZipFile(self.backing_file, 'w')
            self.__add_makefile()
            self.__add_user_code()
            self.zip.close()
        
    def zipfile_name(self):
        return "{0}.zip".format(self.dirname)

    def zipfile_path(self):
        return self.backing_file.name

    def write(self, backing_file, archive_filename):
        '''Writes the given file to the archive with the given name.
        Puts everything in the same directory as specified by
        get_dirname_from_submission'''
        self.zip.write(backing_file,
                       "{0}/{1}".format(self.dirname, archive_filename))

    @staticmethod
    def real_file_path(db_file):
        '''Given a File object, it will return a path to a real underlying
        file for it.'''
        return File.file_path('/tmp/nudibranch_files', db_file.sha1)

    @staticmethod
    def get_dirname_from_submission(submission):
        '''Gets the name of the directory that all submission materials
        will go into'''
        username = ZipSubmission.get_username_from_submission(submission)
        return "{0}_{1}".format(username, submission.id)

    @staticmethod
    def get_username_from_submission(submission):
        user = User.fetch_by_id(submission.user_id)
        if not user:
            raise MissingSomethingException("Bad user")
        return user.username

    @staticmethod
    def get_project_from_submission(submission):
        project = Project.fetch_by_id(submission.project_id)
        if not project:
            raise MissingSomethingException("Bad Project")
        return project

    def __add_makefile(self):
        self.write(
            ZipSubmission.real_file_path(self.project.makefile),
            'makefile')

    def __add_user_code(self):
        filemapping = SubmissionToFile.fetch_file_mapping_for_submission(
            self.submission.id)
        for filename, db_file in filemapping.iteritems():
            self.write(ZipSubmission.real_file_path(db_file),
                       filename)
