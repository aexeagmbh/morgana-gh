#! /usr/bin/env python2
# coding=utf-8

import os
import sys
import boto
import boto.s3
from boto.s3.key import Key

AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']

FILES_TO_SYNC = [
]

DIRS_TO_SYNC = [
    'img',
    'fonts',
    'js',
    'css',
    'content_img',
]

bucket_name = 'ax-semantics'
conn = boto.connect_s3(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

bucket = conn.get_bucket(bucket_name)

def percent_cb(complete, total):
    sys.stdout.write('{:.2f}%\r'.format((float(complete)/total)*100))
    sys.stdout.flush()

def upload_file(filename):
    # upload to foundation subfolder
    uploaded_filename = 'foundation/{0}'.format(filename)
    print 'Uploading %s to Amazon S3 bucket %s' % \
           (filename, bucket_name)

    k = Key(bucket)
    k.key = uploaded_filename.lower()
    k.set_contents_from_filename(filename,
            cb=percent_cb, num_cb=100)
    bucket.set_acl('public-read', k.key)
    print "\nFile completed..."

if len(sys.argv) > 1:
    for filename in sys.argv[1:]:
        upload_file(filename)
else:
    for filename in FILES_TO_SYNC:
        upload_file(filename)

    for dirname in DIRS_TO_SYNC:
        for path, subdirs, files in os.walk(dirname):
            for name in files:
                upload_file(os.path.join(path, name))
