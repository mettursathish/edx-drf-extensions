#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

import edx_rest_framework_extensions

setup(
    name='edx-drf-extensions',
    version=edx_rest_framework_extensions.__version__,
    description='edX extensions of Django REST Framework',
    author='edX',
    author_email='oscm@edx.org',
    url='https://github.com/edx/edx-drf-extensions',
    license='AGPL',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Framework :: Django',
        'Framework :: Django :: 1.8',
        'Framework :: Django :: 1.9',
        'Framework :: Django :: 1.10',
        'Framework :: Django :: 1.11',
    ],
    packages=['edx_rest_framework_extensions'],
    install_requires=[
        'django>=1.8.9,<2.0',
        'djangorestframework',
        'djangorestframework-jwt>=1.7.2,<2.0.0',
        'python-dateutil>=2.0',
        'requests>=2.7.0,<3.0.0',
        'six',
    ]
)
