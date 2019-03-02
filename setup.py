#!/usr/bin/env python

from setuptools import setup

setup(
        name='usr-r16',
        version='0.0.1',
        description='Python client for USR-R16',
        long_description=open('README.md').read(),
        url='https://github.com/blindlight86/USR-R16',
        author='blindlight1986',
        author_email='blindlight1986@gmail.com',
        license='MIT',
        packages=[
            'usr_r16',
            ],
        )