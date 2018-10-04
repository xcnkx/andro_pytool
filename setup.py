# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()


with open('requirements.txt') as fp:
    requirements = fp.read()


setup(
    name='andro_pytool',
    version='0.0.1',
    description='A tool to extract features from apks',
    long_description=readme,
    author='Cristian Kamia',
    author_email='cnk_2806@me.com',
    url='https://github.com/xcnkx/andro_pytool',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires=requirements
)

