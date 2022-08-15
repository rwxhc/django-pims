import os
from setuptools import find_packages, setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))


setup(
    name='django-pims',
    version='1.0.1',
    packages=find_packages(),
    include_package_data=True,
    license='Free', 
    description='A django app for manage ypur private info.',
    author='Huang Cheng',
    author_email='wsjhhc@tom.com',
	url="https://github.com/rwxhc/django-pims",
    install_requires=[
        'gmssl >= "3.2.1"',
        'Django >= "3.2"',
        'python_version >= "3.6"',
    ],
)