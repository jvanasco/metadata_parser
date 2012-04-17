from setuptools import setup, find_packages
import sys, os

version = '0.4.4'

setup(name='metadata_parser',
      version=version,
      description="A module to parse metadata out of documents",
      long_description=open("README.rst").read() + "\n",
      classifiers=[
      'Development Status :: 3 - Alpha',
      'Intended Audience :: Developers',
      'Programming Language :: Python',
      'Topic :: Text Processing :: Markup :: HTML',
      'Topic :: Software Development :: Libraries :: Python Modules',
      ],
      keywords='opengraph protocol facebook',
      author='Jonathan Vanasco',
      author_email='jonathan@findmeon.com',
      url='https://github.com/jvanasco/metadata_parser',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'BeautifulSoup'
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
