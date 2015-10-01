from setuptools import setup, find_packages

version = '0.6.16'

setup(name='metadata_parser',
      version=version,
      description="A module to parse metadata out of documents",
      long_description=open("README.rst").read() + "\n",
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
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
      test_suite='tests',
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'BeautifulSoup4',
          'requests>=1.2'
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
