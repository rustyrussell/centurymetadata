from setuptools import setup
import io

with io.open('requirements.txt', encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]

setup(name='centurymetadata',
      version='0.0.1',
      description='Alpha version of centurymetadata package',
      long_description_content_type='text/markdown',
      author='Rusty Russell',
      author_email='rusty@rustcorp.com.au',
      license='MIT',
      packages=['centurymetadata'],
      scripts=[],
      zip_safe=True,
      install_requires=requirements)
