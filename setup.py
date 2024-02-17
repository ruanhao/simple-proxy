# setup.py
from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()
# install_requires = (this_directory / 'requirements.txt').read_text().splitlines()

__version__ = None

exec(open("simple_proxy/version.py").read())

config = {
    'name': 'simple-proxy',
    'url': 'https://github.com/ruanhao/simple-proxy',
    'license': 'MIT',
    "long_description": long_description,
    "long_description_content_type": 'text/markdown',
    'description': 'A very simple NIO TCP proxy server',
    'author' : 'Hao Ruan',
    'author_email': 'ruanhao1116@gmail.com',
    'keywords': ['network', 'tcp', 'non-blocking', 'proxy'],
    'version': __version__,
    'packages': find_packages(),
    'install_requires': ['click', 'py-netty', 'cryptography'],
    'python_requires': ">=3.7, <4",
    'setup_requires': ['wheel'],
    'package_data': {'simple_proxy': ['*']},
    'entry_points': {
        'console_scripts': [
            'simple-proxy = simple_proxy.__init__:_run',
        ],
    },
    'classifiers': [
        "Intended Audience :: Developers",
        'License :: OSI Approved :: MIT License',
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Software Development :: Libraries",
    ],
}

setup(**config)
