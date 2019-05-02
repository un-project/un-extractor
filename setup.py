from setuptools import setup, Extension, Command

# from pip.req import parse_requirements
# import pip.download

# parse_requirements() returns generator of pip.req.InstallRequirement objects
# install_reqs = parse_requirements("requirements.txt",
# session=pip.download.PipSession())

# reqs is a list of requirement
# e.g. ['django==1.5.1', 'mezzanine==1.4.6']
# reqs = [str(ir.req) for ir in install_reqs]

exec(open("un_extractor/version.py").read())

config = {
    "name": "un-extractor",
    "description": "Extractor for general assembly records.",
    "author": "Olivier Crave",
    "author_email": "olivier.crave@gmail.com",
    "url": "http://github.com/un-project/un-extractor",
    "download_url": "https://github.com/un-project/un-extractor/releases",
    "version": __version__,
    "packages": ["un_extractor", "un_extractor.cli"],
    "entry_points": {"console_scripts": ["un_extractor=un_extractor.cli.main:main"]},
    "install_requires": ["argparse==1.2.1"],
    "license": "MIT License",
}

setup(**config)
