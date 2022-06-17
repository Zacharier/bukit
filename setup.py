from setuptools import setup, find_packages
from src.bukit import __version__

setup(
    name="bukit",
    author="Zacharier",
    version=__version__,
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={"console_scripts": ["bukit = bukit:main"]},
)
